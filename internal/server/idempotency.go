package server

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"perimeter/internal/auth"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

// Idempotency-Key handling for the write routes of /api/v1. A client that
// retries a write after a timeout sends the same key and gets the first answer
// back, instead of making the change a second time.

const (
	idempotencyHeader   = "Idempotency-Key"
	idempotencyReplayed = "Idempotent-Replayed"
	idempotencyMaxLen   = 255
	// idempotencyTTL is how long a key is remembered. A retry after that is a
	// new request.
	idempotencyTTL = 24 * time.Hour
	// idempotencyMaxEntries caps the store. The oldest entry is dropped first.
	idempotencyMaxEntries = 10000
	// idempotencyMaxBytes caps the stored bodies in total, since one import
	// answer can be large. The oldest entries are dropped first.
	idempotencyMaxBytes = 64 << 20
)

// idemKey scopes a client's key to its token, so two tokens may reuse a key.
type idemKey struct {
	token int
	key   string
}

// idemEntry is one remembered request. It is done once its response is stored;
// until then a repeat is refused as still in progress.
type idemEntry struct {
	key         idemKey
	fingerprint string
	expires     time.Time
	elem        *list.Element
	done        bool
	status      int
	contentType string
	body        []byte
}

// idempotencyStore is an in-memory table of responses. It lives in one process,
// which is fine for a single-binary deployment: a restart forgets the keys.
type idempotencyStore struct {
	mu      sync.Mutex
	entries map[idemKey]*idemEntry
	// order holds the entries oldest first. Entries share one TTL, so the
	// expired ones are always at the front.
	order *list.List
	ttl   time.Duration
	max   int
	// bytes is the total size of the stored bodies, kept under maxBytes.
	bytes    int
	maxBytes int
}

func newIdempotencyStore(ttl time.Duration, maxEntries int) *idempotencyStore {
	return &idempotencyStore{
		entries:  make(map[idemKey]*idemEntry),
		order:    list.New(),
		ttl:      ttl,
		max:      maxEntries,
		maxBytes: idempotencyMaxBytes,
	}
}

// middleware handles the key of a POST, PUT or DELETE. Other methods, and
// requests without a key, run as they are.
func (s *idempotencyStore) middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		switch c.Method() {
		case fiber.MethodPost, fiber.MethodPut, fiber.MethodDelete:
		default:
			return c.Next()
		}
		// Copy the header: Fiber v2 runs without Immutable, so c.Get returns a
		// string into a buffer fasthttp reuses after the request, and the key
		// stored in the map would be corrupted.
		key := utils.CopyString(c.Get(idempotencyHeader))
		tok := auth.GetAPIToken(c)
		if key == "" || tok == nil {
			// A nil token is refused with 401 by RequireAPIWrite.
			return c.Next()
		}
		if !validIdempotencyKey(key) {
			return apiError(c, fiber.StatusBadRequest, "invalid_request", "Idempotency-Key must be 1 to 255 printable characters")
		}

		// The body is hashed so a key reused with a different body is caught.
		sum := sha256.Sum256(c.Body())
		fingerprint := c.Method() + " " + c.Path() + " " + hex.EncodeToString(sum[:])
		e, refusal := s.claim(idemKey{token: tok.ID, key: key}, fingerprint)
		if refusal != "" {
			return apiError(c, fiber.StatusConflict, "conflict", refusal)
		}
		if e.done {
			if ct := e.contentType; ct != "" {
				c.Set(fiber.HeaderContentType, ct)
			}
			c.Set(idempotencyReplayed, "true")
			return c.Status(e.status).Send(e.body)
		}

		// Only a finished, replayable answer is kept. Anything else releases the
		// key, so the client can retry.
		finished := false
		defer func() {
			if !finished {
				s.release(e)
			}
		}()
		if err := c.Next(); err != nil {
			return err
		}
		status := c.Response().StatusCode()
		if !replayable(status) {
			return nil
		}
		s.complete(e, status, string(c.Response().Header.ContentType()), bytes.Clone(c.Response().Body()))
		finished = true
		return nil
	}
}

// claim reserves k for a request with this fingerprint. It returns a finished
// entry to replay, or a new entry the caller must run. A key used for another
// request, or whose first request is still running, is refused with a message.
func (s *idempotencyStore) claim(k idemKey, fingerprint string) (*idemEntry, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.dropExpired(now)

	if e, ok := s.entries[k]; ok {
		switch {
		case e.fingerprint != fingerprint:
			return nil, "Idempotency-Key reused with a different request"
		case !e.done:
			return nil, "request with this Idempotency-Key is still in progress"
		}
		return e, ""
	}
	if s.order.Len() >= s.max {
		s.remove(s.order.Front().Value.(*idemEntry))
	}
	e := &idemEntry{key: k, fingerprint: fingerprint, expires: now.Add(s.ttl)}
	e.elem = s.order.PushBack(e)
	s.entries[k] = e
	return e, ""
}

// complete stores the answer of a finished request, so repeats can replay it.
func (s *idempotencyStore) complete(e *idemEntry, status int, contentType string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Same check as release: the entry may have been evicted and its key
	// claimed again while the request ran, and its body size must not leak
	// into s.bytes without an entry to subtract it.
	if s.entries[e.key] != e {
		return
	}
	e.status = status
	e.contentType = contentType
	e.body = body
	e.done = true
	s.bytes += len(body)
	// The entry just stored is the newest, so it is evicted last.
	for s.bytes > s.maxBytes && s.order.Len() > 1 {
		s.remove(s.order.Front().Value.(*idemEntry))
	}
}

// release forgets an entry whose request did not produce a stored answer. The
// map check matters: the key may have been evicted and claimed again since.
func (s *idempotencyStore) release(e *idemEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries[e.key] == e {
		s.remove(e)
	}
}

// dropExpired forgets the entries past their TTL. The caller holds mu.
func (s *idempotencyStore) dropExpired(now time.Time) {
	for f := s.order.Front(); f != nil; f = s.order.Front() {
		e := f.Value.(*idemEntry)
		if now.Before(e.expires) {
			return
		}
		s.remove(e)
	}
}

// remove drops one entry. The caller holds mu.
func (s *idempotencyStore) remove(e *idemEntry) {
	s.order.Remove(e.elem)
	delete(s.entries, e.key)
	s.bytes -= len(e.body)
}

// replayable reports whether an answer with this status is kept for repeats.
// A 5xx may succeed on retry, and 401, 403 and 429 depend on the token, the
// role and the rate limit, which can all change before the retry.
func replayable(status int) bool {
	switch status {
	case fiber.StatusUnauthorized, fiber.StatusForbidden, fiber.StatusTooManyRequests:
		return false
	}
	return status < fiber.StatusInternalServerError
}

// validIdempotencyKey reports whether key is 1 to 255 printable ASCII
// characters, the space included.
func validIdempotencyKey(key string) bool {
	if len(key) == 0 || len(key) > idempotencyMaxLen {
		return false
	}
	for i := range len(key) {
		if key[i] < 0x20 || key[i] > 0x7e {
			return false
		}
	}
	return true
}
