package server

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"perimeter/internal/service"

	"github.com/gofiber/fiber/v2"
)

// The read handlers under /api/v1. They only translate HTTP into service
// calls and back, so the REST API and MCP answer from the same code.

// apiPage is one page of a list. NextCursor is left out on the last page.
type apiPage[T any] struct {
	Items      []T    `json:"items"`
	Total      int    `json:"total"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// apiItems is a list that is not paged.
type apiItems[T any] struct {
	Items []T `json:"items"`
}

// The change feed's page size: the same default and cap as service.ChangesSince.
const (
	defaultChangesLimit = 200
	maxChangesLimit     = 1000
)

// apiChanges is the reply to GET /api/v1/changes. A client polls by passing
// Until back as since.
type apiChanges struct {
	Items     []service.Change `json:"items"`
	Truncated bool             `json:"truncated"`
	Until     string           `json:"until"`
}

// badParam is a 400 for one query or path parameter.
func badParam(field, msg string) error {
	return &service.InvalidError{Field: field, Msg: msg}
}

// apiFail writes the JSON reply for a service or parameter error. Anything
// unexpected is returned as is, and the error handler turns it into a 500.
func apiFail(c *fiber.Ctx, err error) error {
	switch {
	case service.IsInvalid(err):
		return apiError(c, fiber.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, service.ErrNotFound):
		return apiError(c, fiber.StatusNotFound, "not_found", "no such target")
	}
	return err
}

// optionalInt reads an integer parameter. A missing one is 0.
func optionalInt(c *fiber.Ctx, name string) (int, error) {
	raw := c.Query(name)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, badParam(name, "must be a whole number")
	}
	return n, nil
}

// optionalBool reads a boolean parameter. A missing one is false.
func optionalBool(c *fiber.Ctx, name string) (bool, error) {
	raw := c.Query(name)
	if raw == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, badParam(name, "must be true or false")
	}
	return b, nil
}

// listParam reads a parameter that may repeat or hold commas, so that
// ?state=ok&state=pending and ?state=ok,pending both work.
func listParam(c *fiber.Ctx, name string) []string {
	var out []string
	for _, raw := range c.Context().QueryArgs().PeekMulti(name) {
		for _, v := range strings.Split(string(raw), ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// limitParam reads ?limit=. Missing means the service default; a larger value
// is capped there, not refused.
func limitParam(c *fiber.Ctx) (int, error) {
	limit, err := optionalInt(c, "limit")
	if err != nil {
		return 0, err
	}
	if c.Query("limit") != "" && limit < 1 {
		return 0, badParam("limit", "must be at least 1")
	}
	return limit, nil
}

// encodeCursor makes the opaque cursor for an offset. Clients must not read
// it; it is base64url of the decimal offset.
func encodeCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

// decodeCursor returns the offset in a cursor. An empty cursor is offset 0.
func decodeCursor(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, badParam("cursor", "is not a valid cursor")
	}
	n, err := strconv.Atoi(string(raw))
	if err != nil || n < 0 {
		return 0, badParam("cursor", "is not a valid cursor")
	}
	return n, nil
}

// pageParams reads ?limit= and ?cursor=.
func pageParams(c *fiber.Ctx) (limit, offset int, err error) {
	if limit, err = limitParam(c); err != nil {
		return 0, 0, err
	}
	if offset, err = decodeCursor(c.Query("cursor")); err != nil {
		return 0, 0, err
	}
	return limit, offset, nil
}

// toAPIPage converts a service page to the REST shape.
func toAPIPage[T any](p service.Page[T]) apiPage[T] {
	out := apiPage[T]{Items: p.Items, Total: p.Total}
	if p.NextOffset != nil {
		out.NextCursor = encodeCursor(*p.NextOffset)
	}
	return out
}

// targetQueryParams reads the filter, sort and page of GET /api/v1/targets.
func targetQueryParams(c *fiber.Ctx) (service.TargetQuery, error) {
	q := service.TargetQuery{
		Search:   c.Query("q"),
		Tag:      c.Query("tag"),
		States:   listParam(c, "state"),
		SSLBelow: c.Query("ssl_below"),
		SSLGrade: c.Query("ssl_grade"),
		CSP:      c.Query("csp"),
		Sort:     c.Query("sort"),
	}
	var err error
	if q.Port, err = optionalInt(c, "port"); err != nil {
		return q, err
	}
	if q.ExpiringWithinDays, err = optionalInt(c, "expiring_within_days"); err != nil {
		return q, err
	}
	if q.Deleted, err = optionalBool(c, "deleted"); err != nil {
		return q, err
	}
	switch c.Query("order") {
	case "", "asc":
	case "desc":
		q.Desc = true
	default:
		return q, badParam("order", "must be asc or desc")
	}
	q.Limit, q.Offset, err = pageParams(c)
	return q, err
}

// targetIDParam reads the :id path parameter.
func targetIDParam(c *fiber.Ctx) (int, error) {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil || id < 1 {
		return 0, badParam("id", "must be a target id")
	}
	return id, nil
}

// handleAPIListTargets serves GET /api/v1/targets.
func (s *Server) handleAPIListTargets(c *fiber.Ctx) error {
	q, err := targetQueryParams(c)
	if err != nil {
		return apiFail(c, err)
	}
	page, err := s.svc.ListTargets(c.Context(), q)
	if err != nil {
		return apiFail(c, err)
	}
	return c.JSON(toAPIPage(page))
}

// handleAPIGetTarget serves GET /api/v1/targets/:id.
func (s *Server) handleAPIGetTarget(c *fiber.Ctx) error {
	id, err := targetIDParam(c)
	if err != nil {
		return apiFail(c, err)
	}
	d, err := s.svc.GetTarget(c.Context(), id)
	if err != nil {
		return apiFail(c, err)
	}
	return c.JSON(d)
}

// handleAPITargetHistory serves GET /api/v1/targets/:id/history.
func (s *Server) handleAPITargetHistory(c *fiber.Ctx) error {
	id, err := targetIDParam(c)
	if err != nil {
		return apiFail(c, err)
	}
	limit, offset, err := pageParams(c)
	if err != nil {
		return apiFail(c, err)
	}
	page, err := s.svc.TargetHistory(c.Context(), id, limit, offset)
	if err != nil {
		return apiFail(c, err)
	}
	return c.JSON(toAPIPage(page))
}

// handleAPIListTags serves GET /api/v1/tags.
func (s *Server) handleAPIListTags(c *fiber.Ctx) error {
	tags, err := s.svc.ListTags(c.Context())
	if err != nil {
		return apiFail(c, err)
	}
	return c.JSON(apiItems[service.Tag]{Items: tags})
}

// handleAPISummary serves GET /api/v1/summary.
func (s *Server) handleAPISummary(c *fiber.Ctx) error {
	sum, err := s.svc.Summary(c.Context(), time.Now())
	if err != nil {
		return apiFail(c, err)
	}
	return c.JSON(sum)
}

// handleAPIChanges serves GET /api/v1/changes. since is required: without it
// the reply would be the whole history.
func (s *Server) handleAPIChanges(c *fiber.Ctx) error {
	raw := c.Query("since")
	if raw == "" {
		return apiFail(c, badParam("since", "is required, as an RFC 3339 time"))
	}
	since, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return apiFail(c, badParam("since", "must be an RFC 3339 time"))
	}
	limit, err := limitParam(c)
	if err != nil {
		return apiFail(c, err)
	}
	if limit == 0 {
		limit = defaultChangesLimit
	}
	limit = min(limit, maxChangesLimit)
	items, truncated, err := s.svc.ChangesSince(c.Context(), since, limit)
	if err != nil {
		return apiFail(c, err)
	}
	if items == nil {
		items = []service.Change{}
	}
	// Nanosecond precision keeps the next poll from repeating a change that
	// shares the second of the last one.
	until := since
	if n := len(items); n > 0 {
		until = items[n-1].At
	}
	return c.JSON(apiChanges{Items: items, Truncated: truncated, Until: until.Format(time.RFC3339Nano)})
}
