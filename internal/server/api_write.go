package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"time"

	"perimeter/internal/auth"
	"perimeter/internal/service"

	"github.com/gofiber/fiber/v2"
)

// The write handlers under /api/v1. Like the read handlers they only translate
// HTTP into service calls and back, so REST and MCP make the same changes and
// write the same audit rows.

// maxAPIImportTargets caps the entries of one POST /api/v1/targets. It is
// checked before parsing, so a huge body is refused cheaply.
const maxAPIImportTargets = 1000

// apiActor is who a REST write is made by: the user of the token, and the token.
func apiActor(c *fiber.Ctx) service.Actor {
	return service.Actor{User: auth.GetUser(c), Source: service.SourceAPI, Token: auth.GetAPIToken(c)}
}

// decodeBody reads the JSON body of a write into v. It decodes the bytes
// directly, because BodyParser needs a Content-Type header to pick a decoder.
func decodeBody(c *fiber.Ctx, v any) error {
	if err := json.Unmarshal(c.Body(), v); err != nil {
		return badParam("body", "must be a JSON object in the shape the endpoint documents")
	}
	return nil
}

// importBody is the body of POST /api/v1/targets.
type importBody struct {
	Targets []string `json:"targets"`
}

// tagsBody is the body of the tag writes. A pointer, so a missing key is
// told apart from an empty list: {} must not clear a target's tags.
type tagsBody struct {
	Tags *[]string `json:"tags"`
}

// rescanBody is the body of POST /api/v1/rescan.
type rescanBody struct {
	IDs []int `json:"ids"`
}

// apiRescanStatus is the reply to a single rescan. RetryAt is set only when
// the target is cooling down.
type apiRescanStatus struct {
	Status  string     `json:"status"`
	RetryAt *time.Time `json:"retry_at,omitempty"`
}

// tagNames reads the tag names of a tag write.
func tagNames(c *fiber.Ctx) ([]string, error) {
	var in tagsBody
	if err := decodeBody(c, &in); err != nil {
		return nil, err
	}
	if in.Tags == nil {
		return nil, badParam("tags", "is required, as a list (use [] for none)")
	}
	return *in.Tags, nil
}

// tagWrite runs one tag write on the target and tags of the request.
func (s *Server) tagWrite(c *fiber.Ctx, write func(context.Context, service.Actor, int, []string) (*service.TargetSummary, error)) error {
	id, err := targetIDParam(c)
	if err != nil {
		return apiFail(c, err)
	}
	names, err := tagNames(c)
	if err != nil {
		return apiFail(c, err)
	}
	sum, err := write(c.Context(), apiActor(c), id, names)
	if err != nil {
		return apiFail(c, err)
	}
	return c.JSON(sum)
}

// handleAPIImport serves POST /api/v1/targets.
func (s *Server) handleAPIImport(c *fiber.Ctx) error {
	var in importBody
	if err := decodeBody(c, &in); err != nil {
		return apiFail(c, err)
	}
	if len(in.Targets) == 0 {
		return apiFail(c, badParam("targets", "at least one target is required"))
	}
	if len(in.Targets) > maxAPIImportTargets {
		return apiFail(c, badParam("targets", fmt.Sprintf("at most %d per request, got %d", maxAPIImportTargets, len(in.Targets))))
	}
	res, err := s.svc.ImportTargets(c.Context(), apiActor(c), in.Targets)
	if err != nil {
		return apiFail(c, err)
	}
	return c.JSON(res)
}

// handleAPISetTags serves PUT /api/v1/targets/:id/tags.
func (s *Server) handleAPISetTags(c *fiber.Ctx) error {
	return s.tagWrite(c, s.svc.SetTargetTags)
}

// handleAPIAddTags serves POST /api/v1/targets/:id/tags.
func (s *Server) handleAPIAddTags(c *fiber.Ctx) error {
	return s.tagWrite(c, s.svc.AddTargetTags)
}

// handleAPIRemoveTag serves DELETE /api/v1/targets/:id/tags/:tag.
func (s *Server) handleAPIRemoveTag(c *fiber.Ctx) error {
	id, err := targetIDParam(c)
	if err != nil {
		return apiFail(c, err)
	}
	// Fiber leaves path parameters escaped, so a tag with a space arrives as %20.
	name, err := url.PathUnescape(c.Params("tag"))
	if err != nil {
		return apiFail(c, badParam("tag", "is not a valid tag name"))
	}
	sum, err := s.svc.RemoveTargetTags(c.Context(), apiActor(c), id, []string{name})
	if err != nil {
		return apiFail(c, err)
	}
	return c.JSON(sum)
}

// handleAPIDeleteTarget serves DELETE /api/v1/targets/:id. It is a soft delete.
func (s *Server) handleAPIDeleteTarget(c *fiber.Ctx) error {
	id, err := targetIDParam(c)
	if err != nil {
		return apiFail(c, err)
	}
	if err := s.svc.DeleteTarget(c.Context(), apiActor(c), id); err != nil {
		return apiFail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// handleAPIRestoreTarget serves POST /api/v1/targets/:id/restore.
func (s *Server) handleAPIRestoreTarget(c *fiber.Ctx) error {
	id, err := targetIDParam(c)
	if err != nil {
		return apiFail(c, err)
	}
	if err := s.svc.RestoreTarget(c.Context(), apiActor(c), id); err != nil {
		return apiFail(c, err)
	}
	// The service's restore returns nothing, so the summary is read back.
	d, err := s.svc.GetTarget(c.Context(), id)
	if err != nil {
		return apiFail(c, err)
	}
	return c.JSON(d.TargetSummary)
}

// handleAPIRescanTarget serves POST /api/v1/targets/:id/rescan.
func (s *Server) handleAPIRescanTarget(c *fiber.Ctx) error {
	id, err := targetIDParam(c)
	if err != nil {
		return apiFail(c, err)
	}
	res, err := s.svc.RequestRescan(c.Context(), apiActor(c), []int{id})
	if err != nil {
		return apiFail(c, err)
	}
	if len(res.NotFound) > 0 {
		return apiFail(c, service.ErrNotFound)
	}
	if len(res.CoolingDown) > 0 {
		// A cooling-down target is still a 202, so the client can tell it
		// apart from a failure by the status and the body.
		retry := res.CoolingDown[0].RetryAt
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(retryAfterSeconds(retry)))
		return c.Status(fiber.StatusAccepted).JSON(apiRescanStatus{Status: "cooling_down", RetryAt: &retry})
	}
	return c.Status(fiber.StatusAccepted).JSON(apiRescanStatus{Status: "queued"})
}

// handleAPIRescanTargets serves POST /api/v1/rescan.
func (s *Server) handleAPIRescanTargets(c *fiber.Ctx) error {
	var in rescanBody
	if err := decodeBody(c, &in); err != nil {
		return apiFail(c, err)
	}
	res, err := s.svc.RequestRescan(c.Context(), apiActor(c), in.IDs)
	if err != nil {
		return apiFail(c, err)
	}
	return c.Status(fiber.StatusAccepted).JSON(res)
}

// retryAfterSeconds is the whole seconds until t, at least 1, for a Retry-After
// header.
func retryAfterSeconds(t time.Time) int {
	return max(1, int(math.Ceil(time.Until(t).Seconds())))
}
