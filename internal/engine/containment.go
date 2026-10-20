package engine

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"cloudruntimeguardian/internal/journal"
	"cloudruntimeguardian/internal/model"
)

var (
	ErrUnsafeTarget      = errors.New("containment needs a verified, live workload identity")
	ErrActiveContainment = errors.New("an unresolved containment already exists for this incident")
	ErrInvalidTransition = errors.New("invalid containment state transition")
)

// RequestContainment journals a desired state only. It never performs I/O to a
// workload or claims that enforcement has happened. The caller must authorize
// the administrator and opt in to containment BEFORE calling this method.
func (en *Engine) RequestContainment(id, incidentID, reason string, ttl time.Duration, mode string, now time.Time) (model.Containment, bool, error) {
	en.mu.Lock()
	defer en.mu.Unlock()
	if existing, ok := en.containments[id]; ok {
		if existing.IncidentID == incidentID && existing.Reason == reason && existing.ExpiresAt.Sub(existing.RequestedAt) == ttl && existing.Mode == mode {
			return existing, false, nil
		}
		return model.Containment{}, false, ErrConflict
	}
	inc, ok := en.incidents[incidentID]
	if !ok {
		return model.Containment{}, false, ErrNotFound
	}
	for _, c := range en.containments {
		if c.Workload.Namespace == inc.Workload.Namespace && c.Workload.PodUID == inc.Workload.PodUID && c.State != "released" {
			return model.Containment{}, false, ErrActiveContainment
		}
	}
	c := model.Containment{ID: id, IncidentID: incidentID, Workload: inc.Workload, State: "requested", Mode: mode, Reason: reason,
		RequestedAt: now.UTC(), UpdatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl)}
	if err := c.Validate(); err != nil {
		return model.Containment{}, false, fmt.Errorf("%w: %v", ErrUnsafeTarget, err)
	}
	if en.containmentRecords >= en.maxEvents*4 {
		return model.Containment{}, false, ErrFull
	}
	if err := en.ledger.Append(journal.Entry{Kind: "containment", Containment: &c}); err != nil {
		return model.Containment{}, false, err
	}
	if err := en.applyContainment(c); err != nil {
		return model.Containment{}, false, err
	}
	return c, true, nil
}

func (en *Engine) GetContainment(id string) (model.Containment, bool) {
	en.mu.RLock()
	defer en.mu.RUnlock()
	c, ok := en.containments[id]
	return c, ok
}
func (en *Engine) ListContainments() []model.Containment {
	en.mu.RLock()
	defer en.mu.RUnlock()
	out := make([]model.Containment, 0, len(en.containments))
	for _, c := range en.containments {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RequestedAt.Equal(out[j].RequestedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].RequestedAt.Before(out[j].RequestedAt)
	})
	return out
}

func (en *Engine) transitionContainment(id, state string, now time.Time) (model.Containment, error) {
	en.mu.Lock()
	defer en.mu.Unlock()
	old, ok := en.containments[id]
	if !ok {
		return model.Containment{}, ErrNotFound
	}
	if old.State == state {
		return old, nil
	}
	permitted := (old.State == "requested" && (state == "applied" || state == "release_requested")) ||
		(old.State == "applied" && state == "release_requested") ||
		(old.State == "release_requested" && state == "released")
	if !permitted {
		return model.Containment{}, ErrInvalidTransition
	}
	if en.containmentRecords >= en.maxEvents*4 {
		return model.Containment{}, ErrFull
	}
	c := old
	c.State = state
	c.UpdatedAt = now.UTC()
	if c.UpdatedAt.Before(old.UpdatedAt) {
		c.UpdatedAt = old.UpdatedAt
	}
	if err := en.ledger.Append(journal.Entry{Kind: "containment", Containment: &c}); err != nil {
		return model.Containment{}, err
	}
	if err := en.applyContainment(c); err != nil {
		return model.Containment{}, err
	}
	return c, nil
}
func (en *Engine) RequestRelease(id string, now time.Time) (model.Containment, error) {
	c, ok := en.GetContainment(id)
	if !ok {
		return model.Containment{}, ErrNotFound
	}
	if c.State == "released" || c.State == "release_requested" {
		return c, nil
	}
	return en.transitionContainment(id, "release_requested", now)
}

// MarkContainmentApplied is called only after the backend reports successful
// reconciliation; it must never be used as a substitute for backend execution.
func (en *Engine) MarkContainmentApplied(id string, now time.Time) (model.Containment, error) {
	return en.transitionContainment(id, "applied", now)
}
func (en *Engine) MarkContainmentReleased(id string, now time.Time) (model.Containment, error) {
	return en.transitionContainment(id, "released", now)
}

func (en *Engine) applyContainment(c model.Containment) error {
	if err := c.Validate(); err != nil {
		return err
	}
	inc, ok := en.incidents[c.IncidentID]
	if !ok || inc.Workload != c.Workload {
		return ErrUnsafeTarget
	}
	old, exists := en.containments[c.ID]
	if exists {
		if old == c {
			return ErrConflict
		} // duplicated ledger entries are never valid history
		if old.IncidentID != c.IncidentID || old.Workload != c.Workload || old.Reason != c.Reason || old.Mode != c.Mode ||
			!old.RequestedAt.Equal(c.RequestedAt) || !old.ExpiresAt.Equal(c.ExpiresAt) || c.UpdatedAt.Before(old.UpdatedAt) {
			return ErrInvalidTransition
		}
		permitted := (old.State == "requested" && (c.State == "applied" || c.State == "release_requested")) ||
			(old.State == "applied" && c.State == "release_requested") || (old.State == "release_requested" && c.State == "released")
		if !permitted {
			return ErrInvalidTransition
		}
	} else if c.State != "requested" {
		return ErrInvalidTransition
	}
	en.containments[c.ID] = c
	en.containmentRecords++
	return nil
}
