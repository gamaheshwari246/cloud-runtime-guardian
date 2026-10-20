// Package containment performs durable, explicitly authorized, time-bounded
// workload containment. No enforcement occurs by default; simulation is an
// isolated testing mode, never proof that a network policy is effective.
package containment

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/model"
)

// Backend methods MUST be idempotent and scoped to the exact workload UID.
// The controller deliberately never exposes arbitrary network destinations or
// policy selectors provided by a user.
type Backend interface {
	Ensure(context.Context, model.Containment) error
	Release(context.Context, model.Containment) error
}

type Controller struct {
	Engine  *engine.Engine
	Backend Backend
	Mode    string
	mu      sync.Mutex // one reconciler at a time; prevent repeated effects
	Now     func() time.Time
}

func (c *Controller) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Engine == nil || c.Backend == nil || (c.Mode != "simulate" && c.Mode != "kubernetes") {
		return errors.New("containment controller not configured")
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	var failures []error
	for _, item := range c.Engine.ListContainments() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if item.Mode != c.Mode {
			failures = append(failures, fmt.Errorf("%s: mode mismatch", item.ID))
			continue
		}
		if item.State == "released" {
			continue
		}
		if !now.Before(item.ExpiresAt) && (item.State == "requested" || item.State == "applied") {
			changed, err := c.Engine.RequestRelease(item.ID, now)
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: record expiry: %w", item.ID, err))
				continue
			}
			item = changed
		}
		var err error
		switch item.State {
		case "requested":
			err = c.Backend.Ensure(ctx, item)
			if err == nil {
				_, err = c.Engine.MarkContainmentApplied(item.ID, now)
			}
		case "applied":
			// Periodically repair policy drift, not only when first applied.
			err = c.Backend.Ensure(ctx, item)
		case "release_requested":
			err = c.Backend.Release(ctx, item)
			if err == nil {
				_, err = c.Engine.MarkContainmentReleased(item.ID, now)
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", item.ID, err))
		}
	}
	return errors.Join(failures...)
}

func (c *Controller) Run(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval < time.Second {
		interval = time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := c.Reconcile(ctx); err != nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Simulator is an in-memory policy backend; it cannot enforce network traffic.
// A lost simulator state is rebuilt by reapplying desired records on restart.
type Simulator struct {
	mu     sync.Mutex
	active map[string]string
}

func (s *Simulator) Ensure(_ context.Context, c model.Containment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		s.active = make(map[string]string)
	}
	s.active[c.ID] = c.Workload.PodUID
	return nil
}
func (s *Simulator) Release(_ context.Context, c model.Containment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, c.ID)
	return nil
}
func (s *Simulator) Active(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.active[id]
	return ok
}
