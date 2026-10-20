package model

import (
	"errors"
	"fmt"
	"time"
)

// Containment is the last durably recorded state of a time-bounded, explicitly
// authorized response. A request is NEVER sufficient evidence of enforcement.
// No result is marked applied until its backend confirms success.
type Containment struct {
	ID          string    `json:"id"`
	IncidentID  string    `json:"incident_id"`
	Workload    Workload  `json:"workload"`
	State       string    `json:"state"`
	Mode        string    `json:"mode"` // requested, applied, release_requested, released
	Reason      string    `json:"reason"`
	RequestedAt time.Time `json:"requested_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (c Containment) Validate() error {
	if !validIdentifier.MatchString(c.ID) || !validIdentifier.MatchString(c.IncidentID) {
		return errors.New("invalid containment or incident identifier")
	}
	if c.Workload.Namespace == "" || c.Workload.Pod == "" || c.Workload.PodUID == "" || c.Workload.ContainerID == "" || c.Workload.ID == "" {
		return errors.New("containment requires verified pod UID, container ID, namespace, pod and workload ID")
	}
	if len(c.Workload.Namespace) > 63 || len(c.Workload.Pod) > 253 || len(c.Workload.PodUID) > 128 || len(c.Workload.ContainerID) > 256 || len(c.Workload.ID) > 128 {
		return errors.New("containment target exceeds limits")
	}
	if len(c.Reason) < 10 || len(c.Reason) > 500 {
		return errors.New("containment reason must be 10..500 characters")
	}
	if c.RequestedAt.IsZero() || c.UpdatedAt.IsZero() || c.ExpiresAt.IsZero() || c.UpdatedAt.Before(c.RequestedAt) {
		return errors.New("invalid containment timestamps")
	}
	if d := c.ExpiresAt.Sub(c.RequestedAt); d < time.Minute || d > time.Hour {
		return fmt.Errorf("containment duration must be 1..60 minutes, got %s", d)
	}
	if c.Mode != "simulate" && c.Mode != "kubernetes" {
		return errors.New("invalid containment execution mode")
	}
	switch c.State {
	case "requested", "applied", "release_requested", "released":
	default:
		return errors.New("unsupported containment state")
	}
	return nil
}
