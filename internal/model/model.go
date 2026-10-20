// Package model defines the on-wire event and incident schemas.
package model

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	EventProcessExec    = "process.exec"
	EventNetworkConnect = "network.connect"
	RuleShellEgress     = "shell_external_egress"
	Window              = 5 * time.Minute
)

var validIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,128}$`)

type Workload struct {
	ID          string `json:"id"`
	Namespace   string `json:"namespace,omitempty"`
	Pod         string `json:"pod,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
}

type Process struct {
	EntityID       string `json:"entity_id"`
	ParentEntityID string `json:"parent_entity_id,omitempty"`
	PID            int    `json:"pid"`
	Executable     string `json:"executable,omitempty"`
}

type Network struct {
	DestinationIP   string `json:"destination_ip"`
	DestinationPort int    `json:"destination_port"`
	Protocol        string `json:"protocol"`
}

type Event struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`
	HostID     string    `json:"host_id"`
	BootID     string    `json:"boot_id"`
	Workload   Workload  `json:"workload"`
	Process    Process   `json:"process"`
	Network    *Network  `json:"network,omitempty"`
}

func (e Event) Validate() error {
	required := map[string]string{
		"id": e.ID, "host_id": e.HostID, "boot_id": e.BootID,
		"workload.id": e.Workload.ID, "process.entity_id": e.Process.EntityID,
	}
	for k, v := range required {
		if !validIdentifier.MatchString(v) {
			return fmt.Errorf("%s must contain 1-128 safe identifier characters", k)
		}
	}
	if e.Process.ParentEntityID != "" && !validIdentifier.MatchString(e.Process.ParentEntityID) {
		return errors.New("process.parent_entity_id is invalid")
	}
	if e.Process.ParentEntityID != "" && e.Process.ParentEntityID == e.Process.EntityID {
		return errors.New("process cannot be its own parent")
	}
	if e.Process.PID < 1 {
		return errors.New("process.pid must be positive")
	}
	if e.OccurredAt.IsZero() {
		return errors.New("occurred_at is required")
	}
	if len(e.Workload.Namespace) > 128 || len(e.Workload.Pod) > 128 || len(e.Workload.ContainerID) > 256 {
		return errors.New("workload metadata exceeds maximum length")
	}
	if len(e.Process.Executable) > 4096 {
		return errors.New("process.executable is too long")
	}
	switch e.Type {
	case EventProcessExec:
		if strings.TrimSpace(e.Process.Executable) == "" {
			return errors.New("process.executable is required for process.exec")
		}
		if e.Network != nil {
			return errors.New("network must be omitted for process.exec")
		}
	case EventNetworkConnect:
		if e.Network == nil {
			return errors.New("network is required for network.connect")
		}
		ip, err := netip.ParseAddr(e.Network.DestinationIP)
		if err != nil || ip.Zone() != "" {
			return errors.New("network.destination_ip must be a valid IP address")
		}
		if e.Network.DestinationPort < 1 || e.Network.DestinationPort > 65535 {
			return errors.New("network.destination_port must be 1..65535")
		}
		if e.Network.Protocol != "tcp" && e.Network.Protocol != "udp" {
			return errors.New("network.protocol must be tcp or udp")
		}
	default:
		return errors.New("unsupported event type")
	}
	return nil
}

// ExternalIP is a heuristic, not a substitute for an organization egress policy.
// It excludes private, loopback, link-local, unspecified and multicast addresses.
func ExternalIP(s string) bool {
	ip, err := netip.ParseAddr(s)
	return err == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

func IsShell(executable string) bool {
	switch filepath.Base(executable) {
	case "sh", "bash", "dash", "ash", "zsh", "ksh", "fish":
		return true
	default:
		return false
	}
}

// Scope includes the boot epoch to avoid joining reused process identities.
func (e Event) Scope() string {
	return e.HostID + "\x00" + e.BootID + "\x00" + e.Workload.ID
}

type Evidence struct {
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	OccurredAt  time.Time `json:"occurred_at"`
	ProcessID   string    `json:"process_id"`
	Executable  string    `json:"executable,omitempty"`
	Destination string    `json:"destination,omitempty"`
}

type Incident struct {
	ID        string           `json:"id"`
	RuleID    string           `json:"rule_id"`
	Severity  string           `json:"severity"`
	Summary   string           `json:"summary"`
	Workload  Workload         `json:"workload"`
	HostID    string           `json:"host_id"`
	FirstSeen time.Time        `json:"first_seen"`
	LastSeen  time.Time        `json:"last_seen"`
	Evidence  []Evidence       `json:"evidence"`
	Responses []ResponseAction `json:"responses"`
}

type ResponseAction struct {
	RequestID          string    `json:"request_id"`
	IncidentID         string    `json:"incident_id"`
	Action             string    `json:"action"`
	Reason             string    `json:"reason"`
	RequestedAt        time.Time `json:"requested_at"`
	Mode               string    `json:"mode"`
	EnforcementApplied bool      `json:"enforcement_applied"`
}

func (r ResponseAction) Validate() error {
	if !validIdentifier.MatchString(r.RequestID) {
		return errors.New("request_id must be a safe identifier")
	}
	if !validIdentifier.MatchString(r.IncidentID) {
		return errors.New("incident_id is invalid")
	}
	if r.Action != "block_workload_egress" {
		return errors.New("unsupported response action")
	}
	if len(strings.TrimSpace(r.Reason)) < 3 || len(r.Reason) > 500 {
		return errors.New("reason must be 3..500 characters")
	}
	return nil
}
