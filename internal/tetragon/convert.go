// Package tetragon converts documented Tetragon JSON export events into the
// runtime event contract. It deliberately ignores unrecognized event types.
package tetragon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"cloudruntimeguardian/internal/model"
)

type process struct {
	ExecID       string `json:"exec_id"`
	ParentExecID string `json:"parent_exec_id"`
	PID          int    `json:"pid"`
	Binary       string `json:"binary"`
	Docker       string `json:"docker"`
	Pod          *struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Container *struct {
			ID string `json:"id"`
		} `json:"container"`
	} `json:"pod"`
}

type execEvent struct {
	Process process `json:"process"`
}
type connectEvent struct {
	Process         process `json:"process"`
	DestinationIP   string  `json:"destination_ip"`
	DestinationPort int     `json:"destination_port"`
	Protocol        string  `json:"protocol"`
}
type envelope struct {
	NodeName string        `json:"node_name"`
	Time     time.Time     `json:"time"`
	Exec     *execEvent    `json:"process_exec"`
	Connect  *connectEvent `json:"process_connect"`
}

var ErrUnsupported = errors.New("unsupported Tetragon event type")

func hash(parts ...string) string {
	d := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(d[:])
}

// Convert requires the node name to agree with the configured local node to
// prevent events from different hosts accidentally sharing a boot epoch.
// The event ID includes the source log position, making retries idempotent,
// including after a crash between API acknowledgment and checkpoint fsync.
func Convert(raw []byte, nodeName, bootID, fileID string, offset int64) (model.Event, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return model.Event{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if env.Exec == nil && env.Connect == nil {
		return model.Event{}, ErrUnsupported
	}
	if env.Exec != nil && env.Connect != nil {
		return model.Event{}, errors.New("ambiguous Tetragon event")
	}
	if env.NodeName != nodeName || strings.TrimSpace(nodeName) == "" {
		return model.Event{}, fmt.Errorf("node mismatch: received %q, configured %q", env.NodeName, nodeName)
	}
	if env.Time.IsZero() {
		return model.Event{}, errors.New("missing Tetragon event time")
	}
	var p process
	e := model.Event{ID: hash("event", nodeName, bootID, fileID, fmt.Sprint(offset)), OccurredAt: env.Time.UTC(),
		HostID: hash("host", nodeName), BootID: bootID}
	if env.Exec != nil {
		e.Type = model.EventProcessExec
		p = env.Exec.Process
	} else {
		e.Type = model.EventNetworkConnect
		p = env.Connect.Process
		proto := strings.ToLower(env.Connect.Protocol)
		if proto != "tcp" && proto != "udp" {
			return model.Event{}, fmt.Errorf("unsupported protocol %q", env.Connect.Protocol)
		}
		dest, err := netip.ParseAddr(env.Connect.DestinationIP)
		if err != nil || dest.Zone() != "" {
			return model.Event{}, errors.New("invalid destination address")
		}
		e.Network = &model.Network{DestinationIP: dest.String(), DestinationPort: env.Connect.DestinationPort, Protocol: proto}
	}
	if p.ExecID == "" {
		return model.Event{}, errors.New("missing process.exec_id; PID alone is unsafe")
	}
	e.Process.EntityID = hash("proc", p.ExecID)
	if p.ParentExecID != "" {
		e.Process.ParentEntityID = hash("proc", p.ParentExecID)
	}
	e.Process.PID = p.PID
	e.Process.Executable = p.Binary
	switch {
	case p.Pod != nil && p.Pod.Container != nil && p.Pod.Container.ID != "":
		e.Workload.ID = hash("container", p.Pod.Container.ID)
		e.Workload.Namespace = p.Pod.Namespace
		e.Workload.Pod = p.Pod.Name
		e.Workload.ContainerID = p.Pod.Container.ID
	case p.Docker != "":
		e.Workload.ID = hash("container", p.Docker)
		e.Workload.ContainerID = p.Docker
	case p.Pod != nil:
		return model.Event{}, errors.New("pod event lacks stable container identity")
	default:
		e.Workload.ID = hash("host-workload", nodeName, bootID)
	}
	if err := e.Validate(); err != nil {
		return model.Event{}, err
	}
	return e, nil
}
