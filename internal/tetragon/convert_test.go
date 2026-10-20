package tetragon

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"cloudruntimeguardian/internal/model"
)

const execFixture = `{"process_exec":{"process":{"exec_id":"node:100:110","parent_exec_id":"node:100:100","pid":110,"binary":"/bin/bash","pod":{"namespace":"finance","name":"payment-0","container":{"id":"containerd://abc123"}}}},"node_name":"worker-1","time":"2026-10-20T01:00:00Z"}`
const connectFixture = `{"process_connect":{"process":{"exec_id":"node:100:110","parent_exec_id":"node:100:100","pid":110,"binary":"/bin/bash","pod":{"namespace":"finance","name":"payment-0","container":{"id":"containerd://abc123"}}},"destination_ip":"8.8.8.8","destination_port":443,"protocol":"TCP"},"node_name":"worker-1","time":"2026-10-20T01:00:30Z"}`

func TestConvertProcessAndNetworkEvents(t *testing.T) {
	a, err := Convert([]byte(execFixture), "worker-1", "boot-1", "5:77", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Convert([]byte(connectFixture), "worker-1", "boot-1", "5:77", int64(len(execFixture)+1))
	if err != nil {
		t.Fatal(err)
	}
	if a.Type != model.EventProcessExec || b.Type != model.EventNetworkConnect {
		t.Fatalf("wrong types: %s %s", a.Type, b.Type)
	}
	if a.Process.EntityID != b.Process.EntityID || a.Workload.ID != b.Workload.ID {
		t.Fatalf("identity mismatch: %#v %#v", a, b)
	}
	if a.Process.ParentEntityID == "" || a.Process.ParentEntityID == a.Process.EntityID {
		t.Fatal("unsafe ancestry")
	}
	if b.Network.Protocol != "tcp" || b.Network.DestinationIP != "8.8.8.8" {
		t.Fatalf("network: %#v", b.Network)
	}
	if b.OccurredAt.Sub(a.OccurredAt) != 30*time.Second {
		t.Fatal("wrong timestamp")
	}
	other, _ := Convert([]byte(execFixture), "worker-1", "boot-1", "5:77", 1)
	if other.ID == a.ID {
		t.Fatal("offset must affect deterministic event ID")
	}
}

func TestRejectUnsafeSourceFields(t *testing.T) {
	tests := []struct {
		name, raw, node string
		unsupported     bool
	}{
		{"missing process ID", `{"process_exec":{"process":{"pid":10,"binary":"/bin/bash"}},"node_name":"worker-1","time":"2026-10-20T01:00:00Z"}`, "worker-1", false},
		{"node mismatch", execFixture, "worker-2", false},
		{"missing stable workload", `{"process_exec":{"process":{"exec_id":"x","pid":10,"binary":"/bin/bash","pod":{"name":"pay","namespace":"test"}}},"node_name":"worker-1","time":"2026-10-20T01:00:00Z"}`, "worker-1", false},
		{"unsupported unrelated", `{"process_exit":{},"node_name":"worker-1","time":"2026-10-20T01:00:00Z"}`, "worker-1", true},
		{"ambiguous", fmt.Sprintf(`{"process_exec":{"process":{"exec_id":"x"}},"process_connect":{},"node_name":"worker-1","time":"%s"}`, time.Now().UTC().Format(time.RFC3339)), "worker-1", false},
		{"malformed JSON", `{"process_exec":`, "worker-1", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Convert([]byte(test.raw), test.node, "boot-1", "5:77", 0)
			if err == nil {
				t.Fatal("expected error")
			}
			if errors.Is(err, ErrUnsupported) != test.unsupported {
				t.Fatalf("wrong error: %v", err)
			}
		})
	}
}
