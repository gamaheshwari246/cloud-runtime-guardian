package model

import (
	"testing"
	"time"
)

func TestExternalIP(t *testing.T) {
	samples := map[string]bool{"1.1.1.1": true, "8.8.8.8": true, "10.0.1.1": false, "172.16.1.1": false, "192.168.1.1": false, "127.0.0.1": false, "::1": false, "fe80::1": false, "invalid": false}
	for addr, want := range samples {
		if got := ExternalIP(addr); got != want {
			t.Errorf("external(%s)=%t want %t", addr, got, want)
		}
	}
}
func TestValidation(t *testing.T) {
	base := Event{ID: "a", Type: EventProcessExec, OccurredAt: time.Now(), HostID: "h", BootID: "b", Workload: Workload{ID: "w"}, Process: Process{EntityID: "p", PID: 1, Executable: "/bin/sh"}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := base
	invalid.Process.ParentEntityID = "p"
	if invalid.Validate() == nil {
		t.Fatal("same process self-parent allowed")
	}
	invalid = base
	invalid.Process.PID = 0
	if invalid.Validate() == nil {
		t.Fatal("invalid pid allowed")
	}
	invalid = base
	invalid.Network = &Network{DestinationIP: "1.1.1.1", DestinationPort: 443, Protocol: "tcp"}
	if invalid.Validate() == nil {
		t.Fatal("network on exec allowed")
	}
}
