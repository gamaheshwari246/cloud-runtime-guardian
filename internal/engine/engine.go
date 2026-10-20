// Package engine handles durable ingestion and deterministic two-event rules.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"cloudruntimeguardian/internal/journal"
	"cloudruntimeguardian/internal/model"
)

var (
	ErrConflict = errors.New("idempotency key reused with different payload")
	ErrNotFound = errors.New("incident not found")
	ErrFull     = errors.New("ledger capacity reached; archival/rotation is required")
)

const DefaultMaxEvents = 50000

type indexedEvent struct{ e model.Event }
type scopeState struct {
	shells           map[string][]indexedEvent
	connections      map[string][]indexedEvent
	childConnections map[string][]indexedEvent
}

type Engine struct {
	mu               sync.RWMutex
	ledger           *journal.Journal
	maxEvents        int
	events           map[string][32]byte
	responseRequests map[string]model.ResponseAction
	scopes           map[string]*scopeState
	incidents        map[string]*model.Incident
	totalEvents      int
}

type Stats struct {
	Events          int `json:"events"`
	Incidents       int `json:"incidents"`
	DryRunResponses int `json:"dry_run_responses"`
	Capacity        int `json:"event_capacity"`
}

func Open(path string, maxEvents int) (*Engine, error) {
	if maxEvents < 1 {
		maxEvents = DefaultMaxEvents
	}
	ledger, entries, err := journal.Open(path)
	if err != nil {
		return nil, err
	}
	en := &Engine{ledger: ledger, maxEvents: maxEvents,
		events: make(map[string][32]byte), responseRequests: make(map[string]model.ResponseAction),
		scopes: make(map[string]*scopeState), incidents: make(map[string]*model.Incident)}
	for i, entry := range entries {
		if entry.Kind == "event" {
			if err := entry.Event.Validate(); err != nil {
				ledger.Close()
				return nil, fmt.Errorf("invalid replay event %d: %w", i, err)
			}
			if _, err := en.applyEvent(*entry.Event); err != nil {
				ledger.Close()
				return nil, fmt.Errorf("replay event %d: %w", i, err)
			}
		} else {
			if err := entry.Response.Validate(); err != nil || entry.Response.Mode != "dry_run" || entry.Response.EnforcementApplied || entry.Response.RequestedAt.IsZero() {
				ledger.Close()
				return nil, fmt.Errorf("invalid replay response %d", i)
			}
			if err := en.applyResponse(*entry.Response); err != nil {
				ledger.Close()
				return nil, fmt.Errorf("replay response %d: %w", i, err)
			}
		}
	}
	// Replays are bounded too: opening an oversized ledger is explicit error.
	if en.totalEvents > maxEvents || len(en.responseRequests) > maxEvents {
		ledger.Close()
		return nil, fmt.Errorf("existing ledger exceeds configured capacity; increase max-events or archive")
	}
	return en, nil
}

func (en *Engine) Close() error { en.mu.Lock(); defer en.mu.Unlock(); return en.ledger.Close() }

// Ready is an admission/availability signal. An unhealthy ledger or exhausted
// event/response capacity requires operator action before further ingestion.
func (en *Engine) Ready() bool {
	en.mu.RLock()
	defer en.mu.RUnlock()
	return en.ledger.Healthy() && en.totalEvents < en.maxEvents && len(en.responseRequests) < en.maxEvents
}

func digest(e model.Event) [32]byte { b, _ := json.Marshal(e); return sha256.Sum256(b) }

// Ingest returns created=false for an exact event retry. A reused event id with
// different contents is rejected, including after server restarts.
func (en *Engine) Ingest(e model.Event) (created bool, err error) {
	if err := e.Validate(); err != nil {
		return false, err
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	d := digest(e)
	if old, ok := en.events[e.ID]; ok {
		if old != d {
			return false, ErrConflict
		}
		return false, nil
	}
	if en.totalEvents >= en.maxEvents {
		return false, ErrFull
	}
	if err := en.ledger.Append(journal.Entry{Kind: "event", Event: &e}); err != nil {
		return false, err
	}
	_, err = en.applyEvent(e)
	return err == nil, err
}

func (en *Engine) applyEvent(e model.Event) (bool, error) {
	d := digest(e)
	if old, ok := en.events[e.ID]; ok {
		if old == d {
			return false, nil
		}
		return false, ErrConflict
	}
	en.events[e.ID] = d
	en.totalEvents++
	scope := e.Scope()
	st := en.scopes[scope]
	if st == nil {
		st = &scopeState{
			shells:           make(map[string][]indexedEvent),
			connections:      make(map[string][]indexedEvent),
			childConnections: make(map[string][]indexedEvent),
		}
		en.scopes[scope] = st
	}
	if e.Type == model.EventProcessExec && model.IsShell(e.Process.Executable) {
		// Index by stable process entity rather than scanning unrelated flows.
		// A connection may arrive before the corresponding execution event.
		for _, conn := range st.connections[e.Process.EntityID] {
			en.tryMatch(e, conn.e)
		}
		for _, conn := range st.childConnections[e.Process.EntityID] {
			en.tryMatch(e, conn.e)
		}
		st.shells[e.Process.EntityID] = append(st.shells[e.Process.EntityID], indexedEvent{e: e})
	} else if e.Type == model.EventNetworkConnect && model.ExternalIP(e.Network.DestinationIP) {
		for _, shell := range st.shells[e.Process.EntityID] {
			en.tryMatch(shell.e, e)
		}
		if e.Process.ParentEntityID != "" {
			for _, shell := range st.shells[e.Process.ParentEntityID] {
				en.tryMatch(shell.e, e)
			}
		}
		st.connections[e.Process.EntityID] = append(st.connections[e.Process.EntityID], indexedEvent{e: e})
		if e.Process.ParentEntityID != "" {
			st.childConnections[e.Process.ParentEntityID] = append(st.childConnections[e.Process.ParentEntityID], indexedEvent{e: e})
		}
	}
	return true, nil
}

func (en *Engine) tryMatch(shell, conn model.Event) {
	// Event-time ordering, not arrival ordering. Immediate child linkage is
	// supported. Deep ancestry requires an additional graph index (roadmap).
	dt := conn.OccurredAt.Sub(shell.OccurredAt)
	if dt < 0 || dt > model.Window {
		return
	}
	if conn.Process.EntityID != shell.Process.EntityID && conn.Process.ParentEntityID != shell.Process.EntityID {
		return
	}
	sum := sha256.Sum256([]byte(model.RuleShellEgress + "\x00" + shell.ID + "\x00" + conn.ID))
	id := hex.EncodeToString(sum[:16])
	if _, exists := en.incidents[id]; exists {
		return
	}
	destination := fmt.Sprintf("%s:%d/%s", conn.Network.DestinationIP, conn.Network.DestinationPort, conn.Network.Protocol)
	en.incidents[id] = &model.Incident{
		ID: id, RuleID: model.RuleShellEgress, Severity: "medium",
		Summary:  "Shell execution followed by an external connection in the same workload",
		Workload: shell.Workload, HostID: shell.HostID, FirstSeen: shell.OccurredAt, LastSeen: conn.OccurredAt,
		Evidence: []model.Evidence{
			{EventID: shell.ID, EventType: shell.Type, OccurredAt: shell.OccurredAt, ProcessID: shell.Process.EntityID, Executable: shell.Process.Executable},
			{EventID: conn.ID, EventType: conn.Type, OccurredAt: conn.OccurredAt, ProcessID: conn.Process.EntityID, Destination: destination},
		}, Responses: []model.ResponseAction{},
	}
}

func clone(in *model.Incident) model.Incident {
	out := *in
	out.Evidence = append([]model.Evidence(nil), in.Evidence...)
	out.Responses = append([]model.ResponseAction(nil), in.Responses...)
	return out
}

func (en *Engine) List(limit, offset int) ([]model.Incident, int) {
	en.mu.RLock()
	defer en.mu.RUnlock()
	items := make([]model.Incident, 0, len(en.incidents))
	for _, in := range en.incidents {
		items = append(items, clone(in))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].FirstSeen.Equal(items[j].FirstSeen) {
			return items[i].ID < items[j].ID
		}
		return items[i].FirstSeen.After(items[j].FirstSeen)
	})
	count := len(items)
	if offset >= count {
		return []model.Incident{}, count
	}
	items = items[offset:]
	if len(items) > limit {
		items = items[:limit]
	}
	return items, count
}

func (en *Engine) Get(id string) (model.Incident, bool) {
	en.mu.RLock()
	defer en.mu.RUnlock()
	in, ok := en.incidents[id]
	if !ok {
		return model.Incident{}, false
	}
	return clone(in), true
}

func (en *Engine) Stats() Stats {
	en.mu.RLock()
	defer en.mu.RUnlock()
	return Stats{Events: en.totalEvents, Incidents: len(en.incidents), DryRunResponses: len(en.responseRequests), Capacity: en.maxEvents}
}

// DryRunResponse writes an audited *proposal*. No operating-system, container,
// network, or cloud enforcement action is performed by this MVP.
func (en *Engine) DryRunResponse(r model.ResponseAction) (model.ResponseAction, bool, error) {
	if err := r.Validate(); err != nil {
		return model.ResponseAction{}, false, err
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	if _, exists := en.incidents[r.IncidentID]; !exists {
		return model.ResponseAction{}, false, ErrNotFound
	}
	if prev, exists := en.responseRequests[r.RequestID]; exists {
		if prev.IncidentID != r.IncidentID || prev.Action != r.Action || prev.Reason != r.Reason {
			return model.ResponseAction{}, false, ErrConflict
		}
		return prev, false, nil
	}
	if len(en.responseRequests) >= en.maxEvents {
		return model.ResponseAction{}, false, ErrFull
	}
	r.Mode = "dry_run"
	r.EnforcementApplied = false
	r.RequestedAt = time.Now().UTC()
	if err := en.ledger.Append(journal.Entry{Kind: "response", Response: &r}); err != nil {
		return model.ResponseAction{}, false, err
	}
	if err := en.applyResponse(r); err != nil {
		return model.ResponseAction{}, false, err
	}
	return r, true, nil
}

func (en *Engine) applyResponse(r model.ResponseAction) error {
	in, ok := en.incidents[r.IncidentID]
	if !ok {
		return ErrNotFound
	}
	if prev, ok := en.responseRequests[r.RequestID]; ok {
		if prev != r {
			return ErrConflict
		}
		return nil
	}
	en.responseRequests[r.RequestID] = r
	in.Responses = append(in.Responses, r)
	return nil
}
