// Package identity binds authenticated node collectors to live Kubernetes pod
// membership. This mode deliberately fails closed and does not cache pod state.
package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cloudruntimeguardian/internal/model"
)

var (
	ErrUnauthenticated = errors.New("collector authentication failed")
	ErrMismatch        = errors.New("event identity does not match live Kubernetes state")
	ErrUnavailable     = errors.New("Kubernetes identity verification unavailable")
)

// A NodeCredential binds one independent source credential to a Kubernetes
// node. Tokens must be unique and at least 32 bytes long.
type NodeCredential struct {
	Node  string `json:"node"`
	Token string `json:"token"`
}

type credentialFile struct {
	Nodes []NodeCredential `json:"nodes"`
}

var validNode = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// LoadCredentials accepts private regular files and Kubernetes projected Secret
// symlinks, provided the resolved target stays within the credential directory.
// A dedicated fsGroup is needed for projected Secret mode 0440.
func LoadCredentials(path string) ([]NodeCredential, error) {
	root, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil, errors.New("collector credentials must resolve within their mounted directory")
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0027 != 0 {
		return nil, errors.New("collector credential file must be private (0400, 0440, 0600 or 0640)")
	}
	if fi.Size() > 64<<10 {
		return nil, errors.New("collector credential file is too large")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<10 {
		return nil, errors.New("collector credential file is too large")
	}
	var v credentialFile
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("invalid credential file: %w", err)
	}
	if len(v.Nodes) == 0 || len(v.Nodes) > 1024 {
		return nil, errors.New("collector credentials must contain 1..1024 nodes")
	}
	seenNodes, seenTokens := map[string]bool{}, map[[32]byte]bool{}
	for _, n := range v.Nodes {
		if len(n.Node) > 253 || !validNode.MatchString(n.Node) || strings.Contains(n.Node, "..") || len(n.Token) < 32 || len(n.Token) > 4096 {
			return nil, errors.New("invalid node name or token length")
		}
		digest := sha256.Sum256([]byte(n.Token))
		if seenNodes[n.Node] || seenTokens[digest] {
			return nil, errors.New("duplicate node or credential")
		}
		seenNodes[n.Node], seenTokens[digest] = true, true
	}
	return v.Nodes, nil
}

type Resolver interface {
	LookupPod(context.Context, string, string) (Pod, error)
}

type Pod struct {
	UID          string
	Namespace    string
	Name         string
	Node         string
	Deleting     bool
	ContainerIDs []string
}

type boundSource struct {
	node string
	hash [32]byte
}

type Verifier struct {
	sources  []boundSource
	resolver Resolver
}

func New(resolver Resolver, nodes []NodeCredential) (*Verifier, error) {
	if resolver == nil || len(nodes) == 0 || len(nodes) > 1024 {
		return nil, errors.New("resolver and source credentials required")
	}
	seenNodes, seenTokens := map[string]bool{}, map[[32]byte]bool{}
	v := &Verifier{resolver: resolver}
	for _, n := range nodes {
		h := sha256.Sum256([]byte(n.Token))
		if len(n.Token) < 32 || len(n.Token) > 4096 || len(n.Node) > 253 || !validNode.MatchString(n.Node) || seenNodes[n.Node] || seenTokens[h] {
			return nil, errors.New("invalid or duplicate source credential")
		}
		seenNodes[n.Node], seenTokens[h] = true, true
		v.sources = append(v.sources, boundSource{node: n.Node, hash: h})
	}
	return v, nil
}

// authenticate scans every registered digest without early-returning on
// mismatch. Each source is bound to exactly one node.
func (v *Verifier) authenticate(header string) (string, error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return "", ErrUnauthenticated
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if len(token) < 32 || len(token) > 4096 || strings.TrimSpace(token) != token {
		return "", ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(token))
	match, node := 0, ""
	for _, src := range v.sources {
		equal := subtle.ConstantTimeCompare(digest[:], src.hash[:])
		if equal == 1 {
			node = src.node
		}
		match |= equal
	}
	if match != 1 {
		return "", ErrUnauthenticated
	}
	return node, nil
}

func hash(parts ...string) string {
	s := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(s[:])
}

var validDNS = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// Verify returns a *server-enriched* copy. It does not trust the workload ID,
// namespace, pod, container, or node claims until a live API lookup succeeds.
// Deleting/old pods are not accepted: historical backfills require a separate,
// explicitly trusted audit-import path and must never bypass this verifier.
func (v *Verifier) Verify(ctx context.Context, authorization string, e model.Event) (model.Event, error) {
	node, err := v.authenticate(authorization)
	if err != nil {
		return e, err
	}
	if err := e.Validate(); err != nil {
		return e, fmt.Errorf("%w: invalid source event: %v", ErrMismatch, err)
	}
	if e.HostID != hash("host", node) {
		return e, fmt.Errorf("%w: host does not belong to credential node", ErrMismatch)
	}
	w := e.Workload
	if w.Namespace == "" || w.Pod == "" || w.PodUID == "" || w.ContainerID == "" || !validDNS.MatchString(w.Namespace) || !validDNS.MatchString(w.Pod) ||
		w.ID != hash("container", w.ContainerID) {
		return e, fmt.Errorf("%w: incomplete or inconsistent workload identity", ErrMismatch)
	}
	pod, err := v.resolver.LookupPod(ctx, w.Namespace, w.Pod)
	if err != nil {
		return e, err
	}
	if pod.UID == "" || pod.Deleting || pod.Namespace != w.Namespace || pod.Name != w.Pod || pod.Node != node ||
		w.PodUID != pod.UID {
		return e, fmt.Errorf("%w: pod UID, node or lifecycle mismatch", ErrMismatch)
	}
	matched := false
	for _, id := range pod.ContainerIDs {
		if id == w.ContainerID {
			matched = true
		}
	}
	if !matched {
		return e, fmt.Errorf("%w: container not present in current pod status", ErrMismatch)
	}
	e.Workload.PodUID = pod.UID
	e.Workload.ID = hash("k8s-workload", pod.UID, w.ContainerID)
	return e, nil
}

// StatusCode maps identity failures to an HTTP status. Transient API errors
// must yield 503 so collector retries without advancing checkpoints.
func StatusCode(err error) int {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized
	case errors.Is(err, ErrMismatch):
		return http.StatusConflict
	default:
		return http.StatusServiceUnavailable
	}
}
