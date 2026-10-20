// Package incidentindex maintains a bounded in-memory AVL index over durable
// incident records. The index is rebuilt from the write-ahead journal on boot.
// Its only source of truth is the journal; it never acknowledges writes.
package incidentindex

import "time"

// Key sorts incidents by newest occurrence first and by ID ascending for ties.
type Key struct {
	At time.Time
	ID string
}

func less(a, b Key) bool {
	if !a.At.Equal(b.At) {
		return a.At.After(b.At)
	}
	return a.ID < b.ID
}

type node struct {
	key          Key
	left, right  *node
	height, size int
}

type Index struct{ root *node }

func size(n *node) int {
	if n == nil {
		return 0
	}
	return n.size
}
func height(n *node) int {
	if n == nil {
		return 0
	}
	return n.height
}
func update(n *node) {
	n.size = 1 + size(n.left) + size(n.right)
	n.height = 1 + max(height(n.left), height(n.right))
}
func rotateRight(n *node) *node {
	r := n.left
	n.left = r.right
	r.right = n
	update(n)
	update(r)
	return r
}
func rotateLeft(n *node) *node {
	r := n.right
	n.right = r.left
	r.left = n
	update(n)
	update(r)
	return r
}
func rebalance(n *node) *node {
	update(n)
	balance := height(n.left) - height(n.right)
	if balance > 1 {
		if height(n.left.left) < height(n.left.right) {
			n.left = rotateLeft(n.left)
		}
		return rotateRight(n)
	}
	if balance < -1 {
		if height(n.right.right) < height(n.right.left) {
			n.right = rotateRight(n.right)
		}
		return rotateLeft(n)
	}
	return n
}
func insert(n *node, k Key) (*node, bool) {
	if n == nil {
		return &node{key: k, height: 1, size: 1}, true
	}
	if !less(k, n.key) && !less(n.key, k) {
		return n, false
	}
	var added bool
	if less(k, n.key) {
		n.left, added = insert(n.left, k)
	} else {
		n.right, added = insert(n.right, k)
	}
	if !added {
		return n, false
	}
	return rebalance(n), true
}

// Insert is O(log N) worst case and ignores a repeated key.
func (i *Index) Insert(k Key) bool {
	var added bool
	i.root, added = insert(i.root, k)
	return added
}
func (i *Index) Len() int { return size(i.root) }

// afterRank returns the number of keys that are <= k in index order.
// The following page therefore starts strictly after k even if k is absent.
func afterRank(n *node, k Key) int {
	if n == nil {
		return 0
	}
	if less(k, n.key) {
		return afterRank(n.left, k)
	}
	if less(n.key, k) {
		return size(n.left) + 1 + afterRank(n.right, k)
	}
	return size(n.left) + 1
}

// Page returns up to limit keys starting at the provided rank. It walks only
// the requested subtree plus O(log N) nodes; it never sorts or clones all rows.
func (i *Index) Page(offset, limit int) []Key {
	if offset < 0 || limit <= 0 || offset >= i.Len() {
		return nil
	}
	if limit > i.Len()-offset {
		limit = i.Len() - offset
	}
	keys := make([]Key, 0, limit)
	var visit func(*node, int)
	visit = func(n *node, start int) {
		if n == nil || len(keys) >= limit || start+size(n) <= offset {
			return
		}
		visit(n.left, start)
		rank := start + size(n.left)
		if rank >= offset && len(keys) < limit {
			keys = append(keys, n.key)
		}
		if len(keys) < limit {
			visit(n.right, rank+1)
		}
	}
	visit(i.root, 0)
	return keys
}

// PageAfter provides stable keyset pagination if new incidents arrive ahead of
// an existing cursor. Incidents are immutable in this service.
func (i *Index) PageAfter(last Key, limit int) []Key {
	return i.Page(afterRank(i.root, last), limit)
}
