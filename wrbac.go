package wrbac

import (
	"sync"

	"github.com/webasis/wrpc"
	"github.com/webasis/wsync"
)

type Auther interface {
	AuthRPC(req wrpc.Req) bool
	AuthSync(token string, m wsync.AuthMethod, topic string) bool
}

type Role struct {
	RPC  func(r wrpc.Req) bool
	Sync func(token string, m wsync.AuthMethod, topic string) bool
}

func (r *Role) AuthRPC(req wrpc.Req) bool {
	if r == nil || r.RPC == nil {
		return false
	}
	return r.RPC(req)
}

func (r *Role) AuthSync(token string, m wsync.AuthMethod, topic string) bool {
	if r == nil || r.Sync == nil {
		return false
	}
	return r.Sync(token, m, topic)
}

type RoleSet map[*Role]bool

func (rs RoleSet) AuthRPC(req wrpc.Req) bool {
	for role := range rs {
		if role.RPC(req) {
			return true
		}
	}
	return false
}

func (rs RoleSet) AuthSync(token string, m wsync.AuthMethod, topic string) bool {
	for role := range rs {
		if role.Sync(token, m, topic) {
			return true
		}
	}
	return false
}

type Table struct {
	sync.RWMutex
	Users map[string]RoleSet // map[token]
}

func (t *Table) AuthRPC(req wrpc.Req) bool {
	t.RLock()
	defer t.RUnlock()

	return t.Users[req.Token].AuthRPC(req)
}

func (t *Table) AuthSync(token string, m wsync.AuthMethod, topic string) bool {
	t.RLock()
	defer t.RUnlock()

	return t.Users[token].AuthSync(token, m, topic)
}

func (t *Table) Update(fn func() error) error {
	t.Lock()
	defer t.Unlock()

	return fn()
}

func (t *Table) View(fn func() error) error {
	t.RLock()
	defer t.RUnlock()

	return fn()
}
