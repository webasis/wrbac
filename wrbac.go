package wrbac

import (
	"errors"
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

type RoleSet map[Auther]bool

func (rs RoleSet) AuthRPC(req wrpc.Req) bool {
	for role := range rs {
		if role.AuthRPC(req) {
			return true
		}
	}
	return false
}

func (rs RoleSet) AuthSync(token string, m wsync.AuthMethod, topic string) bool {
	for role := range rs {
		if role.AuthSync(token, m, topic) {
			return true
		}
	}
	return false
}

type User struct {
	Secrets map[string]RoleSet // map[secret]
	Masks   map[string]Auther  // map[secret]
}

func NewUser() *User {
	u := &User{
		Secrets: make(map[string]RoleSet),
		Masks:   make(map[string]Auther),
	}
	return u
}

func (u *User) Add(secret string, authers ...Auther) *User {
	rs := make(RoleSet)
	for _, a := range authers {
		rs[a] = true
	}
	u.Secrets[secret] = rs
	return u
}

type Table struct {
	sync.RWMutex
	Users map[string]*User // map[name]
	Roles map[string]Auther
}

func New() *Table {
	return &Table{
		Users: make(map[string]*User),
		Roles: make(map[string]Auther),
	}
}

func (t *Table) AuthRPC(req wrpc.Req) bool {
	t.RLock()
	defer t.RUnlock()

	name, secret := FromToken(req.Token)

	u := t.Users[name]
	if u == nil {
		return false
	}

	mask := u.Masks[secret]
	if mask != nil {
		if mask.AuthRPC(req) == false {
			return false
		}
	}

	return u.Secrets[secret].AuthRPC(req)
}

func (t *Table) AuthSync(token string, m wsync.AuthMethod, topic string) bool {
	t.RLock()
	defer t.RUnlock()

	name, secret := FromToken(token)

	u := t.Users[name]
	if u == nil {
		return false
	}

	mask := u.Masks[secret]
	if mask != nil {
		if mask.AuthSync(token, m, topic) == false {
			return false
		}
	}

	return u.Secrets[secret].AuthSync(token, m, topic)
}

func (t *Table) Register(name string, a Auther) {
	t.Update(func() error {
		t.Roles[name] = a
		return nil
	})
}

func (t *Table) Check(roles ...string) bool {
	err := t.View(func() error {
		for _, role := range roles {
			_, ok := t.Roles[role]
			if !ok {
				return errors.New("not found role")
			}
		}
		return nil
	})
	return err == nil
}

func (t *Table) Load(name, secret string, mask string, roles ...string) {
	t.Update(func() error {
		u := t.Users[name]
		if u == nil {
			u = NewUser()
		}

		u.Masks[secret] = t.Roles[mask]

		authers := make([]Auther, 0, len(roles))
		for _, role := range roles {
			a := t.Roles[role]
			if a != nil {
				authers = append(authers, a)
			}
		}
		u.Add(secret, authers...)
		t.Users[name] = u
		return nil
	})
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
