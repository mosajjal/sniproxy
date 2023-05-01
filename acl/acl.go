package acl

import (
	"net"

	"github.com/knadh/koanf"
	slog "golang.org/x/exp/slog"
)

type Decision uint8

const (
	Accept Decision = iota
	Reject
	ProxyIP
	OriginIP
)

// ConnInfo contains all the information about a connection that is available
// it also serves as an ACL enforcer in a sense that if IsRejected is set to true
// the connection is dropped
type ConnInfo struct {
	SrcIP   net.Addr
	DstIP   net.Addr
	DstPort int
	Domain  string
	Decision
}

type acl interface {
	Decide(*ConnInfo) error
	Name() string
	Config(*slog.Logger, *koanf.Koanf) error
}

type ACL struct {
	activeACLs []*acl
}

func (a *ACL) register(acl acl) {
	a.activeACLs = append(a.activeACLs, &acl)
}

func (a *ACL) StartACLs(log *slog.Logger, k *koanf.Koanf) error {
	for _, acl := range tmpACLs.activeACLs {
		// cut each konaf based on the name of the ACL
		cutK := k.Cut((*acl).Name())
		// only configure if the "enabled" key is set to true
		if !cutK.Bool("enabled") {
			// remove the ACL from the list of active ACLs
			// TODO
			continue
		}
		// TODO: set up a new logger with a service name of the ACL
		l := slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue((*acl).Name())}}))
		if err := (*acl).Config(l, cutK); err != nil {
			return err
		}
		a.activeACLs = append(a.activeACLs, acl)
	}
	return nil
}

func (a ACL) MakeDecision(c *ConnInfo) error {
	for _, acl := range a.activeACLs {
		if err := (*acl).Decide(c); err != nil {
			return err
		}
	}
	return nil
}

var tmpACLs ACL
