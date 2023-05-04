package acl

import (
	"net"

	"github.com/knadh/koanf"
	slog "golang.org/x/exp/slog"
)

// Decision is the type of decision that an ACL can make for each connection info
type Decision uint8

const (
	// Accept shows the indifference of the ACL to the connection
	Accept Decision = iota
	// Reject shows that the ACL has rejected the connection. each ACL should check this before proceeding to check the connection against its rules
	Reject
	// ProxyIP shows that the ACL has decided to proxy the connection through sniproxy rather than the origin IP
	ProxyIP
	// OriginIP shows that the ACL has decided to proxy the connection through the origin IP rather than sniproxy
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
	ConfigAndStart(*slog.Logger, *koanf.Koanf) error
}

// ACL holds all the acl interfaces as a list and provides
// a way for them to be registered and started
type ACL struct {
	activeACLs []*acl
}

// StartACLs starts all the ACLs that have been configured and registered
func (a *ACL) StartACLs(log *slog.Logger, k *koanf.Koanf) error {
	for _, acl := range availableACLs {
		// cut each konaf based on the name of the ACL
		cutK := k.Cut((acl).Name())
		// only configure if the "enabled" key is set to true
		if !cutK.Bool("enabled") {
			// remove the ACL from the list of active ACLs
			// TODO
			continue
		}
		l := slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue((acl).Name())}}))
		if err := (acl).ConfigAndStart(l, cutK); err != nil {
			return err
		}
		a.activeACLs = append(a.activeACLs, &acl)
	}
	return nil
}

// MakeDecision loops through all the ACLs and makes a decision for the connection
func (a ACL) MakeDecision(c *ConnInfo) error {
	for _, acl := range a.activeACLs {
		if err := (*acl).Decide(c); err != nil {
			return err
		}
	}
	return nil
}

// each ACL should register itself by appending itself to this list
var availableACLs []acl
