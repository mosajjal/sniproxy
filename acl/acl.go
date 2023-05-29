package acl

import (
	"fmt"
	"net"
	"sort"

	"github.com/knadh/koanf"
	"github.com/rs/zerolog"
)

// Decision is the type of decision that an ACL can make for each connection info
type Decision string

const (
	// Accept shows the indifference of the ACL to the connection
	Accept Decision = "Accept"
	// Reject shows that the ACL has rejected the connection. each ACL should check this before proceeding to check the connection against its rules
	Reject Decision = "Reject"
	// ProxyIP shows that the ACL has decided to proxy the connection through sniproxy rather than the origin IP
	ProxyIP Decision = "ProxyIP"
	// OriginIP shows that the ACL has decided to proxy the connection through the origin IP rather than sniproxy
	OriginIP Decision = "OriginIP"
	// Override shows that the ACL has decided to override the connection and proxy it through the specified DstIP and DstPort
	Override Decision = "Override"
)

// ConnInfo contains all the information about a connection that is available
// it also serves as an ACL enforcer in a sense that if IsRejected is set to true
// the connection is dropped
type ConnInfo struct {
	SrcIP  net.Addr
	DstIP  net.TCPAddr
	Domain string
	Decision
}

type ByPriority []ACL

func (a ByPriority) Len() int           { return len(a) }
func (a ByPriority) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByPriority) Less(i, j int) bool { return a[i].Priority() < a[j].Priority() }

type ACL interface {
	Decide(*ConnInfo) error
	Name() string
	Priority() uint
	ConfigAndStart(*zerolog.Logger, *koanf.Koanf) error
}

// StartACLs starts all the ACLs that have been configured and registered
func StartACLs(log *zerolog.Logger, k *koanf.Koanf) ([]ACL, error) {
	var a []ACL
	aclK := k.Cut("acl")
	for _, acl := range availableACLs {
		// cut each konaf based on the name of the ACL
		// only configure if the "enabled" key is set to true
		if !aclK.Bool(fmt.Sprintf("%s.enabled", (acl).Name())) {
			continue
		}
		var l = log.With().Str("acl", (acl).Name()).Logger()
		// we pass the full config to each ACL so that they can cut it themselves. it's needed for some ACLs that need
		// to read the config of other ACLs or the global config
		if err := acl.ConfigAndStart(&l, k); err != nil {
			log.Warn().Msgf("failed to start ACL %s with error %s", (acl).Name(), err)
			return a, err
		}
		a = append(a, acl)
		log.Info().Msgf("started ACL: '%s'", (acl).Name())

	}
	return a, nil
}

// MakeDecision loops through all the ACLs and makes a decision for the connection
func MakeDecision(c *ConnInfo, a []ACL) error {
	sort.Sort(ByPriority(a))
	for _, acl := range a {
		if err := acl.Decide(c); err != nil {
			return err
		}
	}
	// if ACL list is empty, we accept the connection
	if len(a) == 0 {
		c.Decision = Accept
	}
	return nil
}

// each ACL should register itself by appending itself to this list
var availableACLs []ACL
