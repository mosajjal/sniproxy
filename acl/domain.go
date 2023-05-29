package acl

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-collections/collections/tst"
	"github.com/knadh/koanf"
	"github.com/rs/zerolog"
)

// domain ACL makes a decision on a connection based on the domain name derived
// from client hello's SNI. It can be used to skip the sni proxy for certain domains
type domain struct {
	Path            string        `yaml:"domain.path"`
	RefreshInterval time.Duration `yaml:"domain.refresh_interval"`
	routePrefixes   *tst.TernarySearchTree
	routeSuffixes   *tst.TernarySearchTree
	routeFQDNs      map[string]uint8
	logger          *zerolog.Logger
	priority        uint
}

const (
	matchPrefix = uint8(1)
	matchSuffix = uint8(2)
	matchFQDN   = uint8(3)
)

// inDomainList returns true if the domain is meant to be SKIPPED and not go through sni proxy
func (d domain) inDomainList(fqdn string) bool {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}
	fqdnLower := strings.ToLower(fqdn)
	// check for fqdn match
	if d.routeFQDNs[fqdnLower] == matchFQDN {
		return false
	}
	// check for prefix match
	if longestPrefix := d.routePrefixes.GetLongestPrefix(fqdnLower); longestPrefix != nil {
		// check if the longest prefix is present in the type hashtable as a prefix
		if d.routeFQDNs[longestPrefix.(string)] == matchPrefix {
			return false
		}
	}
	// check for suffix match. Note that suffix is just prefix reversed
	if longestSuffix := d.routeSuffixes.GetLongestPrefix(reverse(fqdnLower)); longestSuffix != nil {
		// check if the longest suffix is present in the type hashtable as a suffix
		if d.routeFQDNs[longestSuffix.(string)] == matchSuffix {
			return false
		}
	}
	return true
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// LoadDomainsCsv loads a domains Csv file/URL. returns 3 parameters:
// 1. a TST for all the prefixes (type 1)
// 2. a TST for all the suffixes (type 2)
// 3. a hashtable for all the full match fqdn (type 3)
func (d *domain) LoadDomainsCsv(Filename string) error {
	d.logger.Info().Msg("Loading the domain from file/url")
	var scanner *bufio.Scanner
	if strings.HasPrefix(Filename, "http://") || strings.HasPrefix(Filename, "https://") {
		d.logger.Info().Msg("domain list is a URL, trying to fetch")
		client := http.Client{
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				r.URL.Opaque = r.URL.Path
				return nil
			},
		}
		resp, err := client.Get(Filename)
		if err != nil {
			d.logger.Error().Msg(err.Error())
			return err
		}
		d.logger.Info().Msgf("(re)fetching URL: %s", Filename)
		defer resp.Body.Close()
		scanner = bufio.NewScanner(resp.Body)

	} else {
		file, err := os.Open(Filename)
		if err != nil {
			return err
		}
		d.logger.Info().Msgf("(re)loading file: %s", Filename)
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}
	for scanner.Scan() {
		lowerCaseLine := strings.ToLower(scanner.Text())
		// split the line by comma to understand thed.logger.c
		fqdn := strings.Split(lowerCaseLine, ",")
		if len(fqdn) != 2 {
			d.logger.Info().Msg(lowerCaseLine + " is not a valid line, assuming FQDN")
			fqdn = []string{lowerCaseLine, "fqdn"}
		}
		// add the fqdn to the hashtable with its type
		switch entryType := fqdn[1]; entryType {
		case "prefix":
			d.routeFQDNs[fqdn[0]] = matchPrefix
			d.routePrefixes.Insert(fqdn[0], fqdn[0])
		case "suffix":
			d.routeFQDNs[fqdn[0]] = matchSuffix
			// suffix match is much faster if we reverse the strings and match for prefix
			d.routeSuffixes.Insert(reverse(fqdn[0]), fqdn[0])
		case "fqdn":
			d.routeFQDNs[fqdn[0]] = matchFQDN
		default:
			//d.logger.Warnf("%s is not a valid line, assuming fqdn", lowerCaseLine)
			d.logger.Info().Msg(lowerCaseLine + " is not a valid line, assuming FQDN")
			d.routeFQDNs[fqdn[0]] = matchFQDN
		}
	}
	d.logger.Info().Msgf("%s loaded with %d prefix, %d suffix and %d fqdn", Filename, d.routePrefixes.Len(), d.routeSuffixes.Len(), len(d.routeFQDNs)-d.routePrefixes.Len()-d.routeSuffixes.Len())

	return nil
}

func (d *domain) LoadDomainsCSVWorker() {
	for {
		d.LoadDomainsCsv(d.Path)
		time.Sleep(d.RefreshInterval)
	}
}

// implement domain as an ACL interface
func (d domain) Decide(c *ConnInfo) error {
	d.logger.Debug().Any("conn", c).Msg("deciding on domain acl")

	if c.Decision == Reject {
		c.DstIP = net.TCPAddr{IP: net.IPv4zero, Port: 0}
		d.logger.Debug().Any("conn", c).Msg("decided on domain acl")
		return nil
	}
	if d.inDomainList(c.Domain) {
		d.logger.Debug().Msgf("domain not going through proxy: %s", c.Domain)
		c.Decision = OriginIP
	} else {
		d.logger.Debug().Msgf("domain going through proxy: %s", c.Domain)
		c.Decision = ProxyIP
	}
	d.logger.Debug().Any("conn", c).Msg("decided on domain acl")
	return nil
}
func (d domain) Name() string {
	return "domain"
}
func (d domain) Priority() uint {
	return d.priority
}

func (d *domain) ConfigAndStart(logger *zerolog.Logger, c *koanf.Koanf) error {
	c = c.Cut(fmt.Sprintf("acl.%s", d.Name()))
	d.logger = logger
	d.routePrefixes = tst.New()
	d.routeSuffixes = tst.New()
	d.routeFQDNs = make(map[string]uint8)
	d.Path = c.String("path")
	d.priority = uint(c.Int("priority"))
	d.RefreshInterval = c.Duration("refresh_interval")
	go d.LoadDomainsCSVWorker()
	return nil
}

// make domain available to the ACL system at import time
func init() {
	availableACLs = append(availableACLs, &domain{})
}
