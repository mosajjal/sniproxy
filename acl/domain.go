package acl

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-collections/collections/tst"
	"github.com/knadh/koanf"
	slog "golang.org/x/exp/slog"
)

type domain struct {
	Path            string        `yaml:"domain.path"`
	RefreshInterval time.Duration `yaml:"domain.refresh_interval"`
	routePrefixes   *tst.TernarySearchTree
	routeSuffixes   *tst.TernarySearchTree
	routeFQDNs      map[string]uint8
	logger          *slog.Logger
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

func Test_reverse(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{name: "test1", s: "abc", want: "cba"},
		{name: "test2", s: "a", want: "a"},
		{name: "test3", s: "aab", want: "baa"},
		{name: "test4", s: "zzZ", want: "Zzz"},
		{name: "test5", s: "ab2", want: "2ba"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverse(tt.s); got != tt.want {
				t.Errorf("reverse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// LoadDomainsCsv loads a domains Csv file/URL. returns 3 parameters:
// 1. a TST for all the prefixes (type 1)
// 2. a TST for all the suffixes (type 2)
// 3. a hashtable for all the full match fqdn (type 3)
func (d *domain) LoadDomainsCsv(Filename string) error {
	d.logger.Info("Loading the domain from file/url")
	var scanner *bufio.Scanner
	if strings.HasPrefix(Filename, "http://") || strings.HasPrefix(Filename, "https://") {
		d.logger.Info("domain list is a URL, trying to fetch")
		client := http.Client{
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				r.URL.Opaque = r.URL.Path
				return nil
			},
		}
		resp, err := client.Get(Filename)
		if err != nil {
			d.logger.Error(err.Error())
			return err
		}
		d.logger.Info("(re)fetching URL", "url", Filename)
		defer resp.Body.Close()
		scanner = bufio.NewScanner(resp.Body)

	} else {
		file, err := os.Open(Filename)
		if err != nil {
			return err
		}
		d.logger.Info("(re)loading File", "file", Filename)
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}
	for scanner.Scan() {
		lowerCaseLine := strings.ToLower(scanner.Text())
		// split the line by comma to understand thed.logger.c
		fqdn := strings.Split(lowerCaseLine, ",")
		if len(fqdn) != 2 {
			d.logger.Info(lowerCaseLine + " is not a valid line, assuming FQDN")
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
			d.logger.Info(lowerCaseLine + " is not a valid line, assuming FQDN")
			d.routeFQDNs[fqdn[0]] = matchFQDN
		}
	}
	d.logger.Info(fmt.Sprintf("%s loaded with %d prefix, %d suffix and %d fqdn", Filename, d.routePrefixes.Len(), d.routeSuffixes.Len(), len(d.routeFQDNs)-d.routePrefixes.Len()-d.routeSuffixes.Len()))

	return nil
}

func (d *domain) LoadDomainsCsvWorker() {
	for {
		d.LoadDomainsCsv(d.Path)
		time.Sleep(d.RefreshInterval)
	}
}

// implement domain as an ACL interface
func (d domain) Decide(c *ConnInfo) error {
	// true means skip
	if c.Decision == Reject {
		c.DstIP = nil
		return nil
	}
	if d.inDomainList(c.Domain) {
		c.Decision = OriginIP
	} else {
		c.Decision = ProxyIP
	}
	return nil
}
func (d domain) Name() string {
	return "domain"
}
func (d *domain) Config(logger *slog.Logger, c *koanf.Koanf) error {
	d.logger = logger
	d.routePrefixes = tst.New()
	d.routeSuffixes = tst.New()
	d.routeFQDNs = make(map[string]uint8)
	d.Path = c.String("path")
	d.RefreshInterval = c.Duration("refresh_interval")
	// BUG: refresh interval not running
	go d.LoadDomainsCsvWorker()
	return nil
}

// Register the geoIP ACL
func init() {
	tmpACLs.register(&domain{})
}
