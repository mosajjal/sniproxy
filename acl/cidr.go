package acl

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/knadh/koanf"
	"github.com/yl2chen/cidranger"
	slog "golang.org/x/exp/slog"
)

// CIDR acl allows sniproxy to use a list of CIDR to allow or reject connections
// The list is loaded from a file or URL and refreshed periodically
// The list is a CSV file with the CIDR in the first column and the policy in the second
// The policy can be allow or reject and defaults to reject
type cidr struct {
	Path            string        `yaml:"path"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	AllowRanger     cidranger.Ranger
	RejectRanger    cidranger.Ranger
	logger          *slog.Logger
}

func (d *cidr) LoadCIDRCSV(path string) error {
	d.AllowRanger = cidranger.NewPCTrieRanger()
	d.RejectRanger = cidranger.NewPCTrieRanger()

	d.logger.Info("Loading the CIDR from file/url")
	var scanner *bufio.Scanner
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		d.logger.Info("CIDR list is a URL, trying to fetch")
		client := http.Client{
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				r.URL.Opaque = r.URL.Path
				return nil
			},
		}
		resp, err := client.Get(path)
		if err != nil {
			d.logger.Error(err.Error())
			return err
		}
		d.logger.Info("(re)fetching URL", "path", path)
		defer resp.Body.Close()
		scanner = bufio.NewScanner(resp.Body)

	} else {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		d.logger.Info("(re)loading File", "path", path)
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}

	for scanner.Scan() {
		row := scanner.Text()
		// cut the line at the first comma
		cidr, policy, found := strings.Cut(row, ",")
		if !found {
			d.logger.Info(cidr + " is not a valid csv line, assuming reject")
		}
		if policy == "allow" {
			if _, netw, err := net.ParseCIDR(cidr); err == nil {
				_ = d.AllowRanger.Insert(cidranger.NewBasicRangerEntry(*netw))
			} else {
				if _, netw, err := net.ParseCIDR(cidr + "/32"); err == nil {
					_ = d.AllowRanger.Insert(cidranger.NewBasicRangerEntry(*netw))
				} else {
					d.logger.Error(err.Error())
				}
			}
		} else {
			if _, netw, err := net.ParseCIDR(cidr); err == nil {
				_ = d.RejectRanger.Insert(cidranger.NewBasicRangerEntry(*netw))
			} else {
				if _, netw, err := net.ParseCIDR(cidr + "/32"); err == nil {
					_ = d.RejectRanger.Insert(cidranger.NewBasicRangerEntry(*netw))
				} else {
					d.logger.Error(err.Error())
				}
			}
		}
	}
	d.logger.Info("cidrs loaded", "len", d.AllowRanger.Len())

	return nil
}

func (d *cidr) loadCIDRCSVWorker() {
	for {
		_ = d.LoadCIDRCSV(d.Path)
		time.Sleep(d.RefreshInterval)
	}
}

// Decide checks if the connection is allowed or rejected
func (d cidr) Decide(c *ConnInfo) error {
	// check reject first
	c.Decision = Reject

	// get the IP from the connection
	ipPort := strings.Split(c.SrcIP.String(), ":")
	ip := net.ParseIP(ipPort[0])

	if match, err := d.RejectRanger.Contains(ip); match && err == nil {
		return nil
	}
	if match, err := d.AllowRanger.Contains(ip); match && err == nil {
		c.Decision = Accept
	}
	return nil
}

// Name function is used to cut the YAML config file to be passed on to the ACL for config
func (d cidr) Name() string {
	return "cidr"
}

// Config function is what starts the ACL
func (d *cidr) ConfigAndStart(logger *slog.Logger, c *koanf.Koanf) error {
	d.logger = logger
	d.Path = c.String("path")
	d.RefreshInterval = c.Duration("refresh_interval")
	go d.loadCIDRCSVWorker()
	return nil
}

// make the acl available at import time
func init() {
	availableACLs = append(availableACLs, &cidr{})
}
