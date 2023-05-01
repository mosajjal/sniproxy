package acl

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/knadh/koanf"
	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/exp/slices"
	slog "golang.org/x/exp/slog"
)

// var g.logger = slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue("geoip")}}))

type geoIP struct {
	Path    string        `yaml:"path"`
	Include []string      `yaml:"include"`
	Exclude []string      `yaml:"exclude"`
	Refresh time.Duration `yaml:"refresh_interval"`
	mmdb    *maxminddb.Reader
	logger  *slog.Logger
}

func toLowerSlice(in []string) (out []string) {
	for _, v := range in {
		out = append(out, strings.ToLower(v))
	}
	return
}

// getCountry returns the country code for the given IP address.
func (g geoIP) getCountry(ipAddr string) (string, error) {
	ip := net.ParseIP(ipAddr)
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	} // Or any appropriate struct

	err := g.mmdb.Lookup(ip, &record)
	if err != nil {
		return "", err
	}
	return record.Country.ISOCode, nil
}

// initializeGeoIP loads the geolocation database from the specified g.Path.
func (g geoIP) initializeGeoIP() error {

	g.logger.Info("Loading the domain from file/url")
	var scanner []byte
	if strings.HasPrefix(g.Path, "http://") || strings.HasPrefix(g.Path, "https://") {
		g.logger.Info("domain list is a URL, trying to fetch")
		resp, err := http.Get(g.Path)
		if err != nil {
			return err
		}
		g.logger.Info("(re)fetching", "g.Path", g.Path)
		defer resp.Body.Close()
		scanner, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

	} else {
		file, err := os.Open(g.Path)
		if err != nil {
			return err
		}
		g.logger.Info("(re)loading File: ", g.Path)
		defer file.Close()
		n, err := file.Read(scanner)
		if err != nil {
			return err
		}
		g.logger.Info("geolocation database loaded", n)

	}
	var err error
	if g.mmdb, err = maxminddb.FromBytes(scanner); err != nil {
		//g.logger.Warn("%d bytes read, %s", len(scanner), err)
		return err
	}
	g.logger.Info("Loaded MMDB")
	for range time.NewTicker(g.Refresh).C {
		if g.mmdb, err = maxminddb.FromBytes(scanner); err != nil {
			//g.logger.Warn("%d bytes read, %s", len(scanner), err)
			return err
		}
		g.logger.Info("Loaded MMDB %v", g.mmdb)
	}
	return nil
}

// checkGeoIPSkip checks an IP address against the exclude and include lists and returns
// true if the IP address should be allowed to pass through.
func (g geoIP) checkGeoIPSkip(ipport string) bool {
	if g.mmdb == nil {
		return true
	}

	ipPort := strings.Split(ipport, ":")
	ip := ipPort[0]

	var country string
	country, err := g.getCountry(ip)
	country = strings.ToLower(country)
	if err != nil {
		g.logger.Info("Failed to get the geolocation of", "ip", ip, "country", country)
		return false
	}
	if slices.Contains(g.Exclude, country) {
		return false
	}
	if slices.Contains(g.Include, country) {
		return true
	}

	// if exclusion is provided, the rest will be allowed
	if len(g.Exclude) > 0 {
		return true
	}

	// othewise fail
	return false
}

// implement the ACL interface
func (g geoIP) Decide(c *ConnInfo) error {
	// in checkGeoIPSkip, false is reject
	if !g.checkGeoIPSkip(c.SrcIP.String()) {
		c.Decision = Reject
	}
	return nil
}
func (g geoIP) Name() string {
	return "geoip"
}
func (g *geoIP) Config(logger *slog.Logger, c *koanf.Koanf) error {
	g.logger = logger
	g.Path = c.String("path")
	g.Include = toLowerSlice(c.Strings("include"))
	g.Exclude = toLowerSlice(c.Strings("exclude"))
	g.Refresh = c.Duration("refresh_interval")
	return g.initializeGeoIP()
}

// Register the geoIP ACL
func init() {
	tmpACLs.register(&geoIP{})
}
