package acl

import (
	"os"
	"testing"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/rs/zerolog"
)

var reproLogger = zerolog.New(os.Stderr)

// TestConfigAndStartRejectsZeroRefreshInterval guards against the
// time.NewTicker panic: ConfigAndStart must reject a non-positive
// refresh_interval instead of spawning a refresh goroutine that calls
// time.NewTicker(0) (which panics and crashes the whole process).
func TestConfigAndStartRejectsZeroRefreshInterval(t *testing.T) {
	load := func(yamlDoc string) *koanf.Koanf {
		k := koanf.New(".")
		if err := k.Load(rawbytes.Provider([]byte(yamlDoc)), yaml.Parser()); err != nil {
			t.Fatalf("koanf load: %v", err)
		}
		return k
	}

	cases := []struct {
		name string
		acl  ACL
		doc  string
	}{
		{
			name: "cidr",
			acl:  &cidr{},
			doc: `
acl:
  cidr:
    enabled: true
    priority: 30
    path: ../../cidr.csv
    refresh_interval: 0
`,
		},
		{
			name: "domain",
			acl:  &domain{},
			doc: `
acl:
  domain:
    enabled: true
    priority: 20
    path: ../../domains.csv
    refresh_interval: 0
`,
		},
		{
			name: "geoip",
			acl:  &geoIP{},
			doc: `
acl:
  geoip:
    enabled: true
    priority: 10
    path: ../../GeoLite2-Country.mmdb
    refresh_interval: 0
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.acl.ConfigAndStart(&reproLogger, load(tc.doc))
			if err == nil {
				t.Fatal("ConfigAndStart returned nil error for zero refresh_interval; expected rejection")
			}
		})
	}
}

// TestConfigAndStartAcceptsPositiveRefreshInterval ensures the validation
// does not break the normal configuration path.
func TestConfigAndStartAcceptsPositiveRefreshInterval(t *testing.T) {
	k := koanf.New(".")
	if err := k.Load(rawbytes.Provider([]byte(`
acl:
  cidr:
    enabled: true
    priority: 30
    path: ../../cidr.csv
    refresh_interval: 1h0m0s
`)), yaml.Parser()); err != nil {
		t.Fatalf("koanf load: %v", err)
	}

	d := &cidr{}
	if err := d.ConfigAndStart(&reproLogger, k); err != nil {
		t.Fatalf("ConfigAndStart rejected valid config: %v", err)
	}
	d.Stop()
}
