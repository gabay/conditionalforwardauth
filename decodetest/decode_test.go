// Package decodetest checks the plugin's configuration types against the
// decoder Traefik actually uses.
//
// Traefik turns the YAML/label configuration into map[string]interface{} and
// decodes it into the struct returned by CreateConfig with mapstructure,
// configured as in traefik/pkg/plugins: WeaklyTypedInput and a hook that
// splits scalar strings on commas. Nothing in the plugin's own tests exercises
// the mapstructure tags, and a decoding mistake would silently drop
// exemptions, so this module pins the contract.
//
// It is a separate Go module on purpose: the plugin must stay standard-library
// only for Yaegi, and this test needs mapstructure and a YAML parser.
package decodetest

import (
	"os"
	"strings"
	"testing"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"

	cfa "github.com/roigabay/conditionalforwardauth"
)

// decode mirrors traefik/pkg/plugins exactly.
func decode(t *testing.T, raw map[string]interface{}) (*cfa.Config, error) {
	t.Helper()

	cfg := cfa.CreateConfig()
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToSliceHookFunc(","),
		WeaklyTypedInput: true,
		Result:           cfg,
	})
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}

	return cfg, dec.Decode(raw)
}

func fromYAML(t *testing.T, doc string) map[string]interface{} {
	t.Helper()

	var m map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	return m
}

// The catalogue's testData must decode into every key and then compile.
func TestTraefikYAMLTestData(t *testing.T) {
	raw, err := os.ReadFile("../.traefik.yml")
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		TestData map[string]interface{} `yaml:"testData"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("yaml: %v", err)
	}

	cfg, err := decode(t, doc.TestData)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	s := cfg.SkipAuthWhen
	for name, r := range map[string]*cfa.SkipRule{
		"host": s.Host, "path": s.Path, "url": s.URL, "clientIp": s.ClientIP, "userAgent": s.UserAgent,
	} {
		if r == nil {
			t.Errorf("skipAuthWhen.%s did not decode", name)
		}
	}
	if len(s.Custom) != 1 || s.Custom[0].Expression == "" {
		t.Errorf("skipAuthWhen.custom = %+v, want one rule with an expression", s.Custom)
	}
	if got := s.ClientIP.InSubnet; len(got) != 2 {
		t.Errorf("clientIp.inSubnet = %v, want 2 entries", got)
	}

	if _, err := cfa.NewAuthSkipper(s); err != nil {
		t.Errorf("NewAuthSkipper on testData: %v", err)
	}
}

// Shapes the decoder produces that the plugin relies on, or must reject.
func TestDecoderShapes(t *testing.T) {
	t.Run("absent keys stay nil", func(t *testing.T) {
		cfg, err := decode(t, fromYAML(t, `{address: "http://a", skipAuthWhen: {host: {isExactly: [a]}}}`))
		if err != nil {
			t.Fatal(err)
		}
		s := cfg.SkipAuthWhen
		if s.Host == nil || s.Path != nil || s.URL != nil || s.ClientIP != nil || s.UserAgent != nil || s.Custom != nil {
			t.Errorf("got %+v, want only host set", s)
		}
	})

	t.Run("label scalar splits on comma", func(t *testing.T) {
		cfg, err := decode(t, map[string]interface{}{
			"skipAuthWhen": map[string]interface{}{"host": map[string]interface{}{"isExactly": "a.example.com,b.example.com"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.SkipAuthWhen.Host.IsExactly; len(got) != 2 || got[1] != "b.example.com" {
			t.Errorf("isExactly = %v, want [a.example.com b.example.com]", got)
		}
	})

	// The reason empty values are a startup error: a trailing comma in a
	// label produces one, and without the check it would match everything.
	t.Run("trailing comma yields an empty value which NewAuthSkipper rejects", func(t *testing.T) {
		cfg, err := decode(t, map[string]interface{}{
			"skipAuthWhen": map[string]interface{}{"path": map[string]interface{}{"startsWith": "/health,"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.SkipAuthWhen.Path.StartsWith; len(got) != 2 || got[1] != "" {
			t.Fatalf("startsWith = %q, want [/health \"\"]", got)
		}
		_, err = cfa.NewAuthSkipper(cfg.SkipAuthWhen)
		if err == nil || !strings.Contains(err.Error(), "empty value") {
			t.Errorf("NewAuthSkipper error = %v, want an empty-value rejection", err)
		}
	})

	t.Run("pre-1.0 list form is a decode error", func(t *testing.T) {
		_, err := decode(t, fromYAML(t, `{skipAuthWhen: [{expression: "{ .Host }", isExactly: [a]}]}`))
		if err == nil || !strings.Contains(err.Error(), "expected a map, got 'slice'") {
			t.Errorf("error = %v, want \"expected a map, got 'slice'\" (quoted in readme.md)", err)
		}
	})

	t.Run("misplaced keys decode and are then rejected", func(t *testing.T) {
		cfg, err := decode(t, fromYAML(t, `{skipAuthWhen: {path: {isExactly: [/x], inSubnet: [10.0.0.0/8]}}}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = cfa.NewAuthSkipper(cfg.SkipAuthWhen)
		if err == nil || !strings.Contains(err.Error(), "inSubnet is only valid under clientIp") {
			t.Errorf("NewAuthSkipper error = %v, want inSubnet placement error", err)
		}
	})
}
