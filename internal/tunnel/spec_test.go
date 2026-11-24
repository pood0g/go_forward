package tunnel

import "testing"

func TestParseForward(t *testing.T) {
	good := map[string]Forward{
		"1080":                         {Listen: "127.0.0.1:1080"},
		"0.0.0.0:1080":                 {Listen: "0.0.0.0:1080"},
		"*:1080":                       {Listen: "0.0.0.0:1080"},
		":1080":                        {Listen: "0.0.0.0:1080"},
		"8080:example.com:80":          {Listen: "127.0.0.1:8080", Target: "example.com:80"},
		"10.0.0.1:8080:example.com:80": {Listen: "10.0.0.1:8080", Target: "example.com:80"},
		"0:localhost:22":               {Listen: "127.0.0.1:0", Target: "localhost:22"},
	}
	for spec, want := range good {
		got, err := ParseForward(spec)
		if err != nil || got != want {
			t.Errorf("ParseForward(%q) = %+v, %v; want %+v", spec, got, err, want)
		}
	}

	for _, spec := range []string{"", "abc", "70000", "a:b:c:d:e", "8080::80", "8080:host:x"} {
		if _, err := ParseForward(spec); err == nil {
			t.Errorf("ParseForward(%q) succeeded, want error", spec)
		}
	}
}
