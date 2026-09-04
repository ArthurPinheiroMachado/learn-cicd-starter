package auth

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input      http.Header
		wantKey    string
		wantErrMsg string
	}{
		"NoAuthHeader": {
			input:      http.Header{},
			wantKey:    "",
			wantErrMsg: ErrNoAuthHeaderIncluded.Error(),
		},
		"MalformedApiKeyPrefix": {
			input:      http.Header{"Authorization": []string{"Bearer abc123"}},
			wantKey:    "",
			wantErrMsg: "malformed authorization header",
		},
		"MissingKeyValue": {
			input:      http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:    "",
			wantErrMsg: "malformed authorization heder",
		},
		"ValidApiKey": {
			input:      http.Header{"Authorization": []string{"ApiKey abc123"}},
			wantKey:    "abc123",
			wantErrMsg: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)

			diffGot := cmp.Diff(tc.wantKey, got)

			var gotErrMsg string
			if err != nil {
				gotErrMsg = err.Error()
			}
			diffErr := cmp.Diff(tc.wantErrMsg, gotErrMsg)

			if diffGot != "" {
				t.Fatalf("%s", diffGot)
			}

			if diffErr != "" {
				t.Fatalf("%s", diffErr)
			}
		})
	}
}
