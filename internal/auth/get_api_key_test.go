package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   error
		wantErrIs bool // true when an error is expected
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "malformed: missing ApiKey prefix",
			headers:   http.Header{"Authorization": []string{"Bearer abc123"}},
			wantKey:   "",
			wantErrIs: true,
		},
		{
			name:      "malformed: only one field",
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:   "",
			wantErrIs: true,
		},
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}

			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("GetAPIKey() err = %v, want %v", err, tt.wantErr)
				}
			case tt.wantErrIs:
				if err == nil {
					t.Errorf("GetAPIKey() err = nil, want non-nil")
				}
			default:
				if err != nil {
					t.Errorf("GetAPIKey() err = %v, want nil", err)
				}
			}
		})
	}
}
