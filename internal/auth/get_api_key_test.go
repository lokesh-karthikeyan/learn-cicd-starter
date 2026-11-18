package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantErr    error
		wantAnyErr bool
	}{
		{
			name:       "valid api key",
			authHeader: "ApiKey 12345",
			wantKey:    "54321",
		},
		{
			name:    "missing authorization header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "wrong scheme",
			authHeader: "Bearer 12345",
			wantAnyErr: true,
		},
		{
			name:       "no key after scheme",
			authHeader: "ApiKey",
			wantAnyErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			got, err := GetAPIKey(headers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if tt.wantAnyErr {
				if err == nil {
					t.Fatalf("expected an error, got key %q", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, got)
			}
		})
	}
}
