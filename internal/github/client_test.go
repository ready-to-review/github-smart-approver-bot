package github

import (
	"testing"
)

func TestParsePullRequestURL(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantOwner  string
		wantRepo   string
		wantNumber int
		wantErr    bool
	}{
		{
			name:       "github url format",
			url:        "https://github.com/golang/go/pull/12345",
			wantOwner:  "golang",
			wantRepo:   "go",
			wantNumber: 12345,
		},
		{
			name:       "short format",
			url:        "golang/go#12345",
			wantOwner:  "golang",
			wantRepo:   "go",
			wantNumber: 12345,
		},
		{
			name:    "invalid github url",
			url:     "https://github.com/golang/go/issues/12345",
			wantErr: true,
		},
		{
			name:    "invalid short format",
			url:     "golang/go/12345",
			wantErr: true,
		},
		{
			name:    "empty url",
			url:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, number, err := ParsePullRequestURL(tt.url)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePullRequestURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if owner != tt.wantOwner {
					t.Errorf("ParsePullRequestURL() owner = %v, want %v", owner, tt.wantOwner)
				}
				if repo != tt.wantRepo {
					t.Errorf("ParsePullRequestURL() repo = %v, want %v", repo, tt.wantRepo)
				}
				if number != tt.wantNumber {
					t.Errorf("ParsePullRequestURL() number = %v, want %v", number, tt.wantNumber)
				}
			}
		})
	}
}
