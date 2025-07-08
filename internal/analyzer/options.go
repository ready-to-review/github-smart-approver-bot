package analyzer

import (
	"github.com/thegroove/trivial-auto-approve/internal/gemini"
	githubAPI "github.com/thegroove/trivial-auto-approve/internal/github"
)

// Option configures an Analyzer.
type Option func(*Config)

// WithMaxFiles sets the maximum number of files for auto-approval.
func WithMaxFiles(n int) Option {
	return func(c *Config) {
		c.MaxFiles = n
	}
}

// WithSkipFirstTime configures whether to skip first-time contributors.
func WithSkipFirstTime(skip bool) Option {
	return func(c *Config) {
		c.SkipFirstTime = skip
	}
}

// WithDryRun enables dry-run mode.
func WithDryRun(dryRun bool) Option {
	return func(c *Config) {
		c.DryRun = dryRun
	}
}

// WithGemini configures whether to use Gemini AI analysis.
func WithGemini(use bool) Option {
	return func(c *Config) {
		c.UseGemini = use
	}
}

// NewWithOptions creates a new analyzer with the provided options.
func NewWithOptions(gh githubAPI.API, gemini gemini.API, opts ...Option) (*Analyzer, error) {
	config := DefaultConfig()
	for _, opt := range opts {
		opt(config)
	}
	return New(gh, gemini, config)
}
