package gemini

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ModelConfig represents configuration for a specific model
type ModelConfig struct {
	Name              string
	Priority          int     // Lower number = higher priority (1 = primary, 2 = secondary)
	RequiredConfidence float64 // Minimum confidence required from this model
}

// MultiModelClient coordinates analysis across multiple Gemini models
type MultiModelClient struct {
	models        map[string]*Client
	configs       []ModelConfig
	debug         bool
	consensusMode bool // Require consensus between models
	minModels     int  // Minimum number of models that must agree
}

// ConsensusResult represents the combined result from multiple models
type ConsensusResult struct {
	Approved       bool
	AltersBehavior bool
	Category       string
	Confidence     float64
	Reason         string
	ModelResults   map[string]*AnalysisResult
	Agreement      bool
	ModelsUsed     int
}

// NewMultiModelClient creates a client that uses multiple models
func NewMultiModelClient(ctx context.Context, configs []ModelConfig, debug bool) (*MultiModelClient, error) {
	if len(configs) == 0 {
		return nil, fmt.Errorf("at least one model config is required")
	}

	models := make(map[string]*Client)
	for _, config := range configs {
		client, err := NewClient(ctx, config.Name, debug)
		if err != nil {
			return nil, fmt.Errorf("failed to create client for model %s: %w", config.Name, err)
		}
		models[config.Name] = client
	}

	return &MultiModelClient{
		models:        models,
		configs:       configs,
		debug:         debug,
		consensusMode: true,
		minModels:     2, // Require at least 2 models to agree
	}, nil
}

// AnalyzeWithConsensus performs analysis using multiple models and returns consensus
func (m *MultiModelClient) AnalyzeWithConsensus(ctx context.Context, prompt string) (*ConsensusResult, error) {
	// Input validation
	if prompt == "" {
		return nil, fmt.Errorf("prompt cannot be empty")
	}
	
	// Limit prompt size to prevent abuse
	const maxPromptSize = 50000
	if len(prompt) > maxPromptSize {
		return nil, fmt.Errorf("prompt exceeds maximum size of %d characters", maxPromptSize)
	}
	
	if len(m.configs) < m.minModels {
		return nil, fmt.Errorf("need at least %d models for consensus, have %d", m.minModels, len(m.configs))
	}

	// Run analysis with all models in parallel
	type modelResult struct {
		config ModelConfig
		result *AnalysisResult
		err    error
	}

	resultChan := make(chan modelResult, len(m.configs))
	var wg sync.WaitGroup

	for _, config := range m.configs {
		wg.Add(1)
		go func(cfg ModelConfig) {
			defer wg.Done()
			
			client, exists := m.models[cfg.Name]
			if !exists {
				resultChan <- modelResult{
					config: cfg,
					err:    fmt.Errorf("model %s not found", cfg.Name),
				}
				return
			}

			// Add timeout for each model
			modelCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			if m.debug {
				log.Printf("[MULTI-MODEL] Analyzing with %s (priority %d)", cfg.Name, cfg.Priority)
			}

			// For simplicity, analyze the prompt as a single text
			// In a real implementation, we would parse the prompt to extract file changes
			result, err := client.AnalyzeText(modelCtx, prompt)
			resultChan <- modelResult{
				config: cfg,
				result: result,
				err:    err,
			}
		}(config)
	}

	// Wait for all models to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	modelResults := make(map[string]*AnalysisResult)
	var errors []error
	successCount := 0

	for res := range resultChan {
		if res.err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", res.config.Name, res.err))
			if m.debug {
				log.Printf("[MULTI-MODEL] Error from %s: %v", res.config.Name, res.err)
			}
		} else {
			modelResults[res.config.Name] = res.result
			successCount++
			if m.debug {
				log.Printf("[MULTI-MODEL] Result from %s: AltersBehavior=%v, Confidence=%.2f",
					res.config.Name, res.result.AltersBehavior, res.result.Confidence)
			}
		}
	}

	// Check if we have enough successful results
	if successCount < m.minModels {
		return nil, fmt.Errorf("insufficient models succeeded: %d/%d (errors: %v)", 
			successCount, m.minModels, errors)
	}

	// Calculate consensus
	return m.calculateConsensus(modelResults)
}

// calculateConsensus determines if models agree on the analysis
func (m *MultiModelClient) calculateConsensus(results map[string]*AnalysisResult) (*ConsensusResult, error) {
	consensus := &ConsensusResult{
		ModelResults: results,
		ModelsUsed:   len(results),
	}

	// Count votes for altersBehavior
	altersBehaviorVotes := 0
	totalConfidence := 0.0
	categories := make(map[string]int)
	
	// Check each model's result against its required confidence
	highConfidenceCount := 0
	for modelName, result := range results {
		// Find the config for this model
		var config *ModelConfig
		for _, cfg := range m.configs {
			if cfg.Name == modelName {
				config = &cfg
				break
			}
		}
		
		if config == nil {
			continue
		}

		// Check if this model meets its confidence threshold
		if result.Confidence >= config.RequiredConfidence {
			highConfidenceCount++
			
			if result.AltersBehavior {
				altersBehaviorVotes++
			}
			
			// Track categories
			if result.Category != "" {
				categories[result.Category]++
			}
		} else if m.debug {
			log.Printf("[MULTI-MODEL] %s confidence %.2f below threshold %.2f",
				modelName, result.Confidence, config.RequiredConfidence)
		}
		
		totalConfidence += result.Confidence
	}

	// Need at least minModels with high confidence
	if highConfidenceCount < m.minModels {
		consensus.Agreement = false
		consensus.Approved = false
		consensus.Reason = fmt.Sprintf("Insufficient high-confidence results: %d/%d models",
			highConfidenceCount, m.minModels)
		return consensus, nil
	}

	// Calculate average confidence
	consensus.Confidence = totalConfidence / float64(len(results))

	// Determine if models agree (unanimous on altersBehavior for high-confidence models)
	if altersBehaviorVotes == 0 {
		// All high-confidence models agree it doesn't alter behavior
		consensus.Agreement = true
		consensus.AltersBehavior = false
		consensus.Approved = true
		consensus.Reason = "All models agree: change does not alter behavior"
	} else if altersBehaviorVotes == highConfidenceCount {
		// All high-confidence models agree it does alter behavior
		consensus.Agreement = true
		consensus.AltersBehavior = true
		consensus.Approved = false
		consensus.Reason = "All models agree: change alters behavior"
	} else {
		// Models disagree
		consensus.Agreement = false
		consensus.AltersBehavior = true // Conservative: if any model says it alters behavior
		consensus.Approved = false
		consensus.Reason = fmt.Sprintf("Models disagree: %d/%d say alters behavior",
			altersBehaviorVotes, highConfidenceCount)
	}

	// Find most common category
	maxCount := 0
	for cat, count := range categories {
		if count > maxCount {
			maxCount = count
			consensus.Category = cat
		}
	}

	if m.debug {
		log.Printf("[MULTI-MODEL] Consensus: Agreement=%v, Approved=%v, Confidence=%.2f, Reason=%s",
			consensus.Agreement, consensus.Approved, consensus.Confidence, consensus.Reason)
	}

	return consensus, nil
}

// Close closes all model clients
func (m *MultiModelClient) Close() error {
	for name, client := range m.models {
		if err := client.Close(); err != nil {
			log.Printf("[MULTI-MODEL] Error closing client %s: %v", name, err)
		}
	}
	return nil
}

// GetPrimaryClient returns the primary (highest priority) client
func (m *MultiModelClient) GetPrimaryClient() *Client {
	var primaryConfig *ModelConfig
	for _, config := range m.configs {
		if primaryConfig == nil || config.Priority < primaryConfig.Priority {
			primaryConfig = &config
		}
	}
	
	if primaryConfig != nil {
		return m.models[primaryConfig.Name]
	}
	return nil
}