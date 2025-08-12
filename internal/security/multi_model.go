// Package security provides multi-model consensus for AI security
package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// ModelProvider represents different AI model providers
type ModelProvider string

const (
	ModelGemini  ModelProvider = "gemini"
	ModelClaude  ModelProvider = "claude"  // Future support
	ModelOpenAI  ModelProvider = "openai"  // Future support
)

// ModelAnalysis represents analysis from a single model
type ModelAnalysis struct {
	Provider          ModelProvider
	AltersBehavior    bool
	Category          string
	Risky             bool
	PossiblyMalicious bool
	Confidence        float64
	Reason            string
	RawResponse       string
}

// ConsensusResult represents the combined analysis from multiple models
type ConsensusResult struct {
	Consensus         bool     // Do models agree?
	AltersBehavior    bool     // Consensus decision
	Category          string   // Most common category
	Risky             bool     // Any model thinks it's risky
	PossiblyMalicious bool     // Any model thinks it's malicious
	ConfidenceScore   float64  // Average confidence
	Disagreements     []string // List of disagreements
	ModelCount        int      // Number of models used
}

// MultiModelAnalyzer provides consensus-based AI analysis
type MultiModelAnalyzer struct {
	models        []ModelProvider
	threshold     float64 // Agreement threshold (e.g., 0.66 for 2/3)
	strictMode    bool    // Require unanimous agreement for approval
	enableLogging bool
}

// NewMultiModelAnalyzer creates a new multi-model analyzer
func NewMultiModelAnalyzer(models []ModelProvider, threshold float64, strictMode bool) *MultiModelAnalyzer {
	if threshold <= 0 || threshold > 1 {
		threshold = 0.66 // Default to 2/3 agreement
	}

	return &MultiModelAnalyzer{
		models:        models,
		threshold:     threshold,
		strictMode:    strictMode,
		enableLogging: true,
	}
}

// AnalyzeWithConsensus performs analysis using multiple models and returns consensus
func (m *MultiModelAnalyzer) AnalyzeWithConsensus(ctx context.Context, analyses []ModelAnalysis) (*ConsensusResult, error) {
	if len(analyses) == 0 {
		return nil, fmt.Errorf("no model analyses provided")
	}

	result := &ConsensusResult{
		ModelCount: len(analyses),
	}

	// Check for unanimous red flags (any model detecting malicious intent)
	for _, analysis := range analyses {
		if analysis.PossiblyMalicious {
			result.PossiblyMalicious = true
			result.Risky = true
			if m.enableLogging {
				log.Printf("[MULTI-MODEL] Model %s detected possible malicious intent", analysis.Provider)
			}
		}
		if analysis.Risky {
			result.Risky = true
		}
	}

	// Calculate consensus on behavior alteration
	altersBehaviorVotes := 0
	for _, analysis := range analyses {
		if analysis.AltersBehavior {
			altersBehaviorVotes++
		}
	}

	agreementRatio := float64(altersBehaviorVotes) / float64(len(analyses))
	
	// In strict mode, any model saying it alters behavior means rejection
	if m.strictMode {
		result.AltersBehavior = altersBehaviorVotes > 0
		result.Consensus = altersBehaviorVotes == 0 || altersBehaviorVotes == len(analyses)
	} else {
		// Use threshold for consensus
		result.AltersBehavior = agreementRatio >= m.threshold
		result.Consensus = agreementRatio >= m.threshold || agreementRatio <= (1-m.threshold)
	}

	// Determine most common category
	result.Category = m.getMostCommonCategory(analyses)

	// Calculate average confidence
	totalConfidence := 0.0
	for _, analysis := range analyses {
		totalConfidence += analysis.Confidence
	}
	result.ConfidenceScore = totalConfidence / float64(len(analyses))

	// Identify disagreements
	result.Disagreements = m.findDisagreements(analyses)

	if m.enableLogging {
		log.Printf("[MULTI-MODEL] Consensus: %v, AltersBehavior: %v (votes: %d/%d), Category: %s, Confidence: %.2f",
			result.Consensus, result.AltersBehavior, altersBehaviorVotes, len(analyses),
			result.Category, result.ConfidenceScore)
	}

	return result, nil
}

// getMostCommonCategory finds the most common category among analyses
func (m *MultiModelAnalyzer) getMostCommonCategory(analyses []ModelAnalysis) string {
	categoryCount := make(map[string]int)
	for _, analysis := range analyses {
		if analysis.Category != "" {
			categoryCount[analysis.Category]++
		}
	}

	if len(categoryCount) == 0 {
		return "unknown"
	}

	// Find the most common category
	maxCount := 0
	mostCommon := ""
	for category, count := range categoryCount {
		if count > maxCount {
			maxCount = count
			mostCommon = category
		}
	}

	return mostCommon
}

// findDisagreements identifies where models disagree
func (m *MultiModelAnalyzer) findDisagreements(analyses []ModelAnalysis) []string {
	var disagreements []string

	// Check AltersBehavior disagreement
	altersBehaviorValues := make(map[bool][]ModelProvider)
	for _, analysis := range analyses {
		altersBehaviorValues[analysis.AltersBehavior] = append(
			altersBehaviorValues[analysis.AltersBehavior], analysis.Provider)
	}

	if len(altersBehaviorValues) > 1 {
		var providers []string
		for value, models := range altersBehaviorValues {
			modelNames := make([]string, len(models))
			for i, model := range models {
				modelNames[i] = string(model)
			}
			providers = append(providers, fmt.Sprintf("%v: %s", value, strings.Join(modelNames, ", ")))
		}
		disagreements = append(disagreements, 
			fmt.Sprintf("AltersBehavior disagreement - %s", strings.Join(providers, " vs ")))
	}

	// Check Category disagreement
	categoryValues := make(map[string][]ModelProvider)
	for _, analysis := range analyses {
		categoryValues[analysis.Category] = append(
			categoryValues[analysis.Category], analysis.Provider)
	}

	if len(categoryValues) > 1 {
		disagreements = append(disagreements,
			fmt.Sprintf("Category disagreement - %d different categories", len(categoryValues)))
	}

	// Check Risk assessment disagreement
	riskyValues := make(map[bool][]ModelProvider)
	for _, analysis := range analyses {
		riskyValues[analysis.Risky] = append(riskyValues[analysis.Risky], analysis.Provider)
	}

	if len(riskyValues) > 1 {
		disagreements = append(disagreements, "Risk assessment disagreement")
	}

	return disagreements
}

// AnomalyDetector detects anomalous patterns in model responses
type AnomalyDetector struct {
	responseHistory []ModelAnalysis
	maxHistory      int
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(maxHistory int) *AnomalyDetector {
	if maxHistory <= 0 {
		maxHistory = 100
	}
	return &AnomalyDetector{
		responseHistory: make([]ModelAnalysis, 0, maxHistory),
		maxHistory:      maxHistory,
	}
}

// DetectAnomaly checks if a response is anomalous compared to history
func (a *AnomalyDetector) DetectAnomaly(analysis ModelAnalysis) bool {
	// Check for sudden change in typical response patterns
	if len(a.responseHistory) < 10 {
		// Not enough history to detect anomalies
		a.addToHistory(analysis)
		return false
	}

	// Calculate historical patterns
	historicalApprovalRate := 0.0
	categoryDistribution := make(map[string]int)
	
	for _, historical := range a.responseHistory {
		if !historical.AltersBehavior {
			historicalApprovalRate++
		}
		categoryDistribution[historical.Category]++
	}
	historicalApprovalRate /= float64(len(a.responseHistory))

	// Check for anomalies
	anomalies := []string{}

	// 1. Check for unusual approval/rejection pattern
	if historicalApprovalRate > 0.7 && analysis.AltersBehavior {
		// Normally approves but now rejecting
		anomalies = append(anomalies, "Unusual rejection")
	} else if historicalApprovalRate < 0.3 && !analysis.AltersBehavior {
		// Normally rejects but now approving
		anomalies = append(anomalies, "Unusual approval")
	}

	// 2. Check for new category never seen before
	if _, exists := categoryDistribution[analysis.Category]; !exists && len(a.responseHistory) > 20 {
		anomalies = append(anomalies, fmt.Sprintf("New category: %s", analysis.Category))
	}

	// 3. Check for suspiciously low confidence
	if analysis.Confidence < 0.3 {
		anomalies = append(anomalies, "Very low confidence")
	}

	// 4. Check response structure anomalies
	if analysis.RawResponse != "" {
		if !strings.Contains(analysis.RawResponse, "{") || 
		   !strings.Contains(analysis.RawResponse, "}") {
			anomalies = append(anomalies, "Malformed response structure")
		}
	}

	a.addToHistory(analysis)

	if len(anomalies) > 0 {
		log.Printf("[ANOMALY] Detected anomalies in model response: %v", anomalies)
		return true
	}

	return false
}

// addToHistory adds an analysis to history with size limit
func (a *AnomalyDetector) addToHistory(analysis ModelAnalysis) {
	a.responseHistory = append(a.responseHistory, analysis)
	if len(a.responseHistory) > a.maxHistory {
		// Keep only the most recent entries
		a.responseHistory = a.responseHistory[len(a.responseHistory)-a.maxHistory:]
	}
}

// ResponseValidator validates AI model responses for security
type ResponseValidator struct {
	maxResponseSize int
	requiredFields  []string
}

// NewResponseValidator creates a new response validator
func NewResponseValidator() *ResponseValidator {
	return &ResponseValidator{
		maxResponseSize: 10000, // 10KB max response
		requiredFields: []string{
			"alters_behavior",
			"category",
			"reason",
		},
	}
}

// ValidateResponse validates an AI model response
func (v *ResponseValidator) ValidateResponse(response string) error {
	// Check response size
	if len(response) > v.maxResponseSize {
		return fmt.Errorf("response exceeds maximum size: %d > %d", 
			len(response), v.maxResponseSize)
	}

	// Check for empty response
	if strings.TrimSpace(response) == "" {
		return fmt.Errorf("empty response")
	}

	// Try to parse as JSON
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		// Check if response contains JSON somewhere
		jsonStart := strings.Index(response, "{")
		jsonEnd := strings.LastIndex(response, "}")
		
		if jsonStart >= 0 && jsonEnd > jsonStart {
			jsonStr := response[jsonStart : jsonEnd+1]
			if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
				return fmt.Errorf("invalid JSON in response: %w", err)
			}
		} else {
			return fmt.Errorf("no valid JSON found in response")
		}
	}

	// Validate required fields
	for _, field := range v.requiredFields {
		if _, exists := result[field]; !exists {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	// Check for suspicious additional fields
	suspiciousFields := []string{
		"override", "bypass", "force", "ignore_security",
		"always_approve", "skip_checks", "admin",
	}

	for _, suspicious := range suspiciousFields {
		if _, exists := result[suspicious]; exists {
			return fmt.Errorf("suspicious field detected: %s", suspicious)
		}
	}

	// Validate field types
	if altersBehavior, exists := result["alters_behavior"]; exists {
		if _, ok := altersBehavior.(bool); !ok {
			return fmt.Errorf("alters_behavior must be a boolean")
		}
	}

	if category, exists := result["category"]; exists {
		if categoryStr, ok := category.(string); ok {
			validCategories := []string{
				"typo", "comment", "markdown", "lint", "dependency",
				"config", "refactor", "bugfix", "feature", "other",
			}
			isValid := false
			for _, valid := range validCategories {
				if categoryStr == valid {
					isValid = true
					break
				}
			}
			if !isValid {
				return fmt.Errorf("invalid category: %s", categoryStr)
			}
		} else {
			return fmt.Errorf("category must be a string")
		}
	}

	return nil
}

// CalculateConfidence calculates confidence score based on response characteristics
func (v *ResponseValidator) CalculateConfidence(response string, analysis ModelAnalysis) float64 {
	confidence := 1.0

	// Reduce confidence for unclear reasoning
	if len(analysis.Reason) < 10 {
		confidence *= 0.8
	}

	// Reduce confidence for "other" category
	if analysis.Category == "other" {
		confidence *= 0.9
	}

	// Reduce confidence if response had to be extracted from text
	if !strings.HasPrefix(strings.TrimSpace(response), "{") {
		confidence *= 0.9
	}

	// Reduce confidence for contradictory signals
	if !analysis.AltersBehavior && (analysis.Risky || analysis.PossiblyMalicious) {
		confidence *= 0.7
	}

	return confidence
}