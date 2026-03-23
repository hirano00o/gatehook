package main

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
)

// HookInput represents the PreToolUse hook input from Claude Code.
type HookInput struct {
	ToolName  string    `json:"tool_name"`
	ToolInput ToolInput `json:"tool_input"`
}

// ToolInput represents the input parameters for a tool.
type ToolInput struct {
	Command  string `json:"command,omitempty"`   // Bash
	FilePath string `json:"file_path,omitempty"` // Read, Edit, Write
}

// ToolNames accepts a single string or an array of strings in JSON.
type ToolNames []string

func (t *ToolNames) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*t = ToolNames{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return fmt.Errorf("tool must be a string or array of strings")
	}
	*t = ToolNames(multi)
	return nil
}

// Contains reports whether name is in t.
func (t ToolNames) Contains(name string) bool {
	for _, n := range t {
		if n == name {
			return true
		}
	}
	return false
}

// Rule defines a matching rule.
type Rule struct {
	Tool     ToolNames `json:"tool"`     // "Bash" or ["Read", "Edit", "Write"]
	Pattern  string    `json:"pattern"`  // regexp
	Decision string    `json:"decision"` // "deny" | "ask"
	Reason   string    `json:"reason"`   // custom message
}

// Config represents the structure of a rules file.
type Config struct {
	Rules []Rule `json:"rules"`
}

// Result represents the hook output.
type Result struct {
	Decision string `json:"permissionDecision"`
	Reason   string `json:"permissionDecisionReason"`
}

// extractTarget returns the match target value based on the tool type.
func extractTarget(input *HookInput) string {
	switch input.ToolName {
	case "Bash":
		return input.ToolInput.Command
	case "Read", "Edit", "Write":
		return input.ToolInput.FilePath
	default:
		return ""
	}
}

// Evaluate evaluates rules in order and returns the result of the first match.
// Returns nil if no rule matches, delegating to the permissions system.
func (c *Config) Evaluate(input *HookInput) *Result {
	target := extractTarget(input)
	if target == "" {
		return nil
	}

	for _, rule := range c.Rules {
		if !rule.Tool.Contains(input.ToolName) {
			continue
		}
		matched, err := regexp.MatchString(rule.Pattern, target)
		if err != nil {
			// Skip invalid patterns to avoid breaking the entire hook
			log.Printf("invalid pattern %q: %v", rule.Pattern, err)
			continue
		}
		if matched {
			return &Result{Decision: rule.Decision, Reason: rule.Reason}
		}
	}

	return nil
}
