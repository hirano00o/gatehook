package main

import "testing"

var testConfig = &Config{
	Rules: []Rule{
		{Tool: "Bash", Pattern: `\bsed\b`, Decision: "deny", Reason: "Use the Edit tool instead of sed"},
		{Tool: "Bash", Pattern: `\bawk\b`, Decision: "deny", Reason: "Use the Edit tool instead of awk"},
		{Tool: "Bash", Pattern: `(^|[|;&])\s*/`, Decision: "deny", Reason: "Absolute path command execution is not allowed"},
		{Tool: "Bash", Pattern: `\bgit\s+push\b`, Decision: "deny", Reason: "git push is not allowed"},
		{Tool: "Bash", Pattern: `\bgit\s+config\b`, Decision: "ask", Reason: "Attempting to run git config"},
		{Tool: "Read", Pattern: `\.env`, Decision: "deny", Reason: "Reading .env files is not allowed"},
		{Tool: "Edit", Pattern: `^/etc/`, Decision: "deny", Reason: "Editing system files is not allowed"},
		{Tool: "Write", Pattern: `\.env`, Decision: "deny", Reason: "Writing to .env files is not allowed"},
	},
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name         string
		input        *HookInput
		wantNil      bool
		wantDecision string
	}{
		// Bash: deny (sed in pipeline)
		{
			name:         "Bash sed in pipeline",
			input:        &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "cat foo | sed s/a/b/"}},
			wantDecision: "deny",
		},
		// Bash: deny (standalone awk)
		{
			name:         "Bash awk",
			input:        &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "awk '{print $1}' file"}},
			wantDecision: "deny",
		},
		// Bash: deny (absolute path command)
		{
			name:         "Bash absolute path",
			input:        &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "/usr/bin/curl https://example.com"}},
			wantDecision: "deny",
		},
		// Bash: deny (absolute path after pipe)
		{
			name:         "Bash absolute path after pipe",
			input:        &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "cat file | /bin/grep foo"}},
			wantDecision: "deny",
		},
		// Bash: deny (git push)
		{
			name:         "Bash git push",
			input:        &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "git push origin main"}},
			wantDecision: "deny",
		},
		// Bash: ask (git config)
		{
			name:         "Bash git config ask",
			input:        &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "git config user.email"}},
			wantDecision: "ask",
		},
		// Bash: no match → nil
		{
			name:    "Bash npm install unmatched",
			input:   &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "npm install"}},
			wantNil: true,
		},
		// Bash: empty command → nil
		{
			name:    "Bash empty command",
			input:   &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: ""}},
			wantNil: true,
		},
		// Read: deny (.env)
		{
			name:         "Read .env.local",
			input:        &HookInput{ToolName: "Read", ToolInput: ToolInput{FilePath: ".env.local"}},
			wantDecision: "deny",
		},
		// Read: deny (.env exact)
		{
			name:         "Read .env",
			input:        &HookInput{ToolName: "Read", ToolInput: ToolInput{FilePath: ".env"}},
			wantDecision: "deny",
		},
		// Read: no match → nil
		{
			name:    "Read config.yaml unmatched",
			input:   &HookInput{ToolName: "Read", ToolInput: ToolInput{FilePath: "/home/user/config.yaml"}},
			wantNil: true,
		},
		// Read: empty path → nil
		{
			name:    "Read empty path",
			input:   &HookInput{ToolName: "Read", ToolInput: ToolInput{FilePath: ""}},
			wantNil: true,
		},
		// Edit: deny (/etc/)
		{
			name:         "Edit /etc/hosts",
			input:        &HookInput{ToolName: "Edit", ToolInput: ToolInput{FilePath: "/etc/hosts"}},
			wantDecision: "deny",
		},
		// Edit: no match → nil
		{
			name:    "Edit project file unmatched",
			input:   &HookInput{ToolName: "Edit", ToolInput: ToolInput{FilePath: "/home/user/project/main.go"}},
			wantNil: true,
		},
		// Write: deny (.env)
		{
			name:         "Write .env",
			input:        &HookInput{ToolName: "Write", ToolInput: ToolInput{FilePath: ".env"}},
			wantDecision: "deny",
		},
		// Write: no match → nil
		{
			name:    "Write main.go unmatched",
			input:   &HookInput{ToolName: "Write", ToolInput: ToolInput{FilePath: "main.go"}},
			wantNil: true,
		},
		// Unknown tool → nil (extractTarget returns "")
		{
			name:    "Unknown tool List",
			input:   &HookInput{ToolName: "List", ToolInput: ToolInput{}},
			wantNil: true,
		},
		// Rule ordering: first match wins
		{
			name:         "First match wins sed over awk",
			input:        &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "sed 's/a/b/' | awk '{print}'"}},
			wantDecision: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := testConfig.Evaluate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Error("expected non-nil result, got nil")
				return
			}
			if result.Decision != tt.wantDecision {
				t.Errorf("expected decision %q, got %q", tt.wantDecision, result.Decision)
			}
		})
	}
}

func TestEvaluateInvalidPattern(t *testing.T) {
	cfg := &Config{
		Rules: []Rule{
			// Invalid patterns are skipped and subsequent valid rules are evaluated
			{Tool: "Bash", Pattern: `[invalid`, Decision: "deny", Reason: "invalid pattern"},
			{Tool: "Bash", Pattern: `\bls\b`, Decision: "deny", Reason: "ls matched"},
		},
	}
	input := &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: "ls -la"}}
	result := cfg.Evaluate(input)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Decision != "deny" {
		t.Errorf("expected deny, got %s", result.Decision)
	}
	if result.Reason != "ls matched" {
		t.Errorf("expected reason %q, got %q", "ls matched", result.Reason)
	}
}
