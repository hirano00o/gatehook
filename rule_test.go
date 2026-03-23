package main

import (
	"encoding/json"
	"testing"
)

var testConfig = &Config{
	Rules: []Rule{
		{Tool: ToolNames{"Bash"}, Pattern: `\bsed\b`, Decision: "deny", Reason: "Use the Edit tool instead of sed"},
		{Tool: ToolNames{"Bash"}, Pattern: `\bawk\b`, Decision: "deny", Reason: "Use the Edit tool instead of awk"},
		{Tool: ToolNames{"Bash"}, Pattern: `(^|[|;&])\s*/`, Decision: "deny", Reason: "Absolute path command execution is not allowed"},
		{Tool: ToolNames{"Bash"}, Pattern: `\bgit\s+push\b`, Decision: "deny", Reason: "git push is not allowed"},
		{Tool: ToolNames{"Bash"}, Pattern: `\bgit\s+config\b`, Decision: "ask", Reason: "Attempting to run git config"},
		{Tool: ToolNames{"Read", "Edit", "Write"}, Pattern: `\.env`, Decision: "deny", Reason: ".env files are not allowed"},
		{Tool: ToolNames{"Edit"}, Pattern: `^/etc/`, Decision: "deny", Reason: "Editing system files is not allowed"},
	},
}

func TestToolNamesUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ToolNames
		wantErr bool
	}{
		{
			name:  "single string",
			input: `"Bash"`,
			want:  ToolNames{"Bash"},
		},
		{
			name:  "array of strings",
			input: `["Read", "Edit", "Write"]`,
			want:  ToolNames{"Read", "Edit", "Write"},
		},
		{
			name:    "invalid input",
			input:   `123`,
			wantErr: true,
		},
		{
			name:    "empty array",
			input:   `[]`,
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   `""`,
			wantErr: true,
		},
		{
			name:    "null",
			input:   `null`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ToolNames
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("index %d: expected %q, got %q", i, tt.want[i], got[i])
				}
			}
		})
	}
}

func TestToolNamesContains(t *testing.T) {
	names := ToolNames{"Read", "Edit", "Write"}
	for _, tool := range []string{"Read", "Edit", "Write"} {
		if !names.Contains(tool) {
			t.Errorf("expected Contains(%q) to be true", tool)
		}
	}
	if names.Contains("Bash") {
		t.Error("expected Contains(\"Bash\") to be false")
	}
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
		// Read: deny (.env) — matched by array rule ["Read","Edit","Write"]
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
		// Edit: deny (.env) — matched by array rule ["Read","Edit","Write"]
		{
			name:         "Edit .env",
			input:        &HookInput{ToolName: "Edit", ToolInput: ToolInput{FilePath: ".env"}},
			wantDecision: "deny",
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
		// Write: deny (.env) — matched by array rule ["Read","Edit","Write"]
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
		// Bash: not matched by array rule ["Read","Edit","Write"] → nil
		{
			name:    "Bash .env not matched by file rule",
			input:   &HookInput{ToolName: "Bash", ToolInput: ToolInput{Command: ".env"}},
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
			{Tool: ToolNames{"Bash"}, Pattern: `[invalid`, Decision: "deny", Reason: "invalid pattern"},
			{Tool: ToolNames{"Bash"}, Pattern: `\bls\b`, Decision: "deny", Reason: "ls matched"},
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
