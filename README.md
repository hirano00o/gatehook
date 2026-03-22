# gatehook

A rule engine for Claude Code PreToolUse hooks.

## Overview

gatehook reads a PreToolUse hook payload from stdin, evaluates it against a set of rules, and writes a decision to stdout.

```
stdin (JSON)  →  rule evaluation  →  stdout (JSON)  |  no output (delegate)
```

- If a rule matches, gatehook writes `{"permissionDecision": "...", "permissionDecisionReason": "..."}` to stdout.
- If no rule matches, gatehook exits silently, delegating the decision to Claude Code's built-in permission system.
- Rules are evaluated in order; the first match wins.

**Supported tools and match targets:**

| Tool  | Match target         |
|-------|----------------------|
| Bash  | `tool_input.command` |
| Read  | `tool_input.file_path` |
| Edit  | `tool_input.file_path` |
| Write | `tool_input.file_path` |

## Installation

### go install

```sh
go install github.com/hirano00o/gatehook@latest
```

### go build

```sh
git clone https://github.com/hirano00o/gatehook.git
cd gatehook
go build -o gatehook .
sudo mv gatehook /usr/local/bin/
```

### Nix

```sh
nix profile install github:hirano00o/gatehook
```

## Usage

```sh
gatehook --config /path/to/rules.json
```

### Claude Code hooks configuration

Add the following to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "gatehook --config /path/to/rules.json"
          }
        ]
      }
    ]
  }
}
```

## Configuration

The rules file is a JSON object with a single `rules` array.

```json
{
  "rules": [
    {
      "tool":     "<tool name>",
      "pattern":  "<Go regexp>",
      "decision": "deny | ask",
      "reason":   "<message shown to the user>"
    }
  ]
}
```

| Field      | Type   | Description                                              |
|------------|--------|----------------------------------------------------------|
| `tool`     | string | Tool name to match: `Bash`, `Read`, `Edit`, or `Write`. |
| `pattern`  | string | Go regular expression matched against the target value.  |
| `decision` | string | `"deny"` to block the action, `"ask"` to prompt the user. |
| `reason`   | string | Message returned to Claude Code explaining the decision. |

## Example

```json
{
  "rules": [
    { "tool": "Bash",  "pattern": "\\bsed\\b",             "decision": "deny", "reason": "Use the Edit tool instead of sed" },
    { "tool": "Bash",  "pattern": "\\bawk\\b",             "decision": "deny", "reason": "Use the Edit tool instead of awk" },
    { "tool": "Bash",  "pattern": "(^|[|;&])\\s*/",        "decision": "deny", "reason": "Absolute path command execution is not allowed" },
    { "tool": "Bash",  "pattern": "\\bgit\\s+push\\b",     "decision": "deny", "reason": "git push is not allowed" },
    { "tool": "Bash",  "pattern": "\\bgit\\s+config\\b",   "decision": "ask",  "reason": "Attempting to run git config" },
    { "tool": "Read",  "pattern": "\\.env",                "decision": "deny", "reason": "Reading .env files is not allowed" },
    { "tool": "Edit",  "pattern": "^/etc/",                "decision": "deny", "reason": "Editing system files is not allowed" },
    { "tool": "Write", "pattern": "\\.env",                "decision": "deny", "reason": "Writing to .env files is not allowed" }
  ]
}
```

## License

MIT
