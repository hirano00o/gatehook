# gatehook

Claude Code の PreToolUse フック向けルールエンジン。

## 概要

gatehook は stdin から PreToolUse フックのペイロードを受け取り、ルールセットに照らして評価し、結果を stdout に書き出します。

```
stdin (JSON)  →  ルール評価  →  stdout (JSON)  |  無出力（委譲）
```

- ルールが一致した場合、`{"permissionDecision": "...", "permissionDecisionReason": "..."}` を stdout に出力します。
- 一致するルールがない場合、gatehook は何も出力せず終了し、Claude Code の組み込みパーミッションシステムに判断を委ねます。
- ルールは定義順に評価され、最初に一致したルールが採用されます。

**対応ツールとマッチ対象:**

| ツール | マッチ対象           |
|--------|----------------------|
| Bash   | `tool_input.command` |
| Read   | `tool_input.file_path` |
| Edit   | `tool_input.file_path` |
| Write  | `tool_input.file_path` |

## インストール

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

## 使い方

```sh
gatehook --config /path/to/rules.json
```

### Claude Code フック設定

`.claude/settings.json` に以下を追加します。

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

## 設定

ルールファイルは `rules` 配列を持つ JSON オブジェクトです。

```json
{
  "rules": [
    {
      "tool":     "<ツール名>",
      "pattern":  "<Go 正規表現>",
      "decision": "deny | ask",
      "reason":   "<ユーザーに表示するメッセージ>"
    }
  ]
}
```

| フィールド | 型     | 説明                                                     |
|------------|--------|----------------------------------------------------------|
| `tool`     | string | マッチ対象のツール名: `Bash`、`Read`、`Edit`、`Write`。  |
| `pattern`  | string | マッチ対象の値に適用する Go 正規表現。                    |
| `decision` | string | `"deny"` で操作をブロック、`"ask"` でユーザーに確認。    |
| `reason`   | string | Claude Code に返す理由メッセージ。                        |

## 設定例

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

## ライセンス

MIT
