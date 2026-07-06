# /rq - HTTP request & system-command router for Hermes Agent (zero-LLM)

```url
https://github.com/com4pro/hermes-plugin-rq
```

`rq` adds a **`/rq`** slash command (CLI + gateway: Telegram, WebUI…) that routes
`/rq <target> : <payload>` (one or more parameters) to an **HTTP endpoint** OR a
**system command** (exec via argv), declared in `rq-targets.yaml`, and returns the
**raw output - with no LLM call** (0 tokens, ~instant).

It's a config-driven launcher for HTTP requests / webhooks / system commands from
your chat.

## Why `/rq` exists

Hermes is great at reasoning and orchestration, but some chat actions do not need an LLM at all.

When the task is already well-defined - for example:

- querying an internal API,
- triggering a webhook,
- fetching a small operational fact,
- running a safe predefined command,

sending the request through the full model/tool loop adds avoidable latency, token cost, and rate-limit exposure.

`/rq` provides a **direct, deterministic, zero-LLM path** from chat to action.

It lets you stay in the same interface - **Hermes WebUI, Telegram, or another gateway channel** - while routing a short command such as:

```text
/rq kb : production server host
/rq weather : Paris | 3
```

to a predeclared HTTP target or system command and returning the raw result immediately.

## Typical use cases

`/rq` is a good fit for:

- **internal knowledge lookups**,
- **private API calls**,
- **webhook triggers**,
- **operational shortcuts**,
- **safe command wrappers**,
- **low-latency chat actions**.

## Benefits

- **Lower latency** - no LLM round-trip
- **No token usage on the execution path**
- **Deterministic behavior** - same input, same configured target
- **Reduced rate-limit pressure** on model providers
- **Better fit for simple, repeatable micro-actions**

## Real example: Qdrant lookup

In one real test, a simple local Qdrant lookup performed through the normal MCP + LLM path required:

- **7 LLM calls** with Claude, taking **more than 3 minutes** because the API key was limited to **5 calls/minute**
- **more than 37 seconds** with Codex
- **~80 ms** through `/rq`

That means `/rq` was approximately:

- **2,250.00× faster** than the 3-minute Claude-limited path
- **462.50× faster** than the 37-second Codex path

It also avoided a large amount of unnecessary token usage for a request that could be handled without reasoning.

## In short

Use the full Hermes agent when you need **reasoning, interpretation, or orchestration**.

Use `/rq` when you need **fast, cheap, deterministic chat-to-action routing**.

## Installation

The plugin is **self-contained**: it ships `rq-targets.example.yaml` and
`rq-i18n.yaml`. Your **active** targets live in `rq-targets.yaml`, which is
**git-ignored** (never published, never conflicts on `git pull`). If no
`rq-targets.yaml` exists, the plugin reads the example directly. A copy in
`~/.hermes/` overrides the plugin-dir one.

**Via git** (creates the plugins dir if missing):
```bash
mkdir -p ~/.hermes/plugins
git clone https://github.com/com4pro/hermes-plugin-rq ~/.hermes/plugins/rq
cp ~/.hermes/plugins/rq/rq-targets.example.yaml ~/.hermes/plugins/rq/rq-targets.yaml   # create your targets
hermes plugins enable rq
# restart Hermes (gateway + WebUI)
```

**Via zip**:
```bash
mkdir -p ~/.hermes/plugins
unzip hermes-plugin-rq.zip -d ~/.hermes/plugins/   # -> ~/.hermes/plugins/rq/
hermes plugins enable rq
# restart Hermes
```

Then edit targets with `/rq add …` (from chat) or by editing `rq-targets.yaml`
(copy it from `rq-targets.example.yaml`).

## Usage

```
/rq <target> : <payload>
/rq list                 # list targets
/rq show <target>        # show a target
/rq add <name> <GET|POST> <url> [p1 p2 …]   # add an HTTP target
/rq del <target>         # remove a target
/rq help
```

Examples:
```
/rq kb : production server host
/rq weather : Paris | 3
/rq gh : NousResearch | hermes-agent
/rq notify : Deployment finished
/rq dns : yourdomain.tld | A
/rq disk : /var                 # (exec type, requires allow_exec: true)
```

The bundled `rq-targets.yaml` is a **commented catalog** of ready-to-use templates
(knowledge base, n8n, Home Assistant, GitHub, Discord/Slack webhooks, weather, DNS,
plus exec examples) - each says what to customize.

## Target format (`rq-targets.yaml`)

```yaml
defaults: { timeout: 20, max_output: 3000, sep: "|" }
allow_exec: false
targets:
  <alias>:
    type: http | exec
    # HTTP:
    method: GET | POST
    url: "http://host/path/{param}"
    query:  { k: "{param}" }        # optional
    headers: { ... }                # optional
    send: query | json | form       # POST: json (default form)
    params: [a, b]
    trace_timing: false             # optional: emit precise timing logs for this target
    # EXEC:
    cmd: ["prog", "-x", "{param}"]  # argv - {param} = literal argument
```

**Payload parsing** (after `<target> :`): 1 param → whole payload; multiple →
positional `a | b` or named `k1=v1 | k2=v2`. A `{param}` is substituted; a param
not used as `{..}` is sent automatically (query for GET, JSON for POST).

**Secrets**: use `${VAR}` in `url`/`query`/`headers`/`body`/`cmd` to inject an
environment variable (put the value in `~/.hermes/.env`, e.g. `GITHUB_TOKEN=…`).
`${VAR}` expands from the environment only - never from the user payload - so
tokens never live in the targets file.

## Security

- **Access control is control #1**: whoever can type `/rq` can run every target.
  Restrict the surface via the gateway config (e.g. `TELEGRAM_ALLOWED_USERS`).
  `/rq add|del` edits the allowlist → admin only.
- **Allowlist**: only targets in the file exist.
- **Exec via argv** (`shell=False`): `{param}` is a **literal argument** → no shell
  injection (a payload `; rm -rf /` becomes an inert string).
  **Never** put `{param}` inside a `["sh","-c","… {param} …"]`. Templates end options
  with `--` so a value starting with `-` is not treated as a flag (argument injection).
- **`allow_exec: false`** by default: exec targets are inert.
- **SSRF hardening**: requests to **link-local / cloud-metadata** addresses
  (`169.254.0.0/16`, `fe80::/10` - AWS/GCP/Azure metadata) are blocked
  (`block_link_local: true`), and **HTTP redirects are refused**
  (`follow_redirects: false`, a redirect can bypass the host check). Set
  `deny_private: true` to also block RFC1918/loopback (note: breaks internal
  targets like `kb`); `deny_hosts: [...]` for an explicit hostname denylist.
- **Secrets** via `${VAR}` (from `~/.hermes/.env`), never from the payload; prefer
  headers over URLs so secrets never surface in error messages.
- Timeout + truncated output + scrubbed environment.

## Localization (i18n)

User-facing messages follow the active language read from `~/.hermes/config.yaml`
(key `language` - the same setting the WebUI exposes), falling back to
`rq-targets.yaml`'s `defaults.lang`, then English. Translations live in
`~/.hermes/rq-i18n.yaml`, one block per WebUI language code
(`en fr es de it pt ru pl tr vi ja ko zh zh-Hant`). English is built into the
plugin; any missing key falls back to English per key, and `zh-Hant` falls back
to `zh` - same model as the WebUI. Shipped translations: `fr es de it pt`
(others fall back to English until filled - copy the `fr` block and translate).

## Notes

- `/rq add` only creates **HTTP** targets; `exec` targets are added by editing the
  file (extra safeguard).
- Do not name a target with a reserved word: `list, help, add, del, remove, show`.
- Runtime: stdlib (`urllib`, `subprocess`) + `PyYAML` (provided by Hermes).