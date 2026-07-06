"""rq - zero-LLM command router for Hermes (HTTP + exec), config-driven, i18n.

Registers the ``/rq`` slash command, available in the CLI AND on the gateway
(Telegram, WebUI...). It routes ``/rq <target> : <payload>`` to an HTTP endpoint
or a shell command (exec via argv) declared in ``~/.hermes/rq-targets.yaml``, and
returns the raw output - **without ever going through the LLM**.

Localization: user-facing messages follow the active language read from
``~/.hermes/config.yaml`` (key ``language`` - the same setting the WebUI exposes),
falling back to ``rq-targets.yaml``'s ``defaults.lang`` then English. Translations
live in ``~/.hermes/rq-i18n.yaml`` (one block per WebUI language code); any missing
key falls back to English per key (same model as the WebUI).

Security:
- allowlist: only targets present in the file exist;
- exec disabled by default (``allow_exec: false``);
- execution via **argv** (``shell=False``) -> no shell injection possible;
- timeout + truncated output;
- the surface (who can type /rq) is restricted by the gateway config
  (e.g. ``TELEGRAM_ALLOWED_USERS``).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ${VAR} in a target (url/query/headers/body/cmd) expands from the process
# environment (e.g. secrets from ~/.hermes/.env) - never from the user payload.
_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_LOG = logging.getLogger(__name__)


def _trace_enabled(target: dict, defaults: dict) -> bool:
    return bool(target.get("trace_timing", defaults.get("trace_timing", False)))


def _trace_start(target_name: str, target: dict, payload: str, defaults: dict) -> dict:
    now_ns = time.perf_counter_ns()
    return {
        "enabled": _trace_enabled(target, defaults),
        "target": target_name,
        "type": (target.get("type") or "http").lower(),
        "payload_len": len(payload or ""),
        "start_ns": now_ns,
        "last_ns": now_ns,
    }


def _trace_mark(trace: dict | None, stage: str, **fields) -> None:
    if not trace or not trace.get("enabled"):
        return
    now_ns = time.perf_counter_ns()
    elapsed_ms = (now_ns - trace["start_ns"]) / 1_000_000
    delta_ms = (now_ns - trace["last_ns"]) / 1_000_000
    trace["last_ns"] = now_ns
    wall_ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    extras = " ".join(
        f"{k}={json.dumps(v, ensure_ascii=False, sort_keys=True)}"
        for k, v in sorted(fields.items())
    )
    suffix = f" {extras}" if extras else ""
    _LOG.info(
        "rq.trace ts=%s elapsed_ms=%.3f delta_ms=%.3f stage=%s target=%s type=%s payload_len=%d%s",
        wall_ts,
        elapsed_ms,
        delta_ms,
        stage,
        trace["target"],
        trace["type"],
        trace["payload_len"],
        suffix,
    )


def _expand_env(s: str) -> str:
    return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), s)


# -- SSRF hardening ---------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse HTTP redirects (a redirect can bypass the URL host check)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)
_REDIRECT_CODES = {301, 302, 303, 307, 308}


def _http_open(req, timeout, defaults):
    if defaults.get("follow_redirects"):
        return urllib.request.urlopen(req, timeout=timeout)
    return _NO_REDIRECT_OPENER.open(req, timeout=timeout)


def _url_blocked(url: str, defaults: dict):
    """Return an error string if the URL host is denied, else None.

    Blocks link-local / cloud-metadata addresses (169.254.0.0/16, fe80::/10 -
    covers AWS/GCP/Azure metadata) by default. Optionally denies private/loopback
    (`deny_private: true`) and specific hostnames (`deny_hosts: [...]`). Internal
    RFC1918 hosts stay reachable by default (needed for internal service targets).
    """
    host = urllib.parse.urlparse(url).hostname
    if not host:
        return _t("url_invalid")
    if host in set(defaults.get("deny_hosts") or []):
        return _t("host_denied", host)
    block_ll = defaults.get("block_link_local", True)
    deny_private = bool(defaults.get("deny_private", False))
    if not block_ll and not deny_private:
        return None
    candidates = set()
    try:
        candidates.add(str(ipaddress.ip_address(host)))  # host is an IP literal
    except ValueError:
        try:
            for info in socket.getaddrinfo(host, None):
                candidates.add(info[4][0])
        except Exception:
            return None  # unresolved: let the request fail normally
    for cand in candidates:
        try:
            ip = ipaddress.ip_address(cand.split("%")[0])
        except ValueError:
            continue
        if block_ll and ip.is_link_local:
            return _t("blocked_linklocal", ip)
        if deny_private and (ip.is_private or ip.is_loopback):
            return _t("blocked_private", ip)
    return None

try:
    import yaml  # provided by Hermes (config.yaml parsing)
except Exception:  # pragma: no cover
    yaml = None

# Words reserved for management subcommands (do not name a target like these).
RESERVED = {"list", "help", "add", "del", "remove", "show"}

# Built-in English strings (guaranteed default; rq-i18n.yaml overrides per locale).
_EN = {
    "help": (
        "rq - HTTP request & system-command router (one or more parameters).\n\n"
        "Usage: /rq <target> : <payload>\n"
        "  /rq list                        - list targets\n"
        "  /rq show <target>               - show a target\n"
        "  /rq add <name> <GET|POST> <url> [p1 p2 …]   - add an HTTP target\n"
        "  /rq del <target>                - remove a target\n"
        "  /rq help                        - this help\n"
        "Examples: /rq kb : prod host   |   /rq weather : Paris | 3"
    ),
    "expect_one": "this target expects 1 parameter: %s",
    "missing": "missing parameter(s): %s (expected: %s)",
    "yaml_unavailable": "PyYAML unavailable in the runtime.",
    "unreadable": "rq-targets.yaml unreadable: %s",
    "net_error": "network error: %s",
    "url_invalid": "invalid target URL.",
    "host_denied": "host denied by policy: %s",
    "blocked_linklocal": "blocked link-local/metadata address (%s).",
    "blocked_private": "blocked private/loopback address (%s).",
    "redirect_blocked": "redirect blocked (HTTP %s) - set follow_redirects: true to allow.",
    "exec_disabled": "exec disabled - set 'allow_exec: true' in rq-targets.yaml.",
    "exec_invalid": "invalid exec target: 'cmd' must be a list (argv), e.g. [\"df\",\"-h\",\"{path}\"].",
    "cmd_timeout": "command timed out (%ss).",
    "cmd_notfound": "command not found: %s",
    "exec_error": "exec error: %s",
    "no_output": "(no output, exit %s)",
    "truncated": "\n… [truncated at %d chars]",
    "no_targets": "no targets. Add one: /rq add <name> <GET|POST> <url> [params]",
    "targets_header": "Targets:",
    "usage_show": "Usage: /rq show <target>",
    "unknown_target_mgmt": "unknown target: %s",
    "usage_add": "Usage: /rq add <name> <GET|POST> <url> [p1 p2 …]  (HTTP only)",
    "method_invalid": "method must be GET or POST.",
    "target_added": "target '%s' added (HTTP %s, params: %s).",
    "write_failed": "write failed: %s",
    "usage_del": "Usage: /rq del <target>",
    "target_removed": "target '%s' removed.",
    "unknown_target": "unknown target: '%s'. Available: %s",
}

_DEFAULT_LANG = "en"
_I18N_CACHE = None


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
_PLUGIN_DIR = Path(__file__).resolve().parent


def _home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))


def _resolve(name: str) -> Path:
    """Prefer ~/.hermes/<name> (user override), else the plugin's own dir.

    Lets a git-clone / zip install ship rq-targets.yaml + rq-i18n.yaml inside the
    plugin directory and work out of the box, while still honoring a per-user
    override placed in ~/.hermes/.
    """
    for base in (_home(), _PLUGIN_DIR):
        p = base / name
        if p.exists():
            return p
    return _home() / name  # default write target when nothing exists yet


def _targets_read_path() -> Path:
    """Active targets file if present, else the shipped example (read-only)."""
    for base in (_home(), _PLUGIN_DIR):
        p = base / "rq-targets.yaml"
        if p.exists():
            return p
    example = _PLUGIN_DIR / "rq-targets.example.yaml"
    if example.exists():
        return example
    return _home() / "rq-targets.yaml"


def _targets_write_path() -> Path:
    """Where /rq add|del persists - an existing rq-targets.yaml, else ~/.hermes/.
    Never the shipped example (so `git pull` never conflicts with user targets)."""
    for base in (_home(), _PLUGIN_DIR):
        p = base / "rq-targets.yaml"
        if p.exists():
            return p
    return _home() / "rq-targets.yaml"


def _i18n_path() -> Path:
    return _resolve("rq-i18n.yaml")


def _read_yaml(path: Path) -> dict:
    if not path.exists() or yaml is None:
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# i18n
# --------------------------------------------------------------------------- #
def _active_lang() -> str:
    """Active language: config.yaml 'language' -> rq-targets defaults.lang -> en."""
    lang = (_read_yaml(_home() / "config.yaml").get("language") or "").strip()
    if not lang:
        lang = ((_load_cfg().get("defaults") or {}).get("lang") or "").strip()
    return lang or _DEFAULT_LANG


def _i18n() -> dict:
    global _I18N_CACHE
    if _I18N_CACHE is None:
        _I18N_CACHE = _read_yaml(_i18n_path())
    return _I18N_CACHE


def _t(key: str, *args) -> str:
    """Localized message with per-key English fallback (and zh-Hant -> zh)."""
    lang = _active_lang()
    table = _i18n()
    msg = (table.get(lang) or {}).get(key)
    if msg is None and "-" in lang:
        msg = (table.get(lang.split("-")[0]) or {}).get(key)
    if msg is None:
        msg = _EN.get(key, key)
    try:
        return msg % args if args else msg
    except Exception:
        return msg


# --------------------------------------------------------------------------- #
# Targets file
# --------------------------------------------------------------------------- #
def _load_cfg() -> dict:
    p = _targets_read_path()
    if not p.exists():
        return {"defaults": {}, "targets": {}, "allow_exec": False}
    if yaml is None:
        return {"_error": _EN["yaml_unavailable"]}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as e:
        return {"_error": _t("unreadable", e)}
    data.setdefault("defaults", {})
    data.setdefault("targets", {})
    data.setdefault("allow_exec", False)
    return data


def _save_cfg(data: dict) -> None:
    if yaml is None:
        raise RuntimeError("PyYAML unavailable")
    _targets_write_path().write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )


# --------------------------------------------------------------------------- #
# Payload parsing -> parameter values
# --------------------------------------------------------------------------- #
def _parse_params(payload: str, params: list, sep: str):
    """Return (dict param->value, error_message|None)."""
    payload = (payload or "").strip()
    if not params:
        return {}, None
    if len(params) == 1 and "=" not in payload.split(sep, 1)[0]:
        if not payload:
            return {}, _t("expect_one", params[0])
        return {params[0]: payload}, None

    segments = [s.strip() for s in payload.split(sep)] if payload else []
    values: dict = {}
    named = bool(segments) and all("=" in s for s in segments if s)
    if named:
        for s in segments:
            if not s:
                continue
            k, v = s.split("=", 1)
            values[k.strip()] = v.strip()
    else:
        for name, seg in zip(params, segments):
            values[name] = seg
    missing = [p for p in params if not values.get(p)]
    if missing:
        return values, _t("missing", ", ".join(missing), ", ".join(params))
    return values, None


def _subst(obj, values: dict, used: set):
    """Substitute {param} recursively (str/dict/list) and record used keys."""
    if isinstance(obj, str):
        out = obj
        for k, v in values.items():
            token = "{" + k + "}"
            if token in out:
                out = out.replace(token, str(v))
                used.add(k)
        return _expand_env(out)  # ${VAR} -> environment (secrets from ~/.hermes/.env)
    if isinstance(obj, dict):
        return {k: _subst(v, values, used) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_subst(v, values, used) for v in obj]
    return obj


# --------------------------------------------------------------------------- #
# Executors
# --------------------------------------------------------------------------- #
def _run_http(target: dict, values: dict, defaults: dict, trace: dict | None = None) -> str:
    used: set = set()
    _trace_mark(trace, "http_prepare_start", value_keys=sorted(values))
    url = _subst(target.get("url", ""), values, used)
    blocked = _url_blocked(url, defaults)
    if blocked:
        _trace_mark(trace, "http_blocked", reason=blocked)
        return blocked
    method = (target.get("method") or "GET").upper()
    query = _subst(dict(target.get("query") or {}), values, used)
    headers = _subst(dict(target.get("headers") or {}), values, used)
    send = (target.get("send") or "query").lower()
    timeout = int(target.get("timeout") or defaults.get("timeout") or 20)

    extra = {k: v for k, v in values.items() if k not in used}

    body = None
    query_keys = []
    if method == "GET":
        q = dict(query)
        q.update(extra)
        query_keys = sorted(q)
        if q:
            url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(q)
    elif send == "json":
        payload = _subst(dict(target.get("body") or {}), values, used)
        payload.update(extra)
        body = json.dumps(payload).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    else:  # form
        form = dict(query)
        form.update(extra)
        body = urllib.parse.urlencode(form).encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    parsed = urllib.parse.urlparse(url)
    _trace_mark(
        trace,
        "http_request_ready",
        method=method,
        host=parsed.hostname,
        path=parsed.path,
        query_keys=query_keys,
        header_count=len(headers),
        body_bytes=len(body or b""),
        timeout=timeout,
    )
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        _trace_mark(trace, "http_open_start")
        with _http_open(req, timeout, defaults) as resp:
            first = resp.read(1)
            _trace_mark(trace, "http_first_byte", status=getattr(resp, "status", None))
            rest = resp.read()
            body_bytes = len(first) + len(rest)
            _trace_mark(trace, "http_body_done", response_bytes=body_bytes)
            return (first + rest).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code in _REDIRECT_CODES:
            _trace_mark(trace, "http_redirect_blocked", status=e.code)
            return _t("redirect_blocked", e.code)
        detail = e.read().decode("utf-8", "replace")[:500]
        _trace_mark(trace, "http_error", status=e.code, detail_len=len(detail))
        return "HTTP %s: %s" % (e.code, detail)
    except Exception as e:
        _trace_mark(trace, "http_exception", error=str(e))
        return _t("net_error", e)


def _run_exec(target: dict, values: dict, defaults: dict, allow_exec: bool, trace: dict | None = None) -> str:
    if not allow_exec:
        _trace_mark(trace, "exec_disabled")
        return _t("exec_disabled")
    cmd = target.get("cmd")
    if not isinstance(cmd, list) or not cmd:
        _trace_mark(trace, "exec_invalid")
        return _t("exec_invalid")
    used: set = set()
    argv = [str(_subst(x, values, used)) for x in cmd]  # {param} = literal argument
    timeout = int(target.get("timeout") or defaults.get("timeout") or 20)
    _trace_mark(trace, "exec_start", argv0=argv[0], argc=len(argv), timeout=timeout)
    try:
        r = subprocess.run(
            argv, shell=False, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        _trace_mark(trace, "exec_timeout", timeout=timeout)
        return _t("cmd_timeout", timeout)
    except FileNotFoundError:
        _trace_mark(trace, "exec_notfound", argv0=argv[0])
        return _t("cmd_notfound", argv[0])
    except Exception as e:
        _trace_mark(trace, "exec_exception", error=str(e))
        return _t("exec_error", e)
    out = (r.stdout or "").strip() or (r.stderr or "").strip()
    _trace_mark(
        trace,
        "exec_done",
        returncode=r.returncode,
        stdout_len=len(r.stdout or ""),
        stderr_len=len(r.stderr or ""),
        output_len=len(out),
    )
    return out or _t("no_output", r.returncode)


def _truncate(text: str, defaults: dict) -> str:
    m = int(defaults.get("max_output") or 3000)
    text = text or ""
    if len(text) > m:
        return text[:m] + (_t("truncated", m))
    return text


# --------------------------------------------------------------------------- #
# Management subcommands
# --------------------------------------------------------------------------- #
def _manage(sub: str, raw: str, cfg: dict, targets: dict) -> str:
    parts = raw.split()
    if sub == "list":
        if not targets:
            return _t("no_targets")
        lines = [_t("targets_header")]
        for n, t in sorted(targets.items()):
            ps = ",".join(t.get("params") or [])
            lines.append(
                "  %s [%s] %s params: %s"
                % (n, t.get("type", "http"), t.get("method", ""), ps or "-")
            )
        return "\n".join(lines)
    if sub == "show":
        if len(parts) < 2:
            return _t("usage_show")
        t = targets.get(parts[1])
        return json.dumps(t, indent=2, ensure_ascii=False) if t else _t("unknown_target_mgmt", parts[1])
    if sub == "add":
        if len(parts) < 4:
            return _t("usage_add")
        name, method, url, ps = parts[1], parts[2].upper(), parts[3], parts[4:]
        if method not in ("GET", "POST"):
            return _t("method_invalid")
        targets[name] = {"type": "http", "method": method, "url": url, "params": ps}
        cfg["targets"] = targets
        try:
            _save_cfg(cfg)
        except Exception as e:
            return _t("write_failed", e)
        return _t("target_added", name, method, ", ".join(ps) or "-")
    if sub in ("del", "remove"):
        if len(parts) < 2:
            return _t("usage_del")
        if parts[1] not in targets:
            return _t("unknown_target_mgmt", parts[1])
        del targets[parts[1]]
        cfg["targets"] = targets
        try:
            _save_cfg(cfg)
        except Exception as e:
            return _t("write_failed", e)
        return _t("target_removed", parts[1])
    return _t("help")


# --------------------------------------------------------------------------- #
# Main handler + registration
# --------------------------------------------------------------------------- #
def _handle_rq(raw_args: str):
    raw = (raw_args or "").strip()
    if not raw or raw.lower() == "help":
        return _t("help")

    cfg = _load_cfg()
    if "_error" in cfg:
        return cfg["_error"]
    defaults = cfg.get("defaults", {})
    targets = cfg.get("targets", {})
    sep = defaults.get("sep", "|")

    first = raw.split()[0].lower()
    if first in RESERVED:
        return _manage(first, raw, cfg, targets)

    if ":" in raw:
        name, payload = raw.split(":", 1)
    else:
        name, payload = raw, ""
    name, payload = name.strip(), payload.strip()

    target = targets.get(name)
    if not target:
        avail = ", ".join(sorted(targets)) or "(none)"
        return _t("unknown_target", name, avail)

    trace = _trace_start(name, target, payload, defaults)
    _trace_mark(trace, "request_received", raw_len=len(raw))

    values, err = _parse_params(payload, target.get("params") or [], sep)
    if err:
        _trace_mark(trace, "params_error", error=err)
        return "[%s] %s" % (name, err)
    _trace_mark(trace, "params_parsed", param_names=target.get("params") or [], value_keys=sorted(values))

    if (target.get("type") or "http").lower() == "exec":
        out = _run_exec(target, values, defaults, bool(cfg.get("allow_exec")), trace=trace)
    else:
        out = _run_http(target, values, defaults, trace=trace)
    out = _truncate(out, defaults)
    _trace_mark(trace, "request_done", output_len=len(out))
    return out


def register(ctx) -> None:
    ctx.register_command(
        "rq",
        handler=_handle_rq,
        description="HTTP request & system-command router (zero-LLM): /rq <target> : <payload>.",
        args_hint="<target> : <payload>",
    )
