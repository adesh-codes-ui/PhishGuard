"""Deployment artifact tests (Day 12).

The templates in ``deploy/`` are documentation-grade examples: no nginx, caddy,
systemd, docker or openssl binary was available when they were written, so they
were **not** syntax-validated or executed. What *can* be checked without those
tools is that they stay consistent with the application's real configuration --
which is what these tests do.

Covered:

* the proxy body cap matches ``PHISHGUARD_MAX_REQUEST_BODY_BYTES``;
* the proxy provides a shared (not per-process) rate limit;
* TLS termination + plaintext redirect are configured;
* no client-supplied ``X-Forwarded-For`` is ever passed through;
* the unit runs exactly one worker, binds loopback, keeps the database on a
  persistent state directory, and enables an explicit trusted-proxy setting;
* every environment key in the deployment files is a real, read setting (the
  "documented but inert variable" bug class from Day 11);
* production examples do not enable wildcard CORS or the interactive docs;
* local development commands and defaults are unchanged.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = REPO_ROOT / "deploy"


def _read(name: str) -> str:
    return (DEPLOY / name).read_text(encoding="utf-8")


def _env_keys(text: str) -> list[str]:
    """Uncommented ``KEY=VALUE`` names (commented lines are documentation)."""
    keys: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        keys.append(line.split("=", 1)[0].strip())
    return keys


def _strip_inline_comment(line: str) -> str:
    """Drop a trailing ``# ...`` comment (no quoted ``#`` appears in these files)."""
    if line.strip().startswith("#"):
        return ""
    kept: list[str] = []
    for index, char in enumerate(line):
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            break
        kept.append(char)
    return "".join(kept)


def _code_lines(text: str) -> list[str]:
    """Directive lines with comments and blank lines removed."""
    return [
        code
        for code in (_strip_inline_comment(line).strip() for line in text.splitlines())
        if code
    ]


def _active_lines(text: str) -> str:
    """Directives only: drop comment lines so prose is not asserted on."""
    return "\n".join(_code_lines(text))


def _squash(text: str) -> str:
    """Collapse whitespace/newlines and drop Markdown emphasis/backticks.

    Keeps prose assertions stable across line wrapping and ``**bold**``.
    """
    plain = text.replace("*", "").replace("`", "")
    return " ".join(plain.split())


def _is_known_setting(key: str, fields: dict) -> bool:
    """True when the application would actually read this variable."""
    if key == "VIRUSTOTAL_API_KEY":
        field = fields.get("virustotal_api_key")
        # Bound through its own alias, so this exact name is the only one that works.
        return field is not None and field.validation_alias is not None
    if key.startswith("PHISHGUARD_"):
        field = fields.get(key[len("PHISHGUARD_"):].lower())
        # A field with a validation_alias ignores the PHISHGUARD_ prefix.
        return field is not None and field.validation_alias is None
    return False


# --------------------------------------------------------------------------- #
# reverse proxy
# --------------------------------------------------------------------------- #
def test_nginx_body_cap_matches_the_application_default():
    text = _read("nginx-phisguard.conf.example")
    match = re.search(r"^\s*client_max_body_size\s+(\S+);", text, re.MULTILINE)
    assert match, "no client_max_body_size directive found"

    value = match.group(1)
    assert value.endswith("k"), f"expected a 1024-based size, got {value!r}"
    assert int(value[:-1]) * 1024 == Settings.model_fields["max_request_body_bytes"].default


def test_nginx_provides_a_shared_rate_limit():
    text = _read("nginx-phisguard.conf.example")
    # The zone must be keyed on the remote address and shared across workers.
    assert re.search(r"limit_req_zone\s+\$binary_remote_addr\s+zone=\w+", text)
    assert re.search(r"limit_req\s+zone=\w+", text)
    assert "429" in text


def test_nginx_terminates_tls_and_redirects_plaintext():
    text = _read("nginx-phisguard.conf.example")
    assert re.search(r"listen\s+443\s+ssl", text)
    assert re.search(r"listen\s+80", text)
    assert re.search(r"return\s+301\s+https://", text)
    # The certificate paths are placeholders, but must be documented.
    assert "ssl_certificate" in text
    assert "certbot" in text


@pytest.mark.parametrize("name", ["nginx-phisguard.conf.example", "Caddyfile.example"])
def test_proxies_never_forward_client_supplied_forwarded_headers(name: str):
    text = _read(name)
    assert "$http_x_forwarded_for" not in text
    assert "X-Forwarded-For\" \"$http" not in text
    assert "{http.request.header.X-Forwarded-For}" not in text


def test_caddy_example_marks_the_rate_limiter_as_module_dependent():
    text = _read("Caddyfile.example").lower()
    assert "no built-in rate limiter" in text
    assert "caddy-ratelimit" in text


def test_caddy_body_cap_matches_the_application_default():
    text = _read("Caddyfile.example")
    match = re.search(r"max_size\s+(\d+)KB", text, re.IGNORECASE)
    assert match, "no request_body max_size found"
    assert int(match.group(1)) * 1024 == Settings.model_fields["max_request_body_bytes"].default


# --------------------------------------------------------------------------- #
# structural lint (NOT a substitute for nginx -t / caddy validate)
# --------------------------------------------------------------------------- #
def test_nginx_rate_limit_zone_is_declared_in_the_http_context():
    """limit_req_zone is http-context only; it must precede the first server."""
    text = _read("nginx-phisguard.conf.example")
    assert text.index("limit_req_zone") < text.index("server {")


def test_nginx_directives_are_brace_balanced_and_terminated():
    lines = _code_lines(_read("nginx-phisguard.conf.example"))
    body = "\n".join(lines)
    assert body.count("{") == body.count("}"), "unbalanced braces"

    for number, line in enumerate(lines, start=1):
        assert line.endswith((";", "{", "}")), (
            f"nginx directive {number} is not terminated: {line!r}"
        )


def test_caddyfile_is_brace_balanced():
    body = "\n".join(_code_lines(_read("Caddyfile.example")))
    assert body.count("{") == body.count("}"), "unbalanced braces"


def test_systemd_unit_parses_as_an_ini_file_with_expected_sections():
    """Structural check only -- systemd itself was not available to verify it."""
    import configparser

    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str  # systemd directive names are case-sensitive
    parser.read(DEPLOY / "phisguard.service", encoding="utf-8")

    assert set(parser.sections()) >= {"Unit", "Service", "Install"}
    assert parser["Unit"]["Description"]
    assert parser["Service"]["ExecStart"].startswith("/opt/phisguard/backend/.venv/bin/uvicorn")
    assert "-app" not in parser["Service"]["ExecStart"]  # no accidental typo


# --------------------------------------------------------------------------- #
# service unit
# --------------------------------------------------------------------------- #
def test_systemd_unit_runs_exactly_one_worker_on_loopback():
    text = _read("phisguard.service")
    assert re.search(r"--workers\s+1\b", text)
    assert not re.search(r"--workers\s+[2-9]", text)
    assert re.search(r"--host\s+127\.0\.0\.1", text)
    assert re.search(r"--port\s+8000", text)
    # No directive may bind a public interface (comments may mention it).
    assert "0.0.0.0" not in _active_lines(text)


def test_systemd_unit_keeps_the_database_on_a_persistent_state_directory():
    text = _read("phisguard.service")
    assert re.search(r"^StateDirectory=phisguard$", text, re.MULTILINE)

    env = _read("phishguard.env.example")
    assert re.search(r"^PHISHGUARD_DATABASE_PATH=/var/lib/phisguard/\S+\.db$", env, re.MULTILINE)


def test_systemd_unit_configures_an_explicit_trusted_proxy():
    text = _read("phisguard.service")
    assert "--proxy-headers" in text
    assert re.search(r"--forwarded-allow-ips=127\.0\.0\.1", text)


def test_systemd_unit_supervises_and_loads_configuration_from_a_file():
    text = _read("phisguard.service")
    assert re.search(r"^Restart=on-failure$", text, re.MULTILINE)
    assert re.search(r"^RestartSec=\d+$", text, re.MULTILINE)
    assert re.search(r"^TimeoutStopSec=\d+$", text, re.MULTILINE)
    assert re.search(r"^EnvironmentFile=/etc/phisguard/phishguard\.env$", text, re.MULTILINE)
    assert re.search(r"^User=\w+$", text, re.MULTILINE)
    assert "[Install]" in text


# --------------------------------------------------------------------------- #
# configuration consistency
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "relative",
    ["deploy/phishguard.env.example", "backend/.env.example"],
)
def test_environment_files_only_use_real_settings(relative: str):
    text = (REPO_ROOT / relative).read_text(encoding="utf-8")
    fields = Settings.model_fields

    unknown = [key for key in _env_keys(text) if not _is_known_setting(key, fields)]
    assert unknown == [], f"{relative} documents settings that are never read: {unknown}"
    assert _env_keys(text), f"{relative} contained no uncommented settings"


def test_virustotal_key_prefix_is_not_mistaken_for_a_setting():
    """The key is bound to its own alias, so a PHISHGUARD_ prefix is inert."""
    fields = Settings.model_fields
    assert _is_known_setting("VIRUSTOTAL_API_KEY", fields)
    assert not _is_known_setting("PHISHGUARD_VIRUSTOTAL_API_KEY", fields)


def test_production_env_file_is_production_safe():
    text = _read("phishguard.env.example")
    assert re.search(r"^PHISHGUARD_ENVIRONMENT=production$", text, re.MULTILINE)
    assert not re.search(r"PHISHGUARD_CORS_ORIGINS\s*=\s*\*", text)
    assert not re.search(r"^PHISHGUARD_DOCS_ENABLED=true$", text, re.MULTILINE)
    assert re.search(r"^PHISHGUARD_RATE_LIMIT_ENABLED=false$", text, re.MULTILINE)


def test_no_deploy_file_enables_a_wildcard_cors_origin():
    for path in sorted(DEPLOY.glob("*")):
        if path.is_file():
            assert "PHISHGUARD_CORS_ORIGINS=*" not in path.read_text(encoding="utf-8")


def test_production_cors_origin_is_a_placeholder_not_a_localhost_default():
    env = _read("phishguard.env.example")
    match = re.search(r"^PHISHGUARD_CORS_ORIGINS=(.+)$", env, re.MULTILINE)
    assert match
    assert "localhost" not in match.group(1)
    assert match.group(1).startswith("https://")


# --------------------------------------------------------------------------- #
# honesty / documentation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "name",
    ["nginx-phisguard.conf.example", "Caddyfile.example", "phisguard.service"],
)
def test_artifacts_declare_that_they_were_not_validated(name: str):
    assert "not validated" in _read(name).lower()


def test_deployment_readme_states_no_artifact_was_run():
    text = _squash(_read("README.md")).lower()
    assert "was executed or validated on a real host" in text
    assert "no nginx" in text


def test_deployment_docs_state_that_history_is_unauthenticated():
    text = _squash(_read("README.md")).lower()
    assert "unauthenticated" in text
    assert "no authentication" in text or "no user model" in text
    # It must not claim that a public deployment is safe.
    assert "does not make a publicly reachable, unauthenticated api safe" in text


def test_deployment_readme_links_the_backup_tooling():
    text = _read("README.md")
    assert "ops/db_lifecycle.py" in text
    assert "ops/README.md" in text


def test_deployment_readme_keeps_the_health_check_local():
    text = _squash(_read("README.md")).lower()
    assert "/api/health" in text
    assert "not publish" in text


# --------------------------------------------------------------------------- #
# local development stays working
# --------------------------------------------------------------------------- #
def test_root_readme_still_documents_the_local_development_commands():
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "uvicorn app.main:app --reload" in text
    assert "npm run dev" in text
    assert "ops/db_lifecycle.py" in text  # backup tooling is discoverable


def test_development_env_example_keeps_development_defaults():
    env = (REPO_ROOT / "backend" / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^PHISHGUARD_ENVIRONMENT=development$", env, re.MULTILINE)
    assert re.search(r"^PHISHGUARD_DATABASE_PATH=phisguard\.db$", env, re.MULTILINE)
    assert re.search(r"^PHISHGUARD_RATE_LIMIT_ENABLED=false$", env, re.MULTILINE)
    assert re.search(r"^PHISHGUARD_CORS_ORIGINS=http://localhost:5173", env, re.MULTILINE)


# --------------------------------------------------------------------------- #
# Day 13: cross-file consistency findings
#
# These pin the *relationships* between files that a single-file review misses
# (the unit vs the install outline, the unit vs the env template, the env
# template vs the Caddy example, the frontend example vs the frontend client).
# They are still lint-level checks: none of them executes nginx, caddy or
# systemd.
# --------------------------------------------------------------------------- #
def _documented_virtualenv() -> str:
    """The virtualenv directory the install outline actually creates."""
    match = re.search(
        r"^cd\s+(/opt/\S+)$\nsudo python3 -m venv \.venv$",
        _read("README.md"),
        re.MULTILINE,
    )
    assert match, "the install outline no longer runs 'python3 -m venv .venv'"
    return f"{match.group(1)}/.venv"


def test_systemd_unit_runs_uvicorn_from_the_documented_virtualenv():
    """D13-1: ExecStart must point at the venv the install outline creates.

    Before this fix the unit used ``/opt/phisguard/.venv`` while the outline
    (and every other reference) created ``/opt/phisguard/backend/.venv``, so
    following the README verbatim left systemd with a non-existent ExecStart.
    """
    venv = _documented_virtualenv()
    assert venv == "/opt/phisguard/backend/.venv"

    match = re.search(r"^ExecStart=(\S+)", _read("phisguard.service"), re.MULTILINE)
    assert match, "no ExecStart found"
    assert match.group(1) == f"{venv}/bin/uvicorn"


def test_systemd_unit_restricts_state_directory_and_file_permissions():
    """D13-2: the database holds every analyzed URL; it must not be world-readable.

    systemd defaults to StateDirectoryMode=0755 and UMask=0022, which would
    expose the SQLite file to any local user.
    """
    text = _read("phisguard.service")
    assert re.search(r"^StateDirectoryMode=0700$", text, re.MULTILINE)
    assert re.search(r"^UMask=0077$", text, re.MULTILINE)


def test_deployment_files_agree_on_the_config_file_mode():
    """D13-6: the real install mode is 640; the unit must not claim 600."""
    unit = _read("phisguard.service")
    assert "chmod 600" not in unit
    assert "-m 640" in unit

    assert "-m 640" in _read("phishguard.env.example")


def test_deploy_env_does_not_claim_the_proxy_always_enforces_the_rate_limit():
    """D13-4: only the nginx example has a limiter; Caddy's is module-dependent."""
    env = _read("phishguard.env.example")
    assert "nginx" in env
    assert "caddy-ratelimit" in env


def test_deploy_readme_obtains_the_certificate_before_validating_tls():
    """D13-7: `nginx -t` cannot succeed for a 443 block whose cert is commented out."""
    text = _read("README.md")
    outline = text[
        text.index("## Install (outline)") : text.index("## Environment configuration")
    ]
    assert outline.index("certbot") < outline.index("nginx -t")


def test_frontend_env_example_treats_the_base_url_as_an_origin():
    """D13-3: client.ts already prefixes every path with /api/."""
    client = (REPO_ROOT / "frontend" / "src" / "api" / "client.ts").read_text(
        encoding="utf-8"
    )
    assert "'/api/analyze'" in client
    assert "`/api/history?limit=${limit}`" in client
    assert "`/api/history/${id}`" in client

    env = (REPO_ROOT / "frontend" / ".env.example").read_text(encoding="utf-8")
    # A base URL beginning with /api would produce /api/api/...
    assert not re.search(r"VITE_API_BASE_URL=/api(?![a-zA-Z])", env)
