"""URL analysis engine.

This module performs *static* (offline) analysis of a URL string. It never
contacts, resolves, or fetches the URL — the MVP must not visit user-supplied
links.

Design notes
------------
* Every rule produces a :class:`Finding` with a human-readable explanation and
  a point weight. The final risk score is the sum of the weights, capped at 100.
* Heuristics can only ever *raise* suspicion. The engine therefore never states
  that a URL is "safe"; the API always returns a disclaimer.

Scoring model
-------------
Each check contributes an explicit, documented number of points, derived from
its severity:

    info 0  ·  low 10  ·  medium 15  ·  high 25  ·  critical 30

The score is the sum of those contributions, capped at 100, and then mapped to
a label:

    Low 0–24  ·  Medium 25–49  ·  High 50–74  ·  Critical 75–100

Weights describe the *strength of evidence*, not a verdict. In particular, using
plain HTTP is a genuine transport weakness (traffic is unencrypted and can be
tampered with) but it is **not** on its own evidence of phishing. It therefore
carries 15 points (``medium``): a URL whose *only* issue is HTTP lands in the
**Low** band (15 < 25) instead of being escalated to Medium. Risk accumulates
additively, so HTTP combined with real phishing signals still raises the label.
A low score never means "safe" — it means no red flags were found.

Two host checks deserve a note because their wording is deliberately narrow:

* **Ambiguous numeric hosts** (``2130706433``, ``0x7f000001``, ``127.1``) are
  flagged because they are alternate encodings of an IP address that some
  browsers still resolve, not because "numbers are bad".
* **Brand impersonation** matches a brand as a whole label token, or as a token
  prefix for brands longer than :data:`_SHORT_BRAND_MAX` characters. This keeps
  e.g. the short brand ``ups`` from matching unrelated words such as ``groups``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import unquote, urlsplit

try:  # Optional, fully offline Public Suffix List data (no network access).
    from publicsuffixlist import PublicSuffixList

    # ICANN section only: private suffixes (e.g. github.io) are intentionally
    # excluded so brand names hidden in those subdomains are still detectable.
    _PSL: PublicSuffixList | None = PublicSuffixList(only_icann=True)
except Exception:  # pragma: no cover - fall back to the built-in approximation
    _PSL = None

MAX_URL_LENGTH = 2048

# Tokens commonly abused for phishing/impersonation.
BRAND_TOKENS = {
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "dropbox", "adobe", "binance",
    "coinbase", "kraken", "metamask", "trustwallet", "steam", "dhl", "fedex",
    "ups", "usps", "chase", "wellsfargo", "bankofamerica", "hsbc", "barclays",
    "outlook", "office365", "icloud", "gmail", "alibaba", "taobao", "telegram",
    "spotify", "robinhood", "stripe", "visa", "mastercard", "amex", "citibank",
}

# Words frequently used to create urgency on credential-harvesting pages.
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "confirm", "password", "passwd", "banking", "wallet",
    "invoice", "payment", "billing", "alert", "suspended", "unlock", "recover",
    "reset", "webscr", "auth", "session", "token", "validate", "credential",
    "refund", "bonus", "prize", "gift", "lucky", "free", "gift-card",
}

# Top-level domains frequently associated with abuse (not proof on their own).
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "work", "click", "country",
    "kim", "science", "party", "top", "gdn", "stream", "download", "racing",
    "accountant", "review", "loan", "men", "date", "faith", "link", "mom",
}

# Fallback multi-part public suffixes, used only when the bundled Public Suffix
# List data is unavailable (see get_registrable_domain).
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.in", "com.au",
    "com.br", "com.mx", "com.cn", "co.za", "com.tr", "co.nz", "co.kr",
}

_SEVERITY_POINTS = {
    "info": 0,
    "low": 10,
    "medium": 15,
    "high": 25,
    "critical": 30,
}

# Brands of this length or shorter must match a whole label token; longer brands
# may also appear as a prefix of a token (e.g. "paypallogin" or "appleid").
_SHORT_BRAND_MAX = 3

# Split host labels into lowercase alphanumeric tokens on any other character.
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")

# An all-numeric label: decimal/octal-looking (all digits) or hex ("0x...").
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")


@dataclass
class Finding:
    """A single, explainable reason contributing to the risk score."""

    code: str
    title: str
    description: str
    points: int
    severity: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class Analysis:
    """Full analysis output for one URL."""

    input_url: str
    normalized_url: str
    scheme: str
    host: str
    registrable_domain: str
    risk_score: int
    risk_label: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "input_url": self.input_url,
            "normalized_url": self.normalized_url,
            "scheme": self.scheme,
            "host": self.host,
            "registrable_domain": self.registrable_domain,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "findings": [f.to_dict() for f in self.findings],
        }


class InvalidURLError(ValueError):
    """Raised when input cannot be treated as a valid http/https URL."""


# --------------------------------------------------------------------------- #
# Normalization helpers
# --------------------------------------------------------------------------- #
def _validate_host(host: str) -> None:
    """Reject hosts that are structurally malformed.

    Accepts domain names, IPv4/IPv6 literals and internationalized (non-ASCII)
    hosts — the latter are deliberately *not* rejected so the analyzer can flag
    them as visual-spoofing signals. Malformed input (whitespace, empty labels,
    labels starting/ending with '-', or stray punctuation) is rejected.
    """
    if not host:
        raise InvalidURLError("URL is missing a host.")
    if any(ch.isspace() for ch in host):
        raise InvalidURLError("URL host contains whitespace.")

    candidate = host.rstrip(".")
    if not candidate:
        raise InvalidURLError("URL host is invalid.")

    # Valid IPv4/IPv6 literals are fine (does not resolve DNS; parsing only).
    try:
        ipaddress.ip_address(candidate)
        return
    except ValueError:
        pass

    for label in candidate.split("."):
        if not label:
            raise InvalidURLError("URL host contains an empty label.")
        if label.startswith("-") or label.endswith("-"):
            raise InvalidURLError("URL host contains an invalid label.")
        for ch in label:
            # Allow non-ASCII so IDN homographs can be detected downstream.
            if ord(ch) < 128 and not (ch.isalnum() or ch in "-_"):
                raise InvalidURLError("URL host contains invalid characters.")


def _looks_like_schemeless_host(token: str) -> bool:
    """Whether ``token`` may be the host of a schemeless ``host:port`` URL.

    ``example.com:8080/path`` has no scheme and is meant to be read as a bare
    host with a port. ``tel:12345``, ``data:1234`` and ``javascript:1`` match the
    *same* shape — a token, a colon, then digits — yet are non-hierarchical URIs
    whose opaque part merely happens to be numeric. The two readings cannot be
    told apart syntactically, so the bare-host reading is accepted only for
    tokens that are plausibly hosts:

    * a dotted name (``example.com``, ``my.host``, IPv4 literals), or
    * ``localhost`` (the common local-development entry), or
    * an IP literal.

    Anything else is treated as a URI **scheme** and therefore rejected as
    unsupported (except ``http``/``https``, handled before this is consulted).
    This is deliberately fail-closed: a single-label intranet host such as
    ``myserver:8080`` must be written ``http://myserver:8080`` to be analyzed,
    while ``javascript:1`` and friends are refused either way.
    """
    if not token:
        return False
    if token == "localhost":
        return True
    candidate = token[1:-1] if token.startswith("[") and token.endswith("]") else token
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    return "." in candidate


def normalize_url(raw: str) -> tuple[str, bool]:
    """Validate and normalize a raw URL string.

    Returns a ``(normalized_url, scheme_was_added)`` tuple. Raises
    :class:`InvalidURLError` for empty, over-long, or non-http(s) input.
    """
    if raw is None:
        raise InvalidURLError("No URL was provided.")

    text = raw.strip()
    if not text:
        raise InvalidURLError("URL cannot be empty.")
    if len(text) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is too long (max {MAX_URL_LENGTH} characters).")
    if any(ord(ch) < 32 for ch in text):
        raise InvalidURLError("URL contains control characters.")

    scheme_added = False

    # Detect an explicit hierarchical scheme only at the very start, so a
    # "://" appearing later (e.g. in a query parameter) is not mistaken for a
    # scheme. This is what previously rejected inputs such as
    # "example.com/redirect?url=https://evil.com".
    hierarchical = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", text)
    if hierarchical:
        scheme = hierarchical.group(1).lower()
        if scheme not in {"http", "https"}:
            raise InvalidURLError(
                f"Unsupported URL scheme '{scheme}'. Only http and https are allowed."
            )
    else:
        # No leading "://" — distinguish a non-hierarchical scheme
        # (javascript:, data:, mailto:) from a bare host/path.
        match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):(.*)$", text, re.DOTALL)
        if match:
            scheme = match.group(1).lower()
            remainder = match.group(2)
            if scheme in {"http", "https"}:
                text = f"{scheme}://{remainder}"
            elif _looks_like_schemeless_host(scheme) and remainder.split("/", 1)[0].isdigit():
                # Bare "host:port" with no scheme, e.g. example.com:8080/path.
                # Only for host-looking tokens: "tel:12345" / "data:1234" /
                # "javascript:1" must NOT be reinterpreted as http URLs.
                text = "http://" + text
                scheme_added = True
            else:
                raise InvalidURLError(
                    f"Unsupported URL scheme '{scheme}'. Only http and https are allowed."
                )
        else:
            # Treat a bare host/path as http, and remember that no scheme was given.
            text = "http://" + text
            scheme_added = True

    try:
        parts = urlsplit(text)
    except ValueError as exc:
        # urlsplit raises ValueError for structurally invalid URLs such as an
        # unclosed IPv6 literal (e.g. "http://[::1"). Surface it as a clean
        # validation error instead of an unhandled exception.
        raise InvalidURLError("URL is malformed and could not be parsed.") from exc

    scheme = parts.scheme.lower()

    if scheme not in {"http", "https"}:
        raise InvalidURLError(
            f"Unsupported URL scheme '{scheme or '(none)'}'. Only http and https are allowed."
        )
    if not parts.netloc:
        raise InvalidURLError("URL is missing a host.")

    # Accessing .port can raise for malformed/out-of-range ports.
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidURLError("URL contains an invalid port.") from exc

    # Rebuild a normalized form (lowercased scheme/host, preserved path/query).
    host = parts.hostname or ""
    _validate_host(host)
    # Drop a single trailing dot (FQDN form) so hosts are consistent downstream.
    host = host.rstrip(".")

    # IPv6 literals are re-wrapped in brackets so the normalized URL stays valid.
    display_host = f"[{host}]" if ":" in host else host
    # Drop an explicitly written default port so equivalent URLs normalize
    # identically (http:80, https:443). Non-standard ports are preserved.
    is_default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    netloc = display_host
    if port and not is_default_port:
        netloc = f"{display_host}:{port}"
    if parts.username or parts.password:
        # Keep userinfo so the analyzer can flag it, but normalize the host.
        userinfo = parts.username or ""
        if parts.password:
            userinfo = f"{userinfo}:{parts.password}"
        netloc = f"{userinfo}@{netloc}"

    normalized = f"{scheme}://{netloc}{parts.path or '/'}"
    if parts.query:
        normalized += f"?{parts.query}"
    if parts.fragment:
        normalized += f"#{parts.fragment}"
    return normalized, scheme_added


def get_registrable_domain(host: str) -> str:
    """Return the registrable domain (e.g. ``a.b.example.co.uk`` -> ``example.co.uk``).

    Uses the **Public Suffix List** (ICANN section, bundled offline) so that
    multi-part public suffixes such as ``co.uk``, ``com.au`` or ``com.ng`` are
    handled correctly. This is what makes ``paypal.com.example.org`` resolve to
    ``example.org`` and not to ``paypal.com``.

    IP literals are returned unchanged. If the PSL data is unavailable, a small
    built-in suffix list (``MULTI_PART_TLDS``) is used as an approximation.
    """
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass

    candidate = host.rstrip(".")
    if not candidate:
        return host

    if _PSL is not None:
        registrable = _PSL.privatesuffix(candidate)
        if registrable:
            return registrable

    # Fallback approximation used only when the PSL data is unavailable.
    labels = candidate.split(".")
    if len(labels) < 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _classify(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def _add(findings: list[Finding], code: str, title: str, description: str, severity: str) -> None:
    findings.append(
        Finding(
            code=code,
            title=title,
            description=description,
            points=_SEVERITY_POINTS[severity],
            severity=severity,
        )
    )


def _label_tokens(value: str) -> list[str]:
    """Split a host/label into lowercase alphanumeric tokens."""
    return [token for token in _TOKEN_SPLIT.split(value.lower()) if token]


def _brand_in_labels(value: str, brand: str) -> bool:
    """Return True when ``brand`` appears as a label token or token prefix.

    Requiring a token boundary (or, for longer brands, a token *prefix*)
    avoids false positives such as the short brand ``ups`` matching ``groups``
    or ``chase`` matching ``purchase``.
    """
    for token in _label_tokens(value):
        if token == brand:
            return True
        if len(brand) > _SHORT_BRAND_MAX and token.startswith(brand):
            return True
    return False


def _is_ambiguous_numeric_host(host: str) -> bool:
    """True for all-numeric hosts that are not standard IPv4/IPv6 literals.

    Some browsers still resolve alternate address encodings such as the decimal
    ``2130706433``, hex ``0x7f000001``, octal ``0177.0.0.1`` or shortened
    ``127.1``. These are valid inputs to :func:`ipaddress.ip_address` only in
    their canonical forms, so anything all-numeric that is *not* a canonical
    literal is treated as an obfuscated host.
    """
    labels = host.split(".")
    if not labels:
        return False
    return all(_NUMERIC_LABEL.match(label) for label in labels)


def _analyze_host(host: str, registrable: str, findings: list[Finding]) -> None:
    # 1. IP-address hosts.
    is_ip_literal = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip_literal = True
    except ValueError:
        pass

    if is_ip_literal:
        _add(
            findings,
            "ip_address_host",
            "Host is a raw IP address",
            "Legitimate services almost always use domain names. Raw-IP links are a common phishing signal.",
            "high",
        )
    elif _is_ambiguous_numeric_host(host):
        _add(
            findings,
            "numeric_host",
            "Host is a numeric address rather than a domain name",
            "The host is made up only of numbers. Forms such as '2130706433', "
            "'0x7f000001' or '127.1' are alternate encodings of an IP address, "
            "often used to hide the real destination.",
            "high",
        )

    # 2. Punycode / IDN homograph.
    if host.startswith("xn--") or ".xn--" in host:
        _add(
            findings,
            "punycode_host",
            "Punycode (internationalized) domain",
            "Punycode domains can encode look-alike characters used to imitate trusted brands.",
            "high",
        )

    # 3. Non-ASCII characters in the host.
    if any(ord(ch) > 127 for ch in host):
        _add(
            findings,
            "non_ascii_host",
            "Non-ASCII characters in the host",
            "Unicode characters in a hostname are often used for visual spoofing of real domains.",
            "high",
        )

    # 4. Brand name hidden in a subdomain (e.g. paypal.com.evil-site.net).
    host_labels = host.split(".")
    reg_labels = registrable.split(".")
    subdomain = host_labels[: len(host_labels) - len(reg_labels)]
    subdomain_text = ".".join(subdomain)
    for brand in BRAND_TOKENS:
        if _brand_in_labels(subdomain_text, brand):
            _add(
                findings,
                "brand_in_subdomain",
                f"Brand name '{brand}' appears in the subdomain, not the registered domain",
                f"The real owner of this link is '{registrable}', but it references '{brand}' to look trustworthy.",
                "critical",
            )
            break

    # 5. Brand name with extra words in the registered domain (e.g. paypal-secure.com).
    primary_label = reg_labels[0] if reg_labels else registrable
    for brand in BRAND_TOKENS:
        if primary_label.lower() != brand and _brand_in_labels(primary_label, brand):
            _add(
                findings,
                "brand_plus_extra",
                f"Registered domain imitates '{brand}'",
                f"'{registrable}' contains the brand name '{brand}' combined with extra words or digits.",
                "high",
            )
            break

    # 6. Excessive subdomain depth.
    if len(subdomain) >= 4:
        _add(
            findings,
            "many_subdomains",
            "Unusually deep subdomain chain",
            "Many subdomain levels are sometimes used to hide the real registered domain from the user.",
            "medium",
        )
    elif len(subdomain) >= 3:
        _add(
            findings,
            "multiple_subdomains",
            "Multiple subdomains",
            "Several subdomain levels can be used to push the real domain out of view.",
            "low",
        )

    # 7. Hyphens in the primary domain label.
    if primary_label.count("-") >= 2:
        _add(
            findings,
            "hyphenated_domain",
            "Domain name contains multiple hyphens",
            "Hyphen-heavy domains are common in look-alike phishing domains.",
            "medium",
        )

    # 8. Very long domain label.
    if len(primary_label) > 30:
        _add(
            findings,
            "long_domain_label",
            "Unusually long domain label",
            "Very long labels can be used to bury a brand name or a security-relevant detail.",
            "low",
        )

    # 9. Suspicious TLD.
    tld = registrable.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        _add(
            findings,
            "suspicious_tld",
            f"Risky top-level domain '.{tld}'",
            f"The '.{tld}' TLD is disproportionately used for abusive registrations.",
            "medium",
        )


def _analyze_url_parts(
    scheme: str,
    host: str,
    parts: object,
    normalized: str,
    scheme_was_added: bool,
    registrable: str,
    findings: list[Finding],
) -> None:
    getter = parts  # urlsplit result

    # HTTPS usage. Plain HTTP is a real transport weakness but not evidence of
    # phishing, so it carries only `medium` (15) points: on its own it lands in
    # the Low band, and it cannot push a URL to Medium by itself.
    if scheme != "https":
        _add(
            findings,
            "no_https",
            "Connection is not HTTPS",
            "The link uses plain HTTP, so traffic is unencrypted and could be tampered with. "
            "This is a transport weakness, not evidence of phishing on its own.",
            "medium",
        )

    if scheme_was_added:
        _add(
            findings,
            "missing_scheme",
            "No scheme supplied",
            "The URL had no 'http://' or 'https://'. It was assumed to be http for analysis.",
            "info",
        )

    # '@' in the URL — classic trick to make a host look like something else.
    authority = getter.netloc if hasattr(getter, "netloc") else ""
    if "@" in authority:
        _add(
            findings,
            "at_symbol",
            "'@' in the authority section",
            "Everything before '@' is a username, not the host. Attackers hide the real host after it.",
            "high",
        )

    if getter.username or getter.password:
        _add(
            findings,
            "userinfo_present",
            "Credentials embedded in the URL",
            "The URL embeds a username/password before the host, which is a common deception technique.",
            "high",
        )

    # Non-standard port.
    if getter.port and getter.port not in (80, 443):
        _add(
            findings,
            "nonstandard_port",
            f"Non-standard port {getter.port}",
            "Legitimate web links usually use the default port (80/443).",
            "low",
        )

    # Double slash in the path (open-redirect style).
    if "//" in (getter.path or ""):
        _add(
            findings,
            "double_slash_path",
            "Double slash inside the path",
            "A '//' in the path can be used in open-redirect and obfuscation tricks.",
            "medium",
        )

    # Heavy percent-encoding.
    percent_count = normalized.count("%")
    if percent_count >= 3:
        _add(
            findings,
            "encoded_characters",
            "Heavy URL encoding",
            "Many encoded characters can hide the true destination or payload of a link.",
            "medium",
        )

    # Suspicious keywords in host, path or query.
    haystack = unquote(f"{host}{getter.path or ''}?{getter.query or ''}").lower()
    matched = sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in haystack})
    if len(matched) >= 2:
        _add(
            findings,
            "credential_keywords",
            "Multiple credential/urgency keywords",
            f"The URL contains several phishing-style keywords: {', '.join(matched[:5])}.",
            "high",
        )
    elif matched:
        _add(
            findings,
            "suspicious_keyword",
            "Phishing-style keyword in the URL",
            f"The URL contains the keyword '{matched[0]}', often used on credential-harvesting pages.",
            "medium",
        )

    # Overall length tiers.
    length = len(normalized)
    if length > 120:
        _add(
            findings,
            "very_long_url",
            "Very long URL",
            "Long URLs are used to obscure the true destination.",
            "high",
        )
    elif length > 75:
        _add(
            findings,
            "long_url",
            "Long URL",
            "Unusually long URLs can be used to push important details out of view.",
            "medium",
        )

    # HTTPS with an IP/uncertain host compounds risk; note we never call it safe.
    _ = registrable  # reserved for future rules


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def analyze_url(raw_url: str) -> Analysis:
    """Analyze a URL string and return an :class:`Analysis`.

    Raises :class:`InvalidURLError` if the input is not a usable http/https URL.
    """
    normalized, scheme_was_added = normalize_url(raw_url)
    parts = urlsplit(normalized)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    registrable = get_registrable_domain(host)

    findings: list[Finding] = []
    _analyze_host(host, registrable, findings)
    _analyze_url_parts(
        scheme, host, parts, normalized, scheme_was_added, registrable, findings
    )

    # Sort findings by weight so the most important reasons come first.
    findings.sort(key=lambda f: f.points, reverse=True)

    score = min(100, sum(f.points for f in findings))
    label = _classify(score)

    return Analysis(
        input_url=raw_url,
        normalized_url=normalized,
        scheme=scheme,
        host=host,
        registrable_domain=registrable,
        risk_score=score,
        risk_label=label,
        findings=findings,
    )


def has_https(normalized_url: str) -> bool:
    """Small helper used by tests and the API health check."""
    return urlsplit(normalized_url).scheme.lower() == "https"
