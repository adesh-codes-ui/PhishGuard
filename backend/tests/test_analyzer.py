"""Tests for URL normalization, heuristics and risk scoring."""

from __future__ import annotations

import pytest

from app.analyzer import (
    InvalidURLError,
    _classify,
    analyze_url,
    get_registrable_domain,
    normalize_url,
)


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #
def test_normalize_adds_scheme():
    normalized, added = normalize_url("example.com/login")
    assert added is True
    assert normalized.startswith("http://example.com")


def test_normalize_preserves_https():
    normalized, added = normalize_url("https://Example.com/Path")
    assert added is False
    assert normalized.startswith("https://example.com")


def test_normalize_strips_whitespace():
    normalized, _ = normalize_url("   https://example.com   ")
    assert normalized == "https://example.com/"


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "javascript:alert(1)", "data:text/html,<script>", "file:///etc/passwd"],
)
def test_normalize_rejects_bad_input(bad):
    with pytest.raises(InvalidURLError):
        normalize_url(bad)


def test_normalize_rejects_overlong_url():
    with pytest.raises(InvalidURLError):
        normalize_url("https://example.com/" + "a" * 3000)


def test_normalize_rejects_control_characters():
    with pytest.raises(InvalidURLError):
        normalize_url("https://example.com/\x00bad")


def test_normalize_rejects_missing_host():
    with pytest.raises(InvalidURLError):
        normalize_url("https:///nohost")


# --------------------------------------------------------------------------- #
# Registrable domain
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "host,expected",
    [
        ("www.example.com", "example.com"),
        ("a.b.example.com", "example.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("example.com", "example.com"),
    ],
)
def test_registrable_domain(host, expected):
    assert get_registrable_domain(host) == expected


# --------------------------------------------------------------------------- #
# Legitimate URLs -> low risk
# --------------------------------------------------------------------------- #
def test_legit_https_url_is_low_risk():
    result = analyze_url("https://www.example.com/")
    assert result.scheme == "https"
    assert result.risk_label == "Low"
    assert result.risk_score < 25


def test_https_never_returns_safe_claim():
    # The analyzer only produces findings; it never asserts safety.
    result = analyze_url("https://github.com/")
    assert result.risk_label in {"Low", "Medium", "High", "Critical"}
    for finding in result.findings:
        assert "safe" not in finding.description.lower()


# --------------------------------------------------------------------------- #
# Suspicious URLs -> higher risk
# --------------------------------------------------------------------------- #
def test_http_scheme_is_flagged():
    result = analyze_url("http://example.com/")
    codes = {f.code for f in result.findings}
    assert "no_https" in codes


def test_ip_address_host_flagged():
    result = analyze_url("http://192.168.0.1/login")
    codes = {f.code for f in result.findings}
    assert "ip_address_host" in codes
    assert result.risk_label in {"High", "Critical"}


def test_brand_in_subdomain_flagged():
    result = analyze_url("http://paypal.com.secure-login.evil.net/")
    codes = {f.code for f in result.findings}
    assert "brand_in_subdomain" in codes
    assert result.risk_label == "Critical"


def test_brand_plus_extra_flagged():
    result = analyze_url("https://paypal-secure.com/login")
    codes = {f.code for f in result.findings}
    assert "brand_plus_extra" in codes


def test_at_symbol_flagged():
    result = analyze_url("http://accounts.google.com@phish.example.com/login")
    codes = {f.code for f in result.findings}
    assert "at_symbol" in codes or "userinfo_present" in codes


def test_punycode_flagged():
    result = analyze_url("http://xn--pypal-4ve.com/login")
    codes = {f.code for f in result.findings}
    assert "punycode_host" in codes


def test_suspicious_keywords_flagged():
    result = analyze_url("http://example.com/secure-login-verify-account")
    codes = {f.code for f in result.findings}
    assert "credential_keywords" in codes or "suspicious_keyword" in codes


def test_suspicious_tld_flagged():
    result = analyze_url("http://free-money.tk/claim")
    codes = {f.code for f in result.findings}
    assert "suspicious_tld" in codes


def test_findings_sorted_by_points():
    result = analyze_url("http://192.168.1.1/secure-login-verify")
    points = [f.points for f in result.findings]
    assert points == sorted(points, reverse=True)


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url",
    [
        "https://www.example.com/",
        "http://192.168.0.1/login",
        "http://paypal.com.secure-login.evil.net/",
        "https://paypal-secure.com/verify-account",
    ],
)
def test_score_bounds_and_label(url):
    result = analyze_url(url)
    assert 0 <= result.risk_score <= 100
    assert result.risk_label in {"Low", "Medium", "High", "Critical"}


def test_obviously_phishy_scores_higher_than_clean():
    clean = analyze_url("https://www.example.com/")
    phishy = analyze_url("http://paypal.com.secure-login.evil.net/verify-account")
    assert phishy.risk_score > clean.risk_score


def test_score_is_capped_at_100():
    # Stack many signals at once; the score must never exceed 100.
    result = analyze_url(
        "http://paypal.com@192.168.0.1:8080/secure-login-verify-account-update"
        "-confirm-password/reset?token=abcdefghijklmnop#frag"
    )
    assert result.risk_score == 100


# --------------------------------------------------------------------------- #
# Regression: reported scores are locked in
# --------------------------------------------------------------------------- #
def test_regression_https_example_scores_zero():
    result = analyze_url("https://example.com")
    assert result.risk_score == 0
    assert result.risk_label == "Low"
    assert result.findings == []


def test_regression_http_example_is_low_when_http_is_only_signal():
    # Plain HTTP must be treated as a weakness, not a phishing verdict: on its
    # own it lands in the Low band rather than jumping to Medium.
    result = analyze_url("http://example.com")
    assert {f.code for f in result.findings} == {"no_https"}
    assert result.risk_score == 15
    assert result.risk_label == "Low"


def test_http_is_not_assumed_to_be_phishing():
    finding = analyze_url("http://example.com").findings[0]
    assert finding.code == "no_https"
    assert "not evidence of phishing" in finding.description.lower()


def test_regression_paypal_subdomain_belongs_to_example_org():
    result = analyze_url("https://paypal.com.example.org")
    assert result.registrable_domain == "example.org"
    assert result.registrable_domain != "paypal.com"
    assert result.risk_score == 30
    assert result.risk_label == "Medium"

    codes = {f.code for f in result.findings}
    assert "brand_in_subdomain" in codes

    # The explanation must name the real owner, not the impersonated brand.
    brand = next(f for f in result.findings if f.code == "brand_in_subdomain")
    assert "example.org" in brand.description


def test_hostname_parsing_separates_subdomain_from_registrable_domain():
    assert get_registrable_domain("paypal.com.example.org") == "example.org"
    assert get_registrable_domain("paypal.com.evil.net") == "evil.net"
    assert get_registrable_domain("www.paypal.com") == "paypal.com"


def test_real_paypal_domain_is_not_flagged_as_brand_in_subdomain():
    result = analyze_url("https://www.paypal.com/account/login")
    codes = {f.code for f in result.findings}
    assert "brand_in_subdomain" not in codes


def test_http_alone_scores_lower_than_http_plus_real_signal():
    http_only = analyze_url("http://example.com")
    http_and_phish = analyze_url("http://paypal.com.example.org")
    assert http_only.risk_score < http_and_phish.risk_score
    assert http_only.risk_label == "Low"


# --------------------------------------------------------------------------- #
# Regression: malformed input
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad",
    [
        "http://",
        "https://",
        "htp://example.com",
        "http://exa mple.com",
        "not a url",
        "http://.",
        "http://-",
        "https://exa..mple.com",
        "https://-bad.com",
        "https://bad-.com",
        "https://example.com:99999",
        "https://example.com:abc/",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
    ],
)
def test_regression_malformed_urls_are_rejected(bad):
    with pytest.raises(InvalidURLError):
        analyze_url(bad)


def test_normalize_strips_trailing_dot_from_host():
    normalized, _ = normalize_url("https://example.com.")
    assert normalized == "https://example.com/"


def test_normalize_keeps_ipv6_literal_brackets():
    normalized, _ = normalize_url("http://[::1]:8080/x")
    assert normalized == "http://[::1]:8080/x"


def test_registrable_domain_of_ip_is_the_ip_itself():
    assert get_registrable_domain("192.168.0.1") == "192.168.0.1"


# --------------------------------------------------------------------------- #
# Public Suffix List-aware registrable domains (multi-part suffixes)
# --------------------------------------------------------------------------- #
def test_psl_data_is_loaded():
    # The PSL-backed path must be active so multi-part suffixes are correct.
    from app import analyzer

    assert analyzer._PSL is not None


def test_registrable_domain_handles_multipart_public_suffixes():
    assert get_registrable_domain("shop.example.co.uk") == "example.co.uk"
    assert get_registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert get_registrable_domain("www.example.com.ng") == "example.com.ng"
    assert get_registrable_domain("www.example.com.au") == "example.com.au"


def test_example_co_uk_is_low_risk():
    result = analyze_url("https://www.example.co.uk/")
    assert result.registrable_domain == "example.co.uk"
    assert result.risk_score == 0
    assert result.risk_label == "Low"


# --------------------------------------------------------------------------- #
# Malformed URLs (additional coverage)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad",
    [
        "   ",
        "http://exa\tmple.com",
        "https://:8080/",
        "http://example..com",
        "https://.example.com",
        "http://example.com:70000",
        "ftp://example.com",
        "http://[::1",  # unclosed IPv6 literal (urlsplit would raise ValueError)
        "http://[not:hex]/",  # invalid IPv6 literal
    ],
)
def test_additional_malformed_urls_are_rejected(bad):
    with pytest.raises(InvalidURLError):
        analyze_url(bad)


def test_unclosed_ipv6_is_a_validation_error_not_a_crash():
    # Regression: this used to leak a raw ValueError from urlsplit.
    with pytest.raises(InvalidURLError):
        normalize_url("http://[::1")


# --------------------------------------------------------------------------- #
# IP-address hosts
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url,expected_host",
    [
        ("http://192.168.0.1/login", "192.168.0.1"),
        ("https://8.8.8.8/", "8.8.8.8"),
        ("http://[::1]/", "::1"),
    ],
)
def test_ip_address_hosts_are_flagged(url, expected_host):
    result = analyze_url(url)
    assert result.host == expected_host
    # An IP has no registrable domain; it is returned unchanged.
    assert result.registrable_domain == expected_host
    codes = {f.code for f in result.findings}
    assert "ip_address_host" in codes


# --------------------------------------------------------------------------- #
# Misleading brand subdomains
# --------------------------------------------------------------------------- #
def test_brand_in_subdomain_with_multipart_suffix():
    result = analyze_url("http://paypal.com.example.co.uk/login")
    assert result.registrable_domain == "example.co.uk"
    codes = {f.code for f in result.findings}
    assert "brand_in_subdomain" in codes
    assert result.risk_label in {"High", "Critical"}


@pytest.mark.parametrize(
    "url,registrable",
    [
        ("https://apple.id.example.com/", "example.com"),
        ("https://microsoft.com.example.net/", "example.net"),
        ("https://google.example.org/verify", "example.org"),
    ],
)
def test_misleading_brand_subdomains(url, registrable):
    result = analyze_url(url)
    assert result.registrable_domain == registrable
    codes = {f.code for f in result.findings}
    assert "brand_in_subdomain" in codes


def test_brand_subdomain_on_private_suffix_host_is_flagged():
    # github.io is a private suffix; ICANN-only PSL keeps the real owner as
    # github.io so a brand hidden in the subdomain is still detected.
    result = analyze_url("https://paypal.github.io/")
    assert result.registrable_domain == "github.io"
    codes = {f.code for f in result.findings}
    assert "brand_in_subdomain" in codes


# --------------------------------------------------------------------------- #
# Normalization: scheme detection, ports, casing, IDN
# --------------------------------------------------------------------------- #
def test_scheme_like_text_in_query_is_not_mistaken_for_a_scheme():
    # Regression: a bare host whose query contains "://" used to be rejected.
    normalized, added = normalize_url("example.com/redirect?url=https://evil.com")
    assert added is True
    assert normalized == "http://example.com/redirect?url=https://evil.com"


def test_bare_host_with_port_and_embedded_url_in_query():
    normalized, added = normalize_url("example.com:8080/path?u=http://x")
    assert added is True
    assert normalized == "http://example.com:8080/path?u=http://x"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://example.com:443/x", "https://example.com/x"),
        ("http://example.com:80/", "http://example.com/"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("http://example.com:8080/", "http://example.com:8080/"),
    ],
)
def test_normalize_drops_only_default_ports(raw, expected):
    normalized, _ = normalize_url(raw)
    assert normalized == expected


def test_normalize_lowercases_scheme_and_host_but_preserves_path_case():
    normalized, _ = normalize_url("HTTPS://Example.COM/Path/To?Q=Value")
    assert normalized == "https://example.com/Path/To?Q=Value"


def test_normalize_preserves_trailing_slash_semantics():
    # A missing path becomes "/" so equivalent forms are comparable.
    assert normalize_url("https://example.com")[0] == "https://example.com/"
    assert normalize_url("https://example.com/")[0] == "https://example.com/"


def test_normalize_keeps_internationalized_host_intact():
    # IDN hosts are intentionally NOT punycoded so they can be flagged as
    # non-ASCII (visual spoofing) rather than silently rewritten.
    normalized, _ = normalize_url("https://münchen.example/")
    assert "münchen" in normalized


@pytest.mark.parametrize(
    "scheme_url",
    [
        "ftp://example.com",
        "mailto:user@example.com",
        "tel:+123456",
        "javascript:alert(1)",
        "data:text/html,<script>",
        "file:///etc/passwd",
        "ws://example.com/socket",
    ],
)
def test_unsupported_schemes_are_rejected_with_a_message(scheme_url):
    with pytest.raises(InvalidURLError) as excinfo:
        normalize_url(scheme_url)
    assert "scheme" in str(excinfo.value).lower()


# Regression (Day 15): the schemeless "host:port" fallback used to fire for ANY
# token whose remainder started with digits, so "tel:12345", "data:1234" and
# "javascript:1" were silently rewritten to http://tel:12345/ etc. and accepted
# as HTTP URLs — while the equivalent "tel:+123456" was rejected. The bare-host
# reading is now allowed only for tokens that look like hosts.
@pytest.mark.parametrize(
    "numeric_opaque_uri",
    [
        "tel:12345",
        "data:1234",
        "javascript:1",
        "file:1",
        "sms:999",
    ],
)
def test_numeric_opaque_parts_of_non_http_schemes_are_rejected(numeric_opaque_uri):
    with pytest.raises(InvalidURLError) as excinfo:
        normalize_url(numeric_opaque_uri)
    assert "scheme" in str(excinfo.value).lower()


@pytest.mark.parametrize(
    "schemeless_host_port",
    [
        "example.com:8080/path",            # documented bare host:port form
        "example.com:8080/path?u=http://x",
        "x.test:8080",
        "localhost:8000/api/health",        # local-development entry point
    ],
)
def test_schemeless_host_with_port_is_still_accepted(schemeless_host_port):
    normalized, added = normalize_url(schemeless_host_port)
    assert added is True
    assert normalized.startswith("http://")


def test_single_label_intranet_host_may_need_an_explicit_scheme():
    # Documented trade-off: a bare "myserver:8080" cannot be told apart from a
    # "myserver:..." URI, so it is refused; writing the scheme out works.
    with pytest.raises(InvalidURLError):
        normalize_url("myserver:8080")
    normalized, added = normalize_url("http://myserver:8080")
    assert added is False
    assert normalized == "http://myserver:8080/"


# --------------------------------------------------------------------------- #
# Ambiguous / obfuscated numeric hosts
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url",
    [
        "http://2130706433/",       # decimal form of 127.0.0.1
        "http://0x7f000001/",       # hexadecimal form
        "http://0177.0.0.1/",       # octal-looking labels
        "http://127.1/",            # shortened IPv4
        "http://1.2.3.4.5/",        # too many labels to be IPv4
    ],
)
def test_obfuscated_numeric_hosts_are_flagged(url):
    result = analyze_url(url)
    codes = {f.code for f in result.findings}
    assert "numeric_host" in codes
    # A non-canonical numeric host is not a normal domain, so it must not be
    # reported as an ordinary (safe-looking) low-risk domain on its own.
    assert result.risk_score >= 25


@pytest.mark.parametrize("url", ["http://192.168.0.1/", "https://8.8.8.8/"])
def test_canonical_ip_hosts_use_ip_rule_not_numeric_rule(url):
    codes = {f.code for f in analyze_url(url).findings}
    assert "ip_address_host" in codes
    assert "numeric_host" not in codes


def test_plain_numeric_domain_label_is_not_flagged():
    # A numeric label inside a real domain (with a normal TLD) is not an
    # obfuscated address.
    codes = {f.code for f in analyze_url("https://1234.example.com/").findings}
    assert "numeric_host" not in codes


# --------------------------------------------------------------------------- #
# Brand impersonation: reduce false positives but keep real matches
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url",
    [
        "https://groups.com/",              # contains "ups" as a substring
        "https://purchase.example.com/",    # contains "chase" as a substring
        "https://backup.example.com/",      # contains "ups" as a substring
        "https://advisable.example.com/",   # contains "visa" as a substring
    ],
)
def test_brand_substring_false_positives_are_not_flagged(url):
    codes = {f.code for f in analyze_url(url).findings}
    assert "brand_in_subdomain" not in codes
    assert "brand_plus_extra" not in codes


@pytest.mark.parametrize(
    "url,expected_code",
    [
        ("https://paypal-secure.com/login", "brand_plus_extra"),
        ("https://paypallogin.com/", "brand_plus_extra"),
        ("https://ups-login.com/", "brand_plus_extra"),
        ("https://appleid.evil.com/", "brand_in_subdomain"),
        ("https://visacheckout.example.com/", "brand_in_subdomain"),
        ("https://microsoft.com.example.net/", "brand_in_subdomain"),
    ],
)
def test_real_brand_impersonation_is_still_flagged(url, expected_code):
    codes = {f.code for f in analyze_url(url).findings}
    assert expected_code in codes


def test_real_brand_owned_domain_is_not_flagged_as_impersonation():
    # The registrable domain *is* the brand: not an impersonation.
    for url in ("https://www.paypal.com/", "https://apple.com/", "https://ups.com/"):
        codes = {f.code for f in analyze_url(url).findings}
        assert "brand_plus_extra" not in codes
        assert "brand_in_subdomain" not in codes


# --------------------------------------------------------------------------- #
# Score boundaries and label thresholds
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "score,label",
    [
        (0, "Low"),
        (24, "Low"),
        (25, "Medium"),
        (49, "Medium"),
        (50, "High"),
        (74, "High"),
        (75, "Critical"),
        (100, "Critical"),
    ],
)
def test_label_boundaries(score, label):
    assert _classify(score) == label


def test_clean_url_score_is_exactly_zero():
    assert analyze_url("https://www.example.com/").risk_score == 0


def test_every_finding_has_positive_points_and_a_reason():
    result = analyze_url("http://paypal.com.example.org/secure-login")
    assert result.findings
    for finding in result.findings:
        assert finding.points > 0
        assert finding.title
        assert finding.description


def test_score_equals_sum_of_findings_and_is_capped():
    result = analyze_url("http://paypal.com@192.168.0.1:8080/secure-login-verify")
    total = sum(f.points for f in result.findings)
    assert result.risk_score == min(100, total)

