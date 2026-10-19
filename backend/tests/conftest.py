"""Shared test configuration.

The suite must be hermetic. A developer shell that exports ``PHISHGUARD_*`` or
``VIRUSTOTAL_API_KEY`` (or a stray ``backend/.env``) must not change what the
tests observe — and, more importantly, must never push the tests into making
real outbound VirusTotal lookups with a host-provided key.

Each test can still set these variables explicitly via ``monkeypatch.setenv``;
only host-supplied values are removed.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clear_ambient_configuration(monkeypatch):
    """Remove host-supplied PhishGuard/VirusTotal variables for every test."""
    for key in list(os.environ):
        if key.startswith("PHISHGUARD_") or key == "VIRUSTOTAL_API_KEY":
            monkeypatch.delenv(key, raising=False)
