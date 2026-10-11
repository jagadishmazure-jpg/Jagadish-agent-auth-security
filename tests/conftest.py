"""Shared fixtures: key ring, store, company principals."""

from __future__ import annotations

import pytest

from aauth.company import COMPANY
from aauth.keys import KeyRing
from aauth.store import AuthStore


@pytest.fixture
def ring():
    return KeyRing.create(COMPANY.issuer, seed=42)


@pytest.fixture
def store():
    return AuthStore.memory()
