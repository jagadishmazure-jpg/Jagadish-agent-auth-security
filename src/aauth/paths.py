"""Resolved paths used by the package and the CLI."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"
EVIDENCE = ROOT / "evidence"
DOCS = ROOT / "docs"
