"""Agent auth security: JWT vs sessions, hardened tokens, OAuth 2.1, OBO, MCP/A2A.

Everything runs offline for a fictional company, Northglass Financial Services.
Nothing is deployed.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"
VERSION = "0.1.0"
