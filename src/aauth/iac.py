"""Summarise infrastructure controls for the CLI and docs (offline, no cloud)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "infra" / "terraform"
BICEP = ROOT / "infra" / "bicep"
WF = ROOT / ".github" / "workflows"
SHA_PIN = re.compile(r"uses:\s*[\w./-]+@[0-9a-f]{40}\b")


def terraform() -> dict:
    text = "\n".join(p.read_text() for p in sorted(TF.glob("*.tf"))) if TF.exists() else ""
    return {
        "resources": len(re.findall(r'^resource\s+"', text, re.M)),
        "controls": {
            "key_vault": "azurerm_key_vault" in text,
            "entra_apps": "azuread_application" in text,
            "apim": "azurerm_api_management" in text,
            "log_analytics": "azurerm_log_analytics_workspace" in text,
            "no_secrets": "client_secret" not in text.lower() and "account_key" not in text.lower(),
            "rbac_kv": "rbac_authorization_enabled" in text or "rbac_authorization_enabled  = true" in text,
        },
        "test_runs": (TF / "tests" / "plan.tftest.hcl").read_text().count('run "') if (TF / "tests" / "plan.tftest.hcl").exists() else 0,
    }


def bicep() -> dict:
    text = "\n".join(p.read_text() for p in sorted(BICEP.rglob("*.bicep"))) if BICEP.exists() else ""
    return {
        "files": len(list(BICEP.rglob("*.bicep"))) if BICEP.exists() else 0,
        "controls": {
            "key_vault": "Microsoft.KeyVault" in text,
            "apim": "Microsoft.ApiManagement" in text,
            "log_analytics": "Microsoft.OperationalInsights" in text,
            "validate_token": "validate-azure-ad-token" in text or "validate-jwt" in text,
        },
    }


def workflows() -> list[dict]:
    out = []
    if not WF.exists():
        return out
    for p in sorted(WF.glob("*.yml")):
        d = yaml.safe_load(p.read_text())
        text = p.read_text()
        actions = [ln for ln in text.splitlines() if "uses:" in ln and not ln.strip().startswith("#")]
        pinned = [ln for ln in actions if SHA_PIN.search(ln)]
        out.append(
            {
                "workflow": p.name,
                "read_only": d.get("permissions") == {"contents": "read"},
                "actions": len(actions),
                "pinned": len(pinned),
                "gated": text.count("DEPLOY_ENABLED"),
                "oidc": text.count("id-token"),
            }
        )
    return out


def controls_ok() -> bool:
    t = terraform()
    return all(t["controls"].values()) and t["resources"] > 0


def checkov_skips() -> int:
    p = ROOT / ".checkov.yaml"
    if not p.exists():
        return 0
    return sum(1 for ln in p.read_text().splitlines() if ln.strip().startswith("- CKV"))
