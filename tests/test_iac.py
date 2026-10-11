"""Infrastructure and workflow structure, checked offline."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github/workflows"
TF = ROOT / "infra/terraform"
BICEP = ROOT / "infra/bicep"
SHA_PIN = re.compile(r"uses:\s*[\w./-]+@[0-9a-f]{40}\b")
BUILT_IN_ROLES = {"4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User"}


def tf() -> str:
    return "\n".join(p.read_text() for p in sorted(TF.glob("*.tf")))


def bicep() -> str:
    return "\n".join(p.read_text() for p in sorted(BICEP.rglob("*.bicep")))


def wf(name):
    return yaml.safe_load((WF / name).read_text())


def test_stack_has_standard_files():
    for f in (
        "versions.tf",
        "providers.tf",
        "backend.tf",
        "variables.tf",
        "main.tf",
        "outputs.tf",
        ".tflint.hcl",
        "tests/plan.tftest.hcl",
        "envs/dev.tfvars",
        "envs/prod.tfvars",
    ):
        assert (TF / f).exists(), f


def test_no_secrets_in_terraform():
    text = tf().lower()
    for word in ("client_secret", "access_key =", "secret_key", "private_key", "account_key"):
        assert word not in text, word


def test_environment_validated():
    assert re.search(r'contains\(\["dev", "prod"\], var.environment\)', (TF / "variables.tf").read_text())


def test_terraform_tests_use_mocks():
    t = (TF / "tests/plan.tftest.hcl").read_text()
    assert "mock_provider" in t and 'run "dev_defaults"' in t and "expect_failures" in t


def test_azure_controls():
    t = tf()
    assert "enable_rbac_authorization  = true" in t or "enable_rbac_authorization = true" in t
    assert "local_authentication_enabled = false" in t or "local_authentication_enabled  = false" in t
    assert "validate-jwt" in t
    assert "azuread_application" in t
    assert "azurerm_key_vault" in t and "azurerm_api_management" in t


def test_bicep_mirrors_controls():
    b = bicep()
    assert "enableRbacAuthorization: true" in b
    assert "disableLocalAuth: true" in b
    assert "validate-azure-ad-token" in b
    guids = set(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", b, re.I))
    assert "4633458b-17de-408a-b874-0445c86b69e6" in guids


def test_every_checkov_skip_has_a_reason():
    lines = [ln for ln in (ROOT / ".checkov.yaml").read_text().splitlines() if ln.strip().startswith("- CKV")]
    assert lines and all("#" in ln and len(ln.split("#", 1)[1].strip()) > 20 for ln in lines)


@pytest.mark.parametrize("name", sorted(p.name for p in WF.glob("*.yml")))
def test_workflow_hardening(name):
    d = wf(name)
    assert d["permissions"] == {"contents": "read"}
    text = (WF / name).read_text()
    for line in text.splitlines():
        if "uses:" in line and not line.strip().startswith("#"):
            assert SHA_PIN.search(line), f"{name}: {line.strip()}"
    for bad in ("client-secret", "AZURE_CLIENT_SECRET", "credentials_json"):
        assert bad not in text


def test_ci_steps():
    text = (WF / "ci.yml").read_text()
    for step in ("pytest -q", "aauth gate", "render_docs.py --check", "gitleaks", "sbom-action", "bicep build", "ruff format --check"):
        assert step in text, step


def test_deploy_gated_oidc():
    jobs = wf("deploy.yml")["jobs"]
    for name in ("deploy-dev", "deploy-prod"):
        assert "vars.DEPLOY_ENABLED == 'true'" in jobs[name]["if"]
        assert jobs[name]["permissions"]["id-token"] == "write"
    assert jobs["deploy-dev"]["environment"] == "dev"


def test_teardown_needs_confirm():
    job = wf("teardown.yml")["jobs"]["teardown"]
    assert "vars.DEPLOY_ENABLED == 'true'" in job["if"] and "inputs.confirm == inputs.environment" in job["if"]


def test_codeql_python_and_actions():
    text = (WF / "codeql.yml").read_text()
    assert "python" in text and "actions" in text


def test_dependabot():
    d = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    eco = {u["package-ecosystem"] for u in d["updates"]}
    assert {"pip", "github-actions", "terraform"} <= eco


def test_iac_summary():
    from aauth import iac

    t = iac.terraform()
    assert t["resources"] > 5 and t["test_runs"] >= 2
    assert all(t["controls"].values()), t["controls"]
    assert all(iac.bicep()["controls"].values())
    assert iac.controls_ok()
    wf = {w["workflow"]: w for w in iac.workflows()}
    assert all(w["read_only"] and w["pinned"] == w["actions"] for w in wf.values())
