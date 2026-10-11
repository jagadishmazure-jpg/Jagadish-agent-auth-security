"""Entra adapter is importable and documents app registration; never talks to a tenant."""

from aauth.entra import APP_REGISTRATION_NOTES, EntraAdapter, EntraConfig, from_env


def test_entra_config_and_notes():
    cfg = from_env()
    assert "northglass" in cfg.tenant_id or cfg.tenant_id.endswith("a1")
    assert "app roles" in APP_REGISTRATION_NOTES.lower() or "app roles" in APP_REGISTRATION_NOTES
    assert "PKCE" in APP_REGISTRATION_NOTES
    adapter = EntraAdapter(EntraConfig(tenant_id="t", client_id="c"))
    assert adapter.config.authority_url.endswith("/t")
