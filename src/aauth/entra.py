"""Entra ID / MSAL adapter.

Written against MSAL's public API and documented with app-registration steps.
Never run against a real tenant from this repository. Offline tests use a stub
that returns tokens from the local OAuth server instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass
class EntraConfig:
    tenant_id: str
    client_id: str
    # Public client (PKCE) has no secret; confidential clients use a federated credential in Azure.
    client_credential: str | None = None
    authority: str | None = None
    redirect_uri: str = "https://loans.northglass.example/callback"
    api_scope: str = "api://northglass-loan-api/.default"

    @property
    def authority_url(self) -> str:
        return self.authority or f"https://login.microsoftonline.com/{self.tenant_id}"


APP_REGISTRATION_NOTES = """
Entra app registration (documented, not applied from this repo):

1. Register "northglass-loan-api" as a single-tenant app. Expose an API with scopes
   loans.read, loans.write, docs.read, credit.read. Create app roles loan.officer,
   loan.underwriter, compliance.officer, it.admin, agent.loan_assistant.
2. Register "northglass-loan-portal" as a public client (SPA) with redirect URI
   https://loans.northglass.example/callback. Enable auth code + PKCE. Grant the API scopes.
3. Register each agent as an application with a federated credential (no secret) and
   assign the agent.* app roles. For OBO, add knownClientApplications and expose
   the agent as an authorized client of the API.
4. Conditional Access: require MFA for interactive users; block legacy auth; require
   compliant device for admin roles. Agents use workload identity, not user CA.
5. APIM validate-azure-ad-token policy pins the tenant, audience and required roles.
"""


class EntraAdapter:
    """Thin wrapper. Instantiating with real credentials is never done in CI."""

    def __init__(self, config: EntraConfig) -> None:
        self.config = config
        self._app: Any = None

    def _msal_app(self):
        if self._app is None:
            import msal  # optional extra

            if self.config.client_credential:
                self._app = msal.ConfidentialClientApplication(
                    self.config.client_id,
                    authority=self.config.authority_url,
                    client_credential=self.config.client_credential,
                )
            else:
                self._app = msal.PublicClientApplication(self.config.client_id, authority=self.config.authority_url)
        return self._app

    def acquire_client_token(self) -> dict:  # pragma: no cover - needs a tenant
        app = self._msal_app()
        return app.acquire_token_for_client(scopes=[self.config.api_scope])

    def acquire_on_behalf_of(self, user_assertion: str, scopes: list[str]) -> dict:  # pragma: no cover
        app = self._msal_app()
        return app.acquire_token_on_behalf_of(user_assertion=user_assertion, scopes=scopes)


def from_env() -> EntraConfig:
    return EntraConfig(
        tenant_id=os.environ.get("AAUTH_ENTRA_TENANT", "00000000-0000-0000-0000-0000000000a1"),
        client_id=os.environ.get("AAUTH_ENTRA_CLIENT", "00000000-0000-0000-0000-0000000000b2"),
    )
