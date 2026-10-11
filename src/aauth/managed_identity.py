"""Service-to-service auth with managed identity (no secrets).

Offline, `OfflineCredential` returns a platform-signed token for a given scope.
The Azure path uses `DefaultAzureCredential` and is written but never run against
a tenant from this repository.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from aauth import jwt_tokens
from aauth.keys import KeyRing
from aauth.store import AuthStore


@dataclass
class OfflineCredential:
    ring: KeyRing
    store: AuthStore
    principal_id: str = "mi-northglass-api"

    def get_token(self, *scopes: str) -> jwt_tokens.AccessToken:
        audience = scopes[0] if scopes else "api://default"
        return jwt_tokens.issue(self.ring, sub=self.principal_id, audience=audience, scopes=list(scopes), store=self.store)


def get_credential(ring: KeyRing, store: AuthStore):
    if os.environ.get("AAUTH_MI", "offline") != "azure":
        return OfflineCredential(ring=ring, store=store)
    from azure.identity import DefaultAzureCredential  # pragma: no cover

    return DefaultAzureCredential()  # pragma: no cover
