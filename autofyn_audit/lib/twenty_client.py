# Twenty CRM Security Audit — shared GraphQL client
# Pinned commit: fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8
# Server image: twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad
# stdlib only — no third-party dependencies
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from typing import Any
from uuid import uuid4

DEFAULT_BASE_URL = "http://172.20.0.4:3000"
ATTACKER_PASSWORD = "Audit#Secure!2024xX"
GRAPHQL_TIMEOUT_SECONDS = 30

SIGNUP_MUTATION = """
mutation SignUp($email: String!, $password: String!) {
  signUp(email: $email, password: $password) {
    tokens {
      accessOrWorkspaceAgnosticToken { token }
    }
    availableWorkspaces {
      availableWorkspacesForSignIn { id loginToken }
      availableWorkspacesForSignUp { id loginToken }
    }
  }
}
"""

GET_AUTH_TOKENS_MUTATION = """
mutation GetAuthTokens($loginToken: String!, $origin: String!) {
  getAuthTokensFromLoginToken(loginToken: $loginToken, origin: $origin) {
    tokens {
      accessOrWorkspaceAgnosticToken { token }
      refreshToken { token }
    }
  }
}
"""

SIGN_UP_IN_NEW_WORKSPACE_MUTATION = """
mutation SignUpInNewWorkspace {
  signUpInNewWorkspace {
    loginToken { token }
    workspace { id workspaceUrls { subdomainUrl } }
  }
}
"""

ACTIVATE_WORKSPACE_MUTATION = """
mutation ActivateWorkspace($displayName: String!) {
  activateWorkspace(data: { displayName: $displayName }) { id activationStatus }
}
"""


class TwentyClientError(Exception):
    """Raised when a GraphQL call returns errors or a non-200 status."""


class TwentyClient:
    def __init__(self, base_url: str | None = None) -> None:
        env_url = os.environ.get("TARGET_BASE_URL")
        self.base_url = (base_url or env_url or DEFAULT_BASE_URL).rstrip("/")
        self.graphql_endpoint = f"{self.base_url}/graphql"

    # ------------------------------------------------------------------
    # Low-level HTTP
    # ------------------------------------------------------------------

    def _graphql(
        self,
        query: str,
        variables: dict[str, Any],
        token: str | None = None,
    ) -> dict[str, Any]:
        payload = json.dumps({"query": query, "variables": variables}).encode()
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": self.base_url,
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        req = urllib.request.Request(
            self.graphql_endpoint,
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(
                req, timeout=GRAPHQL_TIMEOUT_SECONDS, context=ctx
            ) as resp:
                body = resp.read().decode()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            # GraphQL errors sometimes arrive with 4xx status — still parse JSON
            try:
                return json.loads(body)
            except Exception:
                raise TwentyClientError(
                    f"HTTP {exc.code} from server; body: {body[:500]}"
                ) from exc
        except urllib.error.URLError as exc:
            raise TwentyClientError(f"Network error: {exc.reason}") from exc

        try:
            return json.loads(body)
        except Exception as exc:
            raise TwentyClientError(f"Invalid JSON response: {body[:500]}") from exc

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def signup(self, email: str, password: str) -> dict[str, Any]:
        """Sign up a new user. Returns dict with agnosticToken and availableWorkspaces."""
        resp = self._graphql(SIGNUP_MUTATION, {"email": email, "password": password})
        if resp.get("errors"):
            raise TwentyClientError(
                f"signUp failed: {extract_error_messages(resp)}"
            )
        data = resp.get("data", {}).get("signUp", {})
        if not data:
            raise TwentyClientError(f"signUp returned no data: {resp}")
        agnostic_token = (
            data.get("tokens", {})
            .get("accessOrWorkspaceAgnosticToken", {})
            .get("token")
        )
        if not agnostic_token:
            raise TwentyClientError(f"signUp: no agnosticToken in response: {resp}")
        available_ws = (
            data.get("availableWorkspaces", {})
        )
        sign_in_workspaces = available_ws.get("availableWorkspacesForSignIn", [])
        sign_up_workspaces = available_ws.get("availableWorkspacesForSignUp", [])
        return {
            "agnosticToken": agnostic_token,
            "availableWorkspacesForSignIn": sign_in_workspaces,
            "availableWorkspacesForSignUp": sign_up_workspaces,
        }

    def get_access_token(self, login_token: str, origin: str) -> str:
        """Exchange a login token for a workspace-scoped access token.

        Retries with http://localhost:3000 origin fallback if the first attempt
        fails with a workspace/domain validation error (multi-workspace mode).
        """
        origins_to_try = [origin]
        if origin != "http://localhost:3000":
            origins_to_try.append("http://localhost:3000")

        last_error: str = ""
        for attempt_origin in origins_to_try:
            resp = self._graphql(
                GET_AUTH_TOKENS_MUTATION,
                {"loginToken": login_token, "origin": attempt_origin},
            )
            errors = resp.get("errors", [])
            if errors:
                msgs = extract_error_messages(resp)
                if "EMAIL_NOT_VERIFIED" in msgs or "email" in msgs.lower():
                    raise TwentyClientError(
                        "PRECONDITION: email verification required. "
                        "IS_EMAIL_VERIFICATION_REQUIRED must be false for this PoC."
                    )
                last_error = msgs
                # Try next origin on workspace/domain errors
                continue
            token = (
                resp.get("data", {})
                .get("getAuthTokensFromLoginToken", {})
                .get("tokens", {})
                .get("accessOrWorkspaceAgnosticToken", {})
                .get("token")
            )
            if not token:
                raise TwentyClientError(
                    f"getAuthTokensFromLoginToken: no access token in response: {resp}"
                )
            return token

        raise TwentyClientError(
            f"getAuthTokensFromLoginToken failed with all origins. Last error: {last_error}"
        )

    def sign_up_in_new_workspace(self, agnostic_token: str) -> dict[str, Any]:
        """Create a new workspace; the caller becomes admin. Bearer = agnostic token."""
        resp = self._graphql(
            SIGN_UP_IN_NEW_WORKSPACE_MUTATION, {}, token=agnostic_token
        )
        if resp.get("errors"):
            raise TwentyClientError(
                f"signUpInNewWorkspace failed: {extract_error_messages(resp)}"
            )
        data = resp.get("data", {}).get("signUpInNewWorkspace", {})
        if not data:
            raise TwentyClientError(f"signUpInNewWorkspace returned no data: {resp}")
        login_token = data.get("loginToken", {}).get("token")
        workspace_id = data.get("workspace", {}).get("id")
        if not login_token:
            raise TwentyClientError(
                f"signUpInNewWorkspace: no loginToken in response: {resp}"
            )
        return {"loginToken": login_token, "workspaceId": workspace_id}

    def activate_workspace(self, access_token: str, display_name: str) -> dict[str, Any]:
        """Transition a PENDING_CREATION workspace to active."""
        resp = self._graphql(
            ACTIVATE_WORKSPACE_MUTATION,
            {"displayName": display_name},
            token=access_token,
        )
        if resp.get("errors"):
            raise TwentyClientError(
                f"activateWorkspace failed: {extract_error_messages(resp)}"
            )
        return resp.get("data", {}).get("activateWorkspace", {})

    # ------------------------------------------------------------------
    # Bootstrap
    # ------------------------------------------------------------------

    def bootstrap_attacker(
        self,
        email: str | None = None,
        password: str | None = None,
        want_admin: bool = False,
    ) -> dict[str, Any]:
        """Register a fresh attacker account and return credentials + token.

        Returns dict with keys:
          access_token, workspace_id, email, password, created_via, agnostic_token
        """
        if not email:
            email = f"audit-{uuid4().hex[:10]}@audit-evil.example.com"
        if not password:
            password = ATTACKER_PASSWORD

        print(f"[bootstrap] Registering attacker: {email}", file=sys.stderr)
        try:
            signup_result = self.signup(email, password)
        except TwentyClientError as exc:
            if "already exists" in str(exc).lower() or "user_already_exists" in str(exc).lower():
                # Regenerate and retry once
                email = f"audit-{uuid4().hex[:10]}@audit-evil.example.com"
                print(
                    f"[bootstrap] Email collision — retrying with: {email}",
                    file=sys.stderr,
                )
                signup_result = self.signup(email, password)
            else:
                raise

        agnostic_token = signup_result["agnosticToken"]
        sign_in_workspaces = signup_result["availableWorkspacesForSignIn"]

        if want_admin:
            # Always create a fresh workspace to guarantee admin role
            print("[bootstrap] Creating new workspace for admin role...", file=sys.stderr)
            new_ws = self.sign_up_in_new_workspace(agnostic_token)
            login_token = new_ws["loginToken"]
            workspace_id = new_ws.get("workspaceId", "unknown")
            access_token = self.get_access_token(login_token, self.base_url)
            # Activate workspace (required before WORKFLOWS permission is enforced)
            try:
                self.activate_workspace(access_token, "Audit-Workspace")
                print("[bootstrap] Workspace activated.", file=sys.stderr)
            except TwentyClientError as exc:
                print(
                    f"[bootstrap] activateWorkspace warning (may already be active): {exc}",
                    file=sys.stderr,
                )
            created_via = "signUpInNewWorkspace+activateWorkspace"
        else:
            # Use the default workspace membership (member role)
            if sign_in_workspaces and sign_in_workspaces[0].get("loginToken"):
                login_token = sign_in_workspaces[0]["loginToken"]
                workspace_id = sign_in_workspaces[0].get("id", "unknown")
                print(
                    f"[bootstrap] Joining existing workspace {workspace_id} as member.",
                    file=sys.stderr,
                )
            else:
                # No existing workspace with a login token — create one
                print(
                    "[bootstrap] No existing workspace login token; creating new workspace.",
                    file=sys.stderr,
                )
                new_ws = self.sign_up_in_new_workspace(agnostic_token)
                login_token = new_ws["loginToken"]
                workspace_id = new_ws.get("workspaceId", "unknown")
                try:
                    # Need temporary access token to activate
                    temp_access = self.get_access_token(login_token, self.base_url)
                    self.activate_workspace(temp_access, "Audit-Member-Workspace")
                    login_token_val = login_token  # re-exchange after activation
                    access_token_tmp = self.get_access_token(login_token_val, self.base_url)
                    return {
                        "access_token": access_token_tmp,
                        "workspace_id": workspace_id,
                        "email": email,
                        "password": password,
                        "agnostic_token": agnostic_token,
                        "created_via": "signUpInNewWorkspace+activateWorkspace(member-fallback)",
                    }
                except TwentyClientError as exc:
                    print(f"[bootstrap] workspace creation fallback error: {exc}", file=sys.stderr)
                    raise
            created_via = "signUp(defaultWorkspace)"
            access_token = self.get_access_token(login_token, self.base_url)

        return {
            "access_token": access_token,
            "workspace_id": workspace_id,
            "email": email,
            "password": password,
            "agnostic_token": agnostic_token,
            "created_via": created_via,
        }


# ------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------

def extract_error_messages(resp: dict[str, Any]) -> str:
    """Extract all error messages from a GraphQL response into a single string."""
    errors = resp.get("errors", [])
    if not errors:
        return ""
    parts: list[str] = []
    for err in errors:
        msg = err.get("message", "")
        code = (err.get("extensions") or {}).get("code", "")
        if code:
            parts.append(f"{code}: {msg}")
        else:
            parts.append(msg)
    return " | ".join(parts)


def load_config_env(config_path: str = "/home/agentuser/repo/autofyn_audit/config.env") -> None:
    """Load key=value pairs from config.env into os.environ (idempotent)."""
    try:
        with open(config_path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())
    except FileNotFoundError:
        pass  # config.env not yet created; rely on defaults
