import time

import httpx
import msal

GRAPH_BASE = "https://graph.microsoft.com"
SCOPES = ["https://graph.microsoft.com/.default"]


class GraphClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self._app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        self._http = httpx.Client(timeout=60)
        self._token: str | None = None

    def _acquire_token(self) -> str:
        result = self._app.acquire_token_for_client(scopes=SCOPES)
        if "access_token" not in result:
            raise RuntimeError(
                f"Token acquisition failed: {result.get('error_description', result.get('error'))}"
            )
        return result["access_token"]

    def _headers(self) -> dict:
        if not self._token:
            self._token = self._acquire_token()
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def get(self, path: str, params: dict | None = None, version: str = "v1.0") -> dict:
        url = f"{GRAPH_BASE}/{version}{path}"
        return self._fetch(url, params=params)

    def get_all(
        self, path: str, params: dict | None = None, version: str = "v1.0"
    ) -> list[dict]:
        """Fetch all pages of a collection, following @odata.nextLink."""
        url = f"{GRAPH_BASE}/{version}{path}"
        results: list[dict] = []
        first = True
        while url:
            data = self._fetch(url, params=params if first else None)
            first = False
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return results

    def delete(self, path: str, version: str = "v1.0") -> None:
        url = f"{GRAPH_BASE}/{version}{path}"
        resp = self._request("DELETE", url)
        if resp.status_code == 404:
            return
        resp.raise_for_status()

    def patch(self, path: str, body: dict, version: str = "v1.0") -> dict:
        url = f"{GRAPH_BASE}/{version}{path}"
        resp = self._request("PATCH", url, json=body)
        resp.raise_for_status()
        return resp.json()

    def _request(self, method: str, url: str, **kwargs) -> "httpx.Response":
        while True:
            resp = self._http.request(method, url, headers=self._headers(), **kwargs)
            if resp.status_code == 401:
                self._token = self._acquire_token()
                resp = self._http.request(method, url, headers=self._headers(), **kwargs)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "10"))
                time.sleep(retry_after)
                continue
            return resp

    def _fetch(self, url: str, params: dict | None = None) -> dict:
        resp = self._request("GET", url, params=params)
        resp.raise_for_status()
        return resp.json()
