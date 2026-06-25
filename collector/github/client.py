import time

import httpx

GITHUB_BASE = "https://api.github.com"


class GitHubClient:
    def __init__(self, pat: str):
        self._headers = {
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._http = httpx.Client(timeout=30)

    def get(self, path: str, params: dict | None = None) -> dict:
        url = f"{GITHUB_BASE}{path}"
        return self._raw(url, params).json()

    def get_all(self, path: str, params: dict | None = None) -> list[dict]:
        """Fetch all pages via Link header pagination."""
        url = f"{GITHUB_BASE}{path}"
        p = dict(params or {})
        p.setdefault("per_page", 100)
        results: list[dict] = []
        first = True
        while url:
            resp = self._raw(url, params=p if first else None)
            first = False
            data = resp.json()
            if isinstance(data, list):
                results.extend(data)
            else:
                results.extend(data.get("installations", data.get("value", [])))
            url = _next_link(resp.headers.get("Link", ""))
        return results

    def delete(self, path: str) -> None:
        url = f"{GITHUB_BASE}{path}"
        while True:
            resp = self._http.delete(url, headers=self._headers)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "10"))
                time.sleep(retry_after)
                continue
            if resp.status_code == 404:
                return
            resp.raise_for_status()
            return

    def _raw(self, url: str, params: dict | None = None) -> httpx.Response:
        while True:
            resp = self._http.get(url, headers=self._headers, params=params)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "10"))
                time.sleep(retry_after)
                continue
            if resp.status_code == 403:
                remaining = resp.headers.get("X-RateLimit-Remaining", "1")
                if remaining == "0":
                    reset = int(resp.headers.get("X-RateLimit-Reset", str(int(time.time()) + 60)))
                    time.sleep(max(1, reset - int(time.time())) + 1)
                    continue
            resp.raise_for_status()
            return resp


def _next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            return part.split(";")[0].strip().strip("<>")
    return None
