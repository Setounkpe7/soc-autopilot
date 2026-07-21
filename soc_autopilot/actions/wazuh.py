import time

import httpx
import structlog

from soc_autopilot.config import get_settings
from soc_autopilot.engine.registry import action

log = structlog.get_logger()


class WazuhClient:
    """Client API Wazuh avec cache et refresh anticipé du token JWT."""

    def __init__(self) -> None:
        s = get_settings()
        self._base = s.wazuh_api_url.rstrip("/")
        self._auth = (s.wazuh_api_user, s.wazuh_api_password)
        self._verify = s.wazuh_verify_tls
        self._token: str | None = None
        self._expires_at: float = 0.0

    async def _get_token(self) -> str:
        # Refresh 60 s AVANT expiration (le token Wazuh dure 900 s)
        if self._token and time.time() < self._expires_at - 60:
            return self._token
        async with httpx.AsyncClient(verify=self._verify, timeout=10.0) as c:
            r = await c.post(
                f"{self._base}/security/user/authenticate?raw=true", auth=self._auth
            )
            r.raise_for_status()
            self._token = r.text.strip()
            self._expires_at = time.time() + 900
        return self._token

    async def _request(self, method: str, path: str, **kw) -> dict:
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(verify=self._verify, timeout=15.0) as c:
            r = await c.request(method, f"{self._base}{path}", headers=headers, **kw)
            if r.status_code == 401:  # token périmé malgré le cache
                self._token = None
                token = await self._get_token()
                r = await c.request(
                    method,
                    f"{self._base}{path}",
                    headers={"Authorization": f"Bearer {token}"},
                    **kw,
                )
            r.raise_for_status()
            return r.json()

    async def agent_id(self, name: str) -> str:
        data = await self._request("GET", "/agents", params={"name": name})
        items = data["data"]["affected_items"]
        if not items:
            raise ValueError(f"Agent introuvable: {name}")
        return items[0]["id"]

    async def agent_context(self, name: str) -> dict:
        data = await self._request("GET", "/agents", params={"name": name})
        a = data["data"]["affected_items"][0]
        return {
            "id": a["id"],
            "ip": a.get("ip"),
            "os": a.get("os", {}).get("name"),
            "status": a["status"],
            "last_keep_alive": a.get("lastKeepAlive"),
            "groups": a.get("group", []),
        }

    async def active_response(
        self, command: str, agent_id: str, args: list[str] | None = None
    ) -> dict:
        return await self._request(
            "PUT",
            "/active-response",
            params={"agents_list": agent_id},
            json={"command": command, "arguments": args or []},
        )


# Client paresseux : instancié au PREMIER usage, pas à l'import — sinon importer
# ce module exigerait la config complète (get_settings) avant tout, ce qui casse
# les tests et le simple chargement du registre d'actions.
_client: WazuhClient | None = None


def _get_client() -> WazuhClient:
    global _client
    if _client is None:
        _client = WazuhClient()
    return _client


@action("wazuh.get_agent_context")
async def get_agent_context(params: dict, ctx) -> dict:
    return await _get_client().agent_context(params["agent"])


@action("wazuh.isolate_host")
async def isolate_host(params: dict, ctx) -> dict:
    agent = params["agent"]
    client = _get_client()
    aid = await client.agent_id(agent)
    res = await client.active_response("firewall-drop0", aid, [params.get("ip", "")])
    log.warning("host_isolated", agent=agent, agent_id=aid, execution=ctx.execution_id)
    return {"agent": agent, "agent_id": aid, "result": res.get("data", {})}


@action("wazuh.unisolate_host")
async def unisolate_host(params: dict, ctx) -> dict:
    client = _get_client()
    aid = await client.agent_id(params["agent"])
    res = await client.active_response("firewall-drop0", aid, ["-", "delete"])
    log.warning("host_unisolated", agent=params["agent"], execution=ctx.execution_id)
    return {"agent": params["agent"], "result": res.get("data", {})}
