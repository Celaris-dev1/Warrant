"""Python SDK for Warrant: route every tool call through the PEP.

    agent = Agent(broker_url, pep_url)
    agent.attest("planner", secret)
    agent.token = minted_token

    @wrap_tool(agent, "fs.read", resource=lambda path: f"repo/{path}")
    def read_file(path):  # body never runs locally; the PEP forwards to the real tool
        ...

Standard library only.
"""
from __future__ import annotations

import functools
import inspect
import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

__all__ = ["Agent", "Admin", "WarrantError", "Denied", "wrap_tool"]


class WarrantError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"warrant: {status}: {message}")
        self.status = status
        self.message = message


class Denied(WarrantError):
    """The broker or PEP refused the request (401/403)."""


def _request(method: str, url: str, body: Any = None, headers: Optional[Dict[str, str]] = None, timeout: float = 30) -> Any:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        if v:
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            msg = json.loads(raw).get("error", raw.decode())
        except Exception:
            msg = raw.decode(errors="replace")
        cls = Denied if e.code in (401, 403) else WarrantError
        raise cls(e.code, msg) from None
    return json.loads(raw) if raw else None


class Agent:
    """One workload instance: its identity (JWT-SVID) and capability token."""

    def __init__(self, broker_url: str, pep_url: str, timeout: float = 30):
        self.broker_url = broker_url.rstrip("/")
        self.pep_url = pep_url.rstrip("/")
        self.timeout = timeout
        self.svid: str = ""
        self.spiffe_id: str = ""
        self.token: str = ""
        self.token_id: str = ""
        self._approvals: Dict[str, str] = {}

    def attest(self, workload: str, secret: str, instance: str = "") -> str:
        out = _request("POST", self.broker_url + "/v1/identity",
                       {"workload": workload, "secret": secret, "instance": instance}, timeout=self.timeout)
        self.svid, self.spiffe_id = out["svid"], out["spiffe_id"]
        return self.spiffe_id

    def mint_root(self, admin_token: str, human: str, scopes: List[dict], ttl_seconds: int = 300, max_calls: int = 0) -> dict:
        out = _request("POST", self.broker_url + "/v1/tokens",
                       {"svid": self.svid, "human": human, "scopes": scopes, "ttl_seconds": ttl_seconds, "max_calls": max_calls},
                       {"Authorization": "Bearer " + admin_token}, self.timeout)
        self.token, self.token_id = out["token"], out["claims"]["jti"]
        return out

    def delegate(self, child: "Agent", scopes: List[dict], ttl_seconds: int = 60, max_calls: int = 0) -> dict:
        out = _request("POST", self.broker_url + "/v1/tokens/delegate",
                       {"parent_token": self.token, "parent_svid": self.svid, "child_svid": child.svid,
                        "scopes": scopes, "ttl_seconds": ttl_seconds, "max_calls": max_calls}, timeout=self.timeout)
        child.token, child.token_id = out["token"], out["claims"]["jti"]
        return out

    def use_approval(self, tool: str, approval: str) -> None:
        self._approvals[tool] = approval

    def call(self, tool: str, resource: str, args: Optional[dict] = None) -> Any:
        headers = {"Authorization": "Bearer " + self.token, "X-Warrant-SVID": self.svid,
                   "X-Warrant-Approval": self._approvals.pop(tool, "")}
        return _request("POST", f"{self.pep_url}/call/{tool}", {"resource": resource, "args": args or {}}, headers, self.timeout)


class Admin:
    def __init__(self, broker_url: str, admin_token: str):
        self.broker_url = broker_url.rstrip("/")
        self._h = {"Authorization": "Bearer " + admin_token}

    def register_workload(self, name: str, secret: str) -> None:
        _request("POST", self.broker_url + "/v1/workloads", {"name": name, "secret": secret}, self._h)

    def approve(self, token_id: str, approver: str, tool: str, resource: str, args: Optional[dict] = None) -> str:
        out = _request("POST", self.broker_url + "/v1/approvals",
                       {"token_id": token_id, "approver": approver,
                        "call": {"tool": tool, "resource": resource, "args": args or {}}}, self._h)
        return out["approval"]

    def revoke(self, token_id: str, reason: str = "revoked") -> None:
        _request("POST", f"{self.broker_url}/v1/tokens/{token_id}/revoke", {"reason": reason}, self._h)

    def blast_radius(self, token_id: str) -> dict:
        return _request("GET", f"{self.broker_url}/v1/tokens/{token_id}/blast-radius", None, self._h)


def wrap_tool(agent: Agent, tool: str, resource: Callable[..., str]) -> Callable[[Callable], Callable]:
    """Decorator: replace a tool function with one that calls it through the PEP.

    The wrapped function's bound arguments become the call ``args``;
    ``resource`` receives the same arguments and returns the resource string.
    The original body is never executed in-process: authority is enforced by
    the PEP, which forwards to the real tool.
    """

    def deco(fn: Callable) -> Callable:
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*a, **kw):
            bound = sig.bind(*a, **kw)
            bound.apply_defaults()
            return agent.call(tool, resource(*a, **kw), dict(bound.arguments))

        wrapper.__warrant_tool__ = tool  # type: ignore[attr-defined]
        return wrapper

    return deco
