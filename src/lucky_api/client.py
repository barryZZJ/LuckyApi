from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .errors import (
    LuckyAPIError,
    LuckyAuthenticationError,
    LuckyConfigError,
    LuckyResponseError,
)
from .types import StunRule, DDNS


@dataclass(frozen=True, slots=True)
class _LuckyConfig:
    host_url: str
    username: str
    password: str
    openToken: str


class LuckyClient:
    """Access selected Lucky dashboard APIs."""

    def __init__(self, *, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._config = None

    def load_config_from_dict(self, host_url: str, username: str, password: str, openToken: str) -> _LuckyConfig:
        if not all(isinstance(v, str) and v.strip() for v in (host_url, username, password, openToken)):
            raise LuckyConfigError("All configuration values must be non-empty strings")

        parsed_host = urlsplit(host_url)
        if parsed_host.scheme not in {"http", "https"} or not parsed_host.netloc:
            raise LuckyConfigError("Configuration value 'host_url' must be an HTTP(S) URL")

        self._config = _LuckyConfig(
            host_url=host_url.rstrip("/"),
            username=username,
            password=password,
            openToken=openToken,
        )

    def load_config(self, config_path: str | Path) -> _LuckyConfig:
        try:
            config_text = Path(config_path).read_text(encoding="utf-8")
        except OSError as exc:
            raise LuckyConfigError(
                f"Unable to read configuration: {config_path}"
            ) from exc

        try:
            config = json.loads(config_text)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LuckyConfigError("Configuration must contain valid JSON") from exc

        if not isinstance(config, dict):
            raise LuckyConfigError("Configuration must be a JSON object")

        values: dict[str, str] = {}
        for key in ("host_url", "username", "password", "openToken"):
            value = config.get(key)
            if not isinstance(value, str) or not value.strip():
                raise LuckyConfigError(
                    f"Configuration value {key!r} must be a non-empty string"
                )
            values[key] = value

        parsed_host = urlsplit(values["host_url"])
        if parsed_host.scheme not in {"http", "https"} or not parsed_host.netloc:
            raise LuckyConfigError(
                "Configuration value 'host_url' must be an HTTP(S) URL"
            )

        self._config = _LuckyConfig(
            host_url=values["host_url"].rstrip("/"),
            username=values["username"],
            password=values["password"],
            openToken=values["openToken"],
        )

    @staticmethod
    def _timestamp_ms() -> int:
        return int(time.time() * 1000)

    def get_stun_rules(self) -> list[StunRule]:
        """Return enabled Lucky STUN rules in dashboard order."""
        if self._config and self._config.openToken:
            token = self._config.openToken
        else:
            raise LuckyAuthenticationError("Call load_config() first to load configuration")

        try:
            response = requests.get(
                f"{self._config.host_url}/api/stunrulelist",
                params={"_": self._timestamp_ms()},
                headers={"openToken": token},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise LuckyAPIError("Lucky STUN request failed") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise LuckyResponseError(
                "Lucky STUN response was not valid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise LuckyResponseError("Lucky STUN response must be a JSON object")

        if payload.get("ret") != 0:
            message = payload.get("msg")
            detail = (
                message if isinstance(message, str) and message else "unknown error"
            )
            raise LuckyAPIError(f"Lucky STUN request failed: {detail}")

        items = payload.get("list")
        if not isinstance(items, list):
            raise LuckyResponseError(
                "Lucky STUN response field 'list' must be a list"
            )

        rules: list[StunRule] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise LuckyResponseError(
                    f"Lucky STUN list item {index} must be a JSON object"
                )
            if item.get("Enable") is not True:
                continue

            required_fields = ("Name", "StunType", "StunLocalAddr", "PublicAddr")
            for field in required_fields:
                if not isinstance(item.get(field), str):
                    raise LuckyResponseError(
                        f"Enabled Lucky STUN list item {index} field {field!r} "
                        "must be a string"
                    )

            public_addr = item["PublicAddr"]
            try:
                ip_text, port_text = public_addr.rsplit(":", 1)
                public_ip = ip_text if ip_text else None
                parsed_port = int(port_text) if port_text else None
                public_port = (
                    parsed_port
                    if parsed_port is not None and 0 <= parsed_port <= 65535
                    else None
                )
            except (ValueError, TypeError):
                public_ip = None
                public_port = None

            rules.append(
                {
                    "Name": item["Name"],
                    "StunType": item["StunType"],
                    "StunLocalAddr": item["StunLocalAddr"],
                    "PublicAddr": public_addr,
                    "PublicIp": public_ip,
                    "PublicPort": public_port,
                }
            )

        return rules

    def get_ddns_list(self) -> list[DDNS]:
        """Return enabled Lucky DDNS task in dashboard order."""
        if self._config and self._config.openToken:
            token = self._config.openToken
        else:
            raise LuckyAuthenticationError("Call load_config() first to load configuration")

        try:
            response = requests.get(
                f"{self._config.host_url}/api/ddnstasklist",
                params={"_": self._timestamp_ms()},
                headers={"openToken": token},
                timeout=self._timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise LuckyAPIError("Lucky DDNS request failed") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise LuckyResponseError(
                "Lucky DDNS response was not valid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise LuckyResponseError("Lucky DDNS response must be a JSON object")

        if payload.get("ret") != 0:
            message = payload.get("msg")
            detail = (
                message if isinstance(message, str) and message else "unknown error"
            )
            raise LuckyAPIError(f"Lucky DDNS request failed: {detail}")

        items = payload.get("data")
        if not isinstance(items, list):
            raise LuckyResponseError(
                "Lucky DDNS response field 'data' must be a list"
            )

        rules: list[DDNS] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise LuckyResponseError(
                    f"Lucky DDNS list item {index} must be a JSON object"
                )
            if item.get("Enable") is not True:
                continue

            required_fields = ("TaskName", "TaskType", "Ipv4Addr", "Ipv6Addr")
            for field in required_fields:
                if not isinstance(item.get(field), str):
                    raise LuckyResponseError(
                        f"Enabled Lucky DDNS list item {index} field {field!r} "
                        "must be a string"
                    )

            rules.append(
                {
                    "TaskName": item["TaskName"],
                    "TaskType": item["TaskType"],
                    "Ipv4Addr": item["Ipv4Addr"],
                    "Ipv6Addr": item["Ipv6Addr"],
                }
            )

        return rules
