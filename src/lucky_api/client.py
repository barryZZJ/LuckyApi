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
from .types import StunRule


@dataclass(frozen=True, slots=True)
class _LuckyConfig:
    host_url: str
    username: str
    password: str
    openToken: str


class LuckyClient:
    """Access selected Lucky dashboard APIs."""

    def __init__(self, config_path: str | Path, *, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._config = self._load_config(config_path)

    @staticmethod
    def _load_config(config_path: str | Path) -> _LuckyConfig:
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

        return _LuckyConfig(
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

        token = self._config.openToken
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
                _, port_text = public_addr.rsplit(":", 1)
                parsed_port = int(port_text) if port_text else None
                public_port = (
                    parsed_port
                    if parsed_port is not None and 0 <= parsed_port <= 65535
                    else None
                )
            except (ValueError, TypeError):
                public_port = None

            rules.append(
                {
                    "Name": item["Name"],
                    "StunType": item["StunType"],
                    "StunLocalAddr": item["StunLocalAddr"],
                    "PublicAddr": public_addr,
                    "PublicPort": public_port,
                }
            )

        return rules
