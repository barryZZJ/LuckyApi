from __future__ import annotations

import json

import pytest
import requests

import lucky_api.client as client_module
from lucky_api import (
    LuckyAPIError,
    LuckyAuthenticationError,
    LuckyClient,
    LuckyConfigError,
    LuckyResponseError,
)


class FakeResponse:
    def __init__(self, payload=None, *, http_error=None, json_error=None):
        self._payload = payload
        self._http_error = http_error
        self._json_error = json_error

    def raise_for_status(self):
        if self._http_error is not None:
            raise self._http_error

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._payload


def write_config(tmp_path, config):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return config_path


@pytest.fixture
def config_path(tmp_path):
    return write_config(
        tmp_path,
        {
            "host_url": "https://lucky.example/dashboard/",
            "username": "admin",
            "password": "secret",
        },
    )


def install_successful_login(monkeypatch, payload=None):
    if payload is None:
        payload = {"ret": 0, "token": "test-token", "msg": "ok"}
    monkeypatch.setattr(
        client_module.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(payload),
    )


def test_constructor_rejects_unreadable_config(tmp_path):
    missing_path = tmp_path / "missing.json"

    with pytest.raises(LuckyConfigError, match="Unable to read configuration"):
        LuckyClient(missing_path)


def test_constructor_rejects_invalid_json(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text("not-json", encoding="utf-8")

    with pytest.raises(LuckyConfigError, match="valid JSON"):
        LuckyClient(config_path)


def test_constructor_rejects_non_object_json(tmp_path):
    config_path = write_config(tmp_path, ["not", "an", "object"])

    with pytest.raises(LuckyConfigError, match="JSON object"):
        LuckyClient(config_path)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("host_url", None),
        ("username", ""),
        ("password", "   "),
    ],
)
def test_constructor_rejects_missing_or_empty_required_values(tmp_path, key, value):
    config = {
        "host_url": "https://lucky.example/dashboard",
        "username": "admin",
        "password": "secret",
    }
    if value is None:
        del config[key]
    else:
        config[key] = value
    config_path = write_config(tmp_path, config)

    with pytest.raises(LuckyConfigError, match=key):
        LuckyClient(config_path)


@pytest.mark.parametrize(
    "host_url",
    ["ftp://lucky.example", "http:///missing-host", "lucky.example"],
)
def test_constructor_rejects_invalid_host_url(tmp_path, host_url):
    config_path = write_config(
        tmp_path,
        {
            "host_url": host_url,
            "username": "admin",
            "password": "secret",
        },
    )

    with pytest.raises(LuckyConfigError, match="host_url"):
        LuckyClient(config_path)


def test_get_stun_rules_logs_in_lazily_and_reuses_token(
    monkeypatch, config_path
):
    post_calls = []
    get_calls = []
    timestamps = iter([1.111, 2.222, 3.333])

    def fake_post(url, **kwargs):
        post_calls.append((url, kwargs))
        return FakeResponse({"ret": 0, "token": "test-token", "msg": "ok"})

    def fake_get(url, **kwargs):
        get_calls.append((url, kwargs))
        return FakeResponse({"ret": 0, "list": []})

    monkeypatch.setattr(client_module.time, "time", lambda: next(timestamps))
    monkeypatch.setattr(client_module.requests, "post", fake_post)
    monkeypatch.setattr(client_module.requests, "get", fake_get)

    client = LuckyClient(config_path, timeout=4.5)

    assert client.get_stun_rules() == []
    assert client.get_stun_rules() == []
    assert post_calls == [
        (
            "https://lucky.example/dashboard/api/login",
            {
                "params": {"_": 1111},
                "json": {
                    "Account": "admin",
                    "Password": "secret",
                    "TwoFA": "",
                },
                "timeout": 4.5,
            },
        )
    ]
    assert get_calls == [
        (
            "https://lucky.example/dashboard/api/stunrulelist",
            {
                "params": {"_": 2222},
                "headers": {"Lucky-Admin-Token": "test-token"},
                "timeout": 4.5,
            },
        ),
        (
            "https://lucky.example/dashboard/api/stunrulelist",
            {
                "params": {"_": 3333},
                "headers": {"Lucky-Admin-Token": "test-token"},
                "timeout": 4.5,
            },
        ),
    ]


def test_get_stun_rules_filters_and_parses_enabled_rules(monkeypatch, config_path):
    install_successful_login(monkeypatch)
    monkeypatch.setattr(
        client_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            {
                "ret": 0,
                "list": [
                    {"Enable": False},
                    {"Enable": 1},
                    {
                        "Enable": True,
                        "Name": "ipv4",
                        "StunType": "IPv4-TCP",
                        "StunLocalAddr": "192.168.1.10:8080",
                        "PublicAddr": "203.0.113.8:45678",
                    },
                    {
                        "Enable": True,
                        "Name": "ipv6",
                        "StunType": "IPv6-UDP",
                        "StunLocalAddr": "[fd00::10]:5353",
                        "PublicAddr": "[2001:db8::8]:53530",
                    },
                    {
                        "Enable": True,
                        "Name": "unknown-port",
                        "StunType": "IPv4-UDP",
                        "StunLocalAddr": "192.168.1.20:9000",
                        "PublicAddr": "203.0.113.9:not-a-port",
                    },
                    {
                        "Enable": True,
                        "Name": "missing-port",
                        "StunType": "IPv4-UDP",
                        "StunLocalAddr": "192.168.1.21:9001",
                        "PublicAddr": "203.0.113.10",
                    },
                ],
            }
        ),
    )

    assert LuckyClient(config_path).get_stun_rules() == [
        {
            "Name": "ipv4",
            "StunType": "IPv4-TCP",
            "StunLocalAddr": "192.168.1.10:8080",
            "PublicAddr": "203.0.113.8:45678",
            "PublicPort": 45678,
        },
        {
            "Name": "ipv6",
            "StunType": "IPv6-UDP",
            "StunLocalAddr": "[fd00::10]:5353",
            "PublicAddr": "[2001:db8::8]:53530",
            "PublicPort": 53530,
        },
        {
            "Name": "unknown-port",
            "StunType": "IPv4-UDP",
            "StunLocalAddr": "192.168.1.20:9000",
            "PublicAddr": "203.0.113.9:not-a-port",
            "PublicPort": None,
        },
        {
            "Name": "missing-port",
            "StunType": "IPv4-UDP",
            "StunLocalAddr": "192.168.1.21:9001",
            "PublicAddr": "203.0.113.10",
            "PublicPort": None,
        },
    ]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"ret": 1, "msg": "bad credentials"}, "bad credentials"),
        ({"ret": 0}, "token"),
        ({"ret": 0, "token": ""}, "token"),
        (["not", "an", "object"], "JSON object"),
    ],
)
def test_login_rejects_unsuccessful_or_malformed_responses(
    monkeypatch, config_path, payload, message
):
    install_successful_login(monkeypatch, payload)

    with pytest.raises(LuckyAuthenticationError, match=message):
        LuckyClient(config_path).get_stun_rules()


def test_login_wraps_transport_errors_with_original_cause(monkeypatch, config_path):
    error = requests.ConnectionError("offline")
    monkeypatch.setattr(
        client_module.requests,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )

    with pytest.raises(LuckyAuthenticationError) as exc_info:
        LuckyClient(config_path).get_stun_rules()

    assert exc_info.value.__cause__ is error


def test_login_wraps_http_errors_with_original_cause(monkeypatch, config_path):
    error = requests.HTTPError("unauthorized")
    monkeypatch.setattr(
        client_module.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(http_error=error),
    )

    with pytest.raises(LuckyAuthenticationError) as exc_info:
        LuckyClient(config_path).get_stun_rules()

    assert exc_info.value.__cause__ is error


def test_login_wraps_invalid_json(monkeypatch, config_path):
    install_successful_login(monkeypatch)
    json_error = requests.JSONDecodeError("bad json", "x", 0)
    monkeypatch.setattr(
        client_module.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(json_error=json_error),
    )

    with pytest.raises(LuckyAuthenticationError, match="valid JSON") as exc_info:
        LuckyClient(config_path).get_stun_rules()

    assert exc_info.value.__cause__ is json_error


def test_stun_request_wraps_http_errors(monkeypatch, config_path):
    install_successful_login(monkeypatch)
    http_error = requests.HTTPError("server error")
    monkeypatch.setattr(
        client_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(http_error=http_error),
    )

    with pytest.raises(LuckyAPIError) as exc_info:
        LuckyClient(config_path).get_stun_rules()

    assert exc_info.value.__cause__ is http_error


def test_stun_request_wraps_timeout_with_original_cause(monkeypatch, config_path):
    install_successful_login(monkeypatch)
    error = requests.Timeout("timed out")
    monkeypatch.setattr(
        client_module.requests,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )

    with pytest.raises(LuckyAPIError) as exc_info:
        LuckyClient(config_path).get_stun_rules()

    assert exc_info.value.__cause__ is error


def test_stun_request_wraps_invalid_json(monkeypatch, config_path):
    install_successful_login(monkeypatch)
    json_error = requests.JSONDecodeError("bad json", "x", 0)
    monkeypatch.setattr(
        client_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(json_error=json_error),
    )

    with pytest.raises(LuckyResponseError, match="valid JSON") as exc_info:
        LuckyClient(config_path).get_stun_rules()

    assert exc_info.value.__cause__ is json_error


@pytest.mark.parametrize(
    ("payload", "exception_type", "message"),
    [
        ({"ret": -1, "msg": "login expired"}, LuckyAPIError, "login expired"),
        ({"ret": 0}, LuckyResponseError, "list"),
        ({"ret": 0, "list": {}}, LuckyResponseError, "list"),
        (["not", "an", "object"], LuckyResponseError, "JSON object"),
    ],
)
def test_stun_request_rejects_unsuccessful_or_malformed_responses(
    monkeypatch, config_path, payload, exception_type, message
):
    install_successful_login(monkeypatch)
    monkeypatch.setattr(
        client_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(payload),
    )

    with pytest.raises(exception_type, match=message):
        LuckyClient(config_path).get_stun_rules()


def test_stun_request_does_not_relogin_after_token_rejection(
    monkeypatch, config_path
):
    login_count = 0

    def fake_post(*args, **kwargs):
        nonlocal login_count
        login_count += 1
        return FakeResponse({"ret": 0, "token": "expired-token"})

    monkeypatch.setattr(client_module.requests, "post", fake_post)
    monkeypatch.setattr(
        client_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            {"ret": -1, "msg": "login expired"}
        ),
    )
    client = LuckyClient(config_path)

    with pytest.raises(LuckyAPIError, match="login expired"):
        client.get_stun_rules()
    with pytest.raises(LuckyAPIError, match="login expired"):
        client.get_stun_rules()

    assert login_count == 1


@pytest.mark.parametrize(
    "field", ["Name", "StunType", "StunLocalAddr", "PublicAddr"]
)
def test_enabled_rule_requires_string_fields(monkeypatch, config_path, field):
    install_successful_login(monkeypatch)
    rule = {
        "Enable": True,
        "Name": "example",
        "StunType": "IPv4-TCP",
        "StunLocalAddr": "192.168.1.10:8080",
        "PublicAddr": "203.0.113.8:45678",
    }
    rule[field] = None
    monkeypatch.setattr(
        client_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            {
                "ret": 0,
                "list": [rule],
            }
        ),
    )

    with pytest.raises(LuckyResponseError, match=field):
        LuckyClient(config_path).get_stun_rules()


@pytest.mark.parametrize("port", ["-1", "65536"])
def test_out_of_range_public_port_returns_none(monkeypatch, config_path, port):
    install_successful_login(monkeypatch)
    monkeypatch.setattr(
        client_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(
            {
                "ret": 0,
                "list": [
                    {
                        "Enable": True,
                        "Name": "bad-port",
                        "StunType": "IPv4-TCP",
                        "StunLocalAddr": "192.168.1.10:8080",
                        "PublicAddr": f"203.0.113.8:{port}",
                    }
                ],
            }
        ),
    )

    rules = LuckyClient(config_path).get_stun_rules()

    assert rules[0]["PublicPort"] is None


def test_non_object_stun_item_raises_response_error(monkeypatch, config_path):
    install_successful_login(monkeypatch)
    monkeypatch.setattr(
        client_module.requests,
        "get",
        lambda *args, **kwargs: FakeResponse({"ret": 0, "list": ["bad-item"]}),
    )

    with pytest.raises(LuckyResponseError, match="item 0"):
        LuckyClient(config_path).get_stun_rules()
