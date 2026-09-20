# Lucky API

`lucky_api` is a small synchronous Python client for reading enabled STUN
rules from a [Lucky](https://github.com/gdy666/lucky) dashboard.

## Requirements

- Python 3.10 or newer
- Network access to the Lucky dashboard

## Installation

Install the package from this repository:

```powershell
python -m pip install .
```

For development and testing:

```powershell
python -m pip install -e ".[test]"
python -m pytest -v
```

## Configuration

Copy `config.example.json` to `config.json` and replace the placeholder
values:

```json
{
  "host_url": "http://192.0.2.10:16601/dashboard",
  "username": "your-username",
  "password": "your-password"
}
```

`host_url` must contain the complete dashboard base URL, including any path
prefix used by a reverse proxy. A trailing slash is optional. Keep
`config.json` private; it contains the dashboard password and is excluded by
the repository's `.gitignore`.

## Usage

```python
from lucky_api import LuckyClient

client = LuckyClient("config.json", timeout=10.0)
rules = client.get_stun_rules()

for rule in rules:
    print(rule["Name"], rule["PublicAddr"], rule["PublicPort"])
```

The first call authenticates with Lucky. The returned token is retained only
in the client instance and reused by later calls. If Lucky rejects the cached
token, `get_stun_rules()` raises an exception instead of logging in again;
create a new client instance to start a new session.

Only rules whose `Enable` value is exactly `true` are returned. Their original
order is preserved. Each result has this shape:

```python
{
    "Name": str,
    "StunType": str,
    "StunLocalAddr": str,
    "PublicAddr": str,
    "PublicPort": int | None,
}
```

`PublicPort` is `None` when `PublicAddr` has no parseable port or the parsed
number is outside the range 0 through 65535.

## Errors

All package exceptions inherit from `LuckyError`:

- `LuckyConfigError`: the configuration cannot be read or validated.
- `LuckyAuthenticationError`: the login request or response is unsuccessful.
- `LuckyAPIError`: the STUN request fails or Lucky returns a nonzero `ret`.
- `LuckyResponseError`: a successful response has invalid JSON or an invalid
  structure. This is a subclass of `LuckyAPIError`.

Network and HTTP exceptions are available through the raised exception's
`__cause__` attribute.
