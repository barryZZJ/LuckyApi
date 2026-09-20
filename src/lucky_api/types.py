from typing import TypedDict, Literal


class StunRule(TypedDict):
    """Normalized enabled STUN rule returned by Lucky."""

    Name: str
    StunType: str
    StunLocalAddr: str
    PublicAddr: str
    PublicIp: str | None
    PublicPort: int | None

class DDNS(TypedDict):
    """Normalized enabled DDNS returned by Lucky."""

    TaskName: str
    Ipv4Addr: str
    Ipv6Addr: str
    TaskType: Literal["IPv6", "IPv4"]
