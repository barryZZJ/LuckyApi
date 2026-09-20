from typing import TypedDict


class StunRule(TypedDict):
    """Normalized enabled STUN rule returned by Lucky."""

    Name: str
    StunType: str
    StunLocalAddr: str
    PublicAddr: str
    PublicPort: int | None
