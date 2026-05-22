from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EntryType(Enum):
    SUBNET = "subnet"
    ASN = "asn"
    IP = "ip"
    INVALID = "invalid"


@dataclass(frozen=True)
class ClassifiedEntry:
    raw: str
    entry_type: EntryType
    value: str


@dataclass(frozen=True)
class LookupResult:
    entry: str
    ip: str
    ptr: str
    noise: bool | None
    riot: bool | None
    classification: str
    name: str
    link: str
    last_seen: str
    message: str
