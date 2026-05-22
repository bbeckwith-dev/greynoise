from dataclasses import dataclass
from enum import Enum
from typing import Optional


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
    noise: Optional[bool]
    riot: Optional[bool]
    classification: str
    name: str
    link: str
    last_seen: str
    message: str
