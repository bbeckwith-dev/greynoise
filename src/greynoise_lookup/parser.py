from __future__ import annotations

import ipaddress
import logging
import re

from greynoise_lookup.models import ClassifiedEntry, EntryType

logger = logging.getLogger(__name__)

_ASN_PATTERN = re.compile(r"^asn?(\d+)$", re.IGNORECASE)

MAX_ENTRIES = 10_000


def classify_entry(raw: str) -> ClassifiedEntry:
    stripped = raw.strip()
    if not stripped:
        return ClassifiedEntry(raw=raw, entry_type=EntryType.INVALID, value=stripped)

    asn_match = _ASN_PATTERN.match(stripped)
    if asn_match:
        return ClassifiedEntry(
            raw=raw, entry_type=EntryType.ASN, value=asn_match.group(1)
        )

    if "/" in stripped:
        try:
            network = ipaddress.IPv4Network(stripped, strict=False)
            normalized = str(network)
            return ClassifiedEntry(
                raw=raw, entry_type=EntryType.SUBNET, value=normalized
            )
        except (ipaddress.AddressValueError, ValueError):
            return ClassifiedEntry(
                raw=raw, entry_type=EntryType.INVALID, value=stripped
            )

    try:
        addr = ipaddress.ip_address(stripped)
        if isinstance(addr, ipaddress.IPv6Address):
            logger.debug("IPv6 not supported: %s", stripped)
            return ClassifiedEntry(
                raw=raw, entry_type=EntryType.INVALID, value=stripped
            )
        return ClassifiedEntry(
            raw=raw, entry_type=EntryType.IP, value=str(addr)
        )
    except ValueError:
        pass

    return ClassifiedEntry(raw=raw, entry_type=EntryType.INVALID, value=stripped)


def expand_subnet(cidr: str, max_ips: int = 10_000) -> list[str]:
    network = ipaddress.IPv4Network(cidr, strict=False)
    ips: list[str] = []
    for i, addr in enumerate(network):
        if i >= max_ips:
            logger.warning(
                "Subnet %s truncated at %d IPs (total: %d)",
                cidr, max_ips, network.num_addresses,
            )
            break
        ips.append(str(addr))
    return ips


def parse_input_file(
    path: str, max_entries: int = MAX_ENTRIES
) -> list[ClassifiedEntry]:
    entries: list[ClassifiedEntry] = []
    with open(path, "r") as f:
        for line in f:
            if len(entries) >= max_entries:
                logger.warning(
                    "Input truncated at %d entries", max_entries
                )
                break
            stripped = line.strip()
            if not stripped:
                continue
            entries.append(classify_entry(stripped))
    return entries
