from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename
import requests

from greynoise_lookup.models import LookupResult

logger = logging.getLogger(__name__)

dns_resolver = dns.resolver

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community"
SHADOWSERVER_ASN_URL = "https://api.shadowserver.org/net/asn"

MAX_RETRIES = 3
REQUEST_TIMEOUT = 10


def reverse_dns(ip: str) -> str:
    rev_name = dns.reversename.from_address(ip)
    try:
        answers = dns_resolver.resolve(rev_name, "PTR")
        return str(answers[0])
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ):
        logger.debug("No PTR record for %s", ip)
        return "No PTR"


def query_greynoise(
    ip: str,
    api_key: str | None = None,
    pre_request_delay: float = 1.0,
) -> dict[str, Any]:
    url = f"{GREYNOISE_COMMUNITY_URL}/{ip}"
    headers: dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["key"] = api_key

    if pre_request_delay > 0:
        time.sleep(pre_request_delay)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                result: dict[str, Any] = resp.json()
                return result
            if resp.status_code in (429, 500, 502, 503):
                if attempt < MAX_RETRIES:
                    backoff = 2 ** attempt
                    logger.warning(
                        "GreyNoise %d for %s (attempt %d/%d), retrying in %ds",
                        resp.status_code, ip, attempt, MAX_RETRIES, backoff,
                    )
                    time.sleep(backoff)
                continue
            logger.error(
                "GreyNoise %d for %s: %.200s",
                resp.status_code, ip, resp.text or "",
            )
            return _error_result(ip, f"HTTP {resp.status_code}")
        except requests.RequestException as exc:
            logger.warning(
                "GreyNoise request failed for %s (attempt %d/%d): %s",
                ip, attempt, MAX_RETRIES, exc,
            )
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)

    return _error_result(ip, f"API error after {MAX_RETRIES} attempts")


def resolve_asn_to_networks(
    asn_number: str, max_networks: int = 50
) -> list[str]:
    try:
        resp = requests.get(
            SHADOWSERVER_ASN_URL,
            params={"prefix": asn_number},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        networks = resp.json()
        if not isinstance(networks, list):
            logger.error("Unexpected Shadowserver response for AS%s", asn_number)
            return []
        valid = [n for n in networks if _is_valid_ipv4_cidr(n)]
        if len(valid) < len(networks):
            logger.warning(
                "AS%s: dropped %d invalid CIDRs from Shadowserver response",
                asn_number, len(networks) - len(valid),
            )
        if len(valid) > max_networks:
            logger.warning(
                "AS%s has %d networks, truncating to %d",
                asn_number, len(valid), max_networks,
            )
        return valid[:max_networks]
    except requests.RequestException as exc:
        logger.error("Shadowserver API error for AS%s: %s", asn_number, exc)
        return []
    except ValueError:
        logger.error("Invalid JSON from Shadowserver for AS%s", asn_number)
        return []


def _is_valid_ipv4_cidr(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Network(value, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def process_ip(
    entry: str,
    ip: str,
    api_key: str | None = None,
    pre_request_delay: float = 1.0,
) -> LookupResult:
    ptr = reverse_dns(ip)
    gn = query_greynoise(ip, api_key=api_key, pre_request_delay=pre_request_delay)
    return LookupResult(
        entry=entry,
        ip=ip,
        ptr=ptr,
        noise=gn.get("noise"),
        riot=gn.get("riot"),
        classification=gn.get("classification", ""),
        name=gn.get("name", ""),
        link=gn.get("link", ""),
        last_seen=gn.get("last_seen", ""),
        message=gn.get("message", ""),
    )


def _error_result(ip: str, message: str) -> dict[str, Any]:
    return {
        "ip": ip,
        "noise": None,
        "riot": None,
        "classification": "",
        "name": "",
        "link": "",
        "last_seen": "",
        "message": message,
    }
