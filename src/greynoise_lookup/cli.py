from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys

from dotenv import load_dotenv

from greynoise_lookup.lookup import process_ip, resolve_asn_to_networks
from greynoise_lookup.models import ClassifiedEntry, EntryType, LookupResult
from greynoise_lookup.parser import classify_entry, expand_subnet, parse_input_file
from greynoise_lookup.writer import print_summary, write_results, write_results_json

logger = logging.getLogger("greynoise_lookup")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="greynoise-lookup",
        description="IP, subnet, and ASN threat research via reverse DNS and GreyNoise.",
    )
    parser.add_argument(
        "-i", "--input",
        default="iplist.txt",
        help="Path to input file with IPs/subnets/ASNs, one per line (default: iplist.txt)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Path to output file (default: results.csv or results.json)",
    )
    parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        dest="format",
        help="Output format (default: csv)",
    )
    parser.add_argument(
        "--max-ips",
        type=int,
        default=10_000,
        help="Max IPs to process per subnet/ASN expansion (default: 10000)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and classify input without querying APIs",
    )
    return parser


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root = logging.getLogger("greynoise_lookup")
    root.setLevel(level)
    root.addHandler(handler)


def process_entry(
    entry: ClassifiedEntry,
    api_key: str | None,
    max_ips: int,
) -> list[LookupResult]:
    if entry.entry_type == EntryType.IP:
        return [process_ip(entry.raw.strip(), entry.value, api_key=api_key)]

    if entry.entry_type == EntryType.SUBNET:
        ips = expand_subnet(entry.value, max_ips=max_ips)
        logger.info("Subnet %s: processing %d IPs", entry.value, len(ips))
        return [
            process_ip(entry.raw.strip(), ip, api_key=api_key)
            for ip in ips
        ]

    if entry.entry_type == EntryType.ASN:
        networks = resolve_asn_to_networks(entry.value)
        if not networks:
            logger.warning("No networks found for AS%s", entry.value)
            return []
        logger.info("AS%s: %d networks found", entry.value, len(networks))
        results: list[LookupResult] = []
        for cidr in networks:
            ips = expand_subnet(cidr, max_ips=max_ips)
            logger.info("  %s: processing %d IPs", cidr, len(ips))
            for ip in ips:
                results.append(
                    process_ip(entry.raw.strip(), ip, api_key=api_key)
                )
                if len(results) >= max_ips:
                    logger.warning("AS%s: hit max-ips limit (%d)", entry.value, max_ips)
                    return results
        return results

    logger.warning("Skipping invalid entry: %s", entry.raw.strip())
    return []


def dry_run_report(entries: list[ClassifiedEntry], max_ips: int) -> None:
    for entry in entries:
        label = entry.entry_type.value.upper()
        if entry.entry_type == EntryType.SUBNET:
            network = ipaddress.IPv4Network(entry.value, strict=False)
            count = min(network.num_addresses, max_ips)
            logger.info("[%s] %s -> %d IPs", label, entry.value, count)
        elif entry.entry_type == EntryType.ASN:
            logger.info("[%s] AS%s (network count requires API call)", label, entry.value)
        elif entry.entry_type == EntryType.IP:
            logger.info("[%s] %s", label, entry.value)
        else:
            logger.info("[%s] %s", label, entry.raw.strip())


def _resolve_output_path(args: argparse.Namespace) -> str:
    if args.output is not None:
        return str(args.output)
    return "results.json" if args.format == "json" else "results.csv"


def run(args: argparse.Namespace) -> int:
    load_dotenv()
    api_key = os.environ.get("GREYNOISE_API_KEY") or None
    output_path = _resolve_output_path(args)

    if not api_key:
        logger.info("No GREYNOISE_API_KEY set — using unauthenticated community API")

    try:
        entries = parse_input_file(args.input)
    except FileNotFoundError:
        logger.error("Input file not found: %s", args.input)
        return 1

    if not entries:
        logger.error("No entries found in %s", args.input)
        return 1

    logger.info("Loaded %d entries from %s", len(entries), args.input)

    if args.dry_run:
        dry_run_report(entries, args.max_ips)
        return 0

    all_results: list[LookupResult] = []
    for entry in entries:
        results = process_entry(entry, api_key, args.max_ips)
        all_results.extend(results)

    if args.format == "json":
        write_results_json(all_results, output_path)
    else:
        write_results(all_results, output_path)
    print_summary(all_results)
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)
    sys.exit(run(args))
