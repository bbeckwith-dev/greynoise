from __future__ import annotations

import csv
import json
import logging
from collections import Counter
from dataclasses import asdict
from typing import Any

from greynoise_lookup.models import LookupResult

logger = logging.getLogger(__name__)

CSV_FIELDS = [
    "entry", "ip", "ptr", "noise", "riot",
    "classification", "name", "link", "last_seen", "message",
]


def write_results(results: list[LookupResult], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))
    logger.info("Wrote %d results to %s", len(results), output_path)


def write_results_json(results: list[LookupResult], output_path: str) -> None:
    data = [asdict(r) for r in results]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info("Wrote %d results to %s", len(results), output_path)


def build_summary(results: list[LookupResult]) -> dict[str, Any]:
    classifications: Counter[str] = Counter()
    noise_count = 0
    riot_count = 0

    for r in results:
        if r.noise is True:
            noise_count += 1
        if r.riot is True:
            riot_count += 1
        if r.classification:
            classifications[r.classification] += 1

    return {
        "total_ips": len(results),
        "noise_count": noise_count,
        "riot_count": riot_count,
        "classifications": dict(classifications),
    }


def print_summary(results: list[LookupResult]) -> None:
    summary = build_summary(results)
    logger.info("--- Summary ---")
    logger.info("Total IPs scanned: %d", summary["total_ips"])
    logger.info("Noise (observed scanning): %d", summary["noise_count"])
    logger.info("RIOT (known benign service): %d", summary["riot_count"])
    if summary["classifications"]:
        logger.info("Classifications:")
        for cls, count in sorted(summary["classifications"].items()):
            logger.info("  %s: %d", cls, count)
