import csv

import pytest

from greynoise_lookup.models import LookupResult
from greynoise_lookup.writer import write_results, build_summary


def _make_result(**overrides) -> LookupResult:
    defaults = dict(
        entry="8.8.8.8",
        ip="8.8.8.8",
        ptr="dns.google.",
        noise=False,
        riot=True,
        classification="benign",
        name="Google Public DNS",
        link="https://viz.greynoise.io/riot/8.8.8.8",
        last_seen="2024-01-15",
        message="Success",
    )
    defaults.update(overrides)
    return LookupResult(**defaults)


class TestWriteResults:
    def test_writes_csv_with_headers(self, tmp_path):
        out = tmp_path / "results.csv"
        results = [_make_result()]
        write_results(results, str(out))

        with open(out, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["ip"] == "8.8.8.8"
        assert rows[0]["ptr"] == "dns.google."
        assert rows[0]["classification"] == "benign"

    def test_handles_commas_in_values(self, tmp_path):
        out = tmp_path / "results.csv"
        results = [_make_result(name="Acme, Inc.")]
        write_results(results, str(out))

        with open(out, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert rows[0]["name"] == "Acme, Inc."

    def test_writes_multiple_rows(self, tmp_path):
        out = tmp_path / "results.csv"
        results = [
            _make_result(ip="8.8.8.8"),
            _make_result(ip="1.1.1.1", entry="1.1.1.1"),
        ]
        write_results(results, str(out))

        with open(out, newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2

    def test_empty_results_writes_headers_only(self, tmp_path):
        out = tmp_path / "results.csv"
        write_results([], str(out))

        with open(out, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 0
        assert "ip" in reader.fieldnames


class TestBuildSummary:
    def test_basic_counts(self):
        results = [
            _make_result(noise=True, riot=False, classification="malicious"),
            _make_result(noise=False, riot=True, classification="benign"),
            _make_result(noise=False, riot=False, classification="unknown"),
        ]
        summary = build_summary(results)
        assert summary["total_ips"] == 3
        assert summary["noise_count"] == 1
        assert summary["riot_count"] == 1
        assert summary["classifications"]["malicious"] == 1
        assert summary["classifications"]["benign"] == 1
        assert summary["classifications"]["unknown"] == 1

    def test_empty_results(self):
        summary = build_summary([])
        assert summary["total_ips"] == 0
        assert summary["noise_count"] == 0
        assert summary["riot_count"] == 0

    def test_none_noise_riot_not_counted(self):
        results = [_make_result(noise=None, riot=None)]
        summary = build_summary(results)
        assert summary["noise_count"] == 0
        assert summary["riot_count"] == 0
