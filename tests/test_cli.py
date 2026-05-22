import argparse
import csv
import json
from unittest.mock import patch

import pytest
import responses

from greynoise_lookup.cli import _resolve_output_path, build_parser, dry_run_report, run


GN_BASE = "https://api.greynoise.io/v3/community"


def _make_args(tmp_path, input_lines, **overrides):
    input_file = tmp_path / "input.txt"
    input_file.write_text("\n".join(input_lines) + "\n")
    output_file = tmp_path / "output.csv"
    defaults = {
        "input": str(input_file),
        "output": str(output_file),
        "max_ips": 10_000,
        "verbose": False,
        "dry_run": False,
        "format": "csv",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults), str(output_file)


def _gn_response(ip="8.8.8.8"):
    return {
        "ip": ip,
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google Public DNS",
        "link": f"https://viz.greynoise.io/riot/{ip}",
        "last_seen": "2024-01-15",
        "message": "Success",
    }


class TestBuildParser:
    def test_defaults(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.input == "iplist.txt"
        assert args.output is None
        assert args.format == "csv"
        assert args.max_ips == 10_000
        assert args.verbose is False
        assert args.dry_run is False

    def test_custom_args(self):
        parser = build_parser()
        args = parser.parse_args(["-i", "my.txt", "-o", "out.csv", "--max-ips", "50", "-v", "--dry-run"])
        assert args.input == "my.txt"
        assert args.output == "out.csv"
        assert args.max_ips == 50
        assert args.verbose is True
        assert args.dry_run is True


class TestRunIntegration:
    @responses.activate
    @patch("greynoise_lookup.lookup.reverse_dns", return_value="dns.google.")
    def test_single_ip_end_to_end(self, mock_dns, tmp_path):
        responses.add(responses.GET, f"{GN_BASE}/8.8.8.8", json=_gn_response())
        args, output = _make_args(tmp_path, ["8.8.8.8"])
        exit_code = run(args)
        assert exit_code == 0

        with open(output, newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["ip"] == "8.8.8.8"
        assert rows[0]["ptr"] == "dns.google."
        assert rows[0]["classification"] == "benign"

    @responses.activate
    @patch("greynoise_lookup.lookup.reverse_dns", return_value="No PTR")
    def test_subnet_expansion(self, mock_dns, tmp_path):
        for i in range(4):
            responses.add(
                responses.GET,
                f"{GN_BASE}/10.0.0.{i}",
                json=_gn_response(f"10.0.0.{i}"),
            )
        args, output = _make_args(tmp_path, ["10.0.0.0/30"])
        exit_code = run(args)
        assert exit_code == 0

        with open(output, newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 4

    def test_dry_run_no_api_calls(self, tmp_path):
        args, output = _make_args(tmp_path, ["8.8.8.8", "AS7029", "10.0.0.0/30"], dry_run=True)
        exit_code = run(args)
        assert exit_code == 0
        assert not (tmp_path / "output.csv").exists() or (tmp_path / "output.csv").stat().st_size == 0

    def test_missing_input_file(self, tmp_path):
        args = argparse.Namespace(
            input="/nonexistent/file.txt",
            output=str(tmp_path / "out.csv"),
            max_ips=10_000,
            verbose=False,
            dry_run=False,
        )
        exit_code = run(args)
        assert exit_code == 1

    @responses.activate
    @patch("greynoise_lookup.lookup.reverse_dns", return_value="No PTR")
    def test_invalid_entries_dont_crash(self, mock_dns, tmp_path):
        responses.add(responses.GET, f"{GN_BASE}/1.1.1.1", json=_gn_response("1.1.1.1"))
        args, output = _make_args(tmp_path, ["garbage", "1.1.1.1", "also bad"])
        exit_code = run(args)
        assert exit_code == 0

        with open(output, newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["ip"] == "1.1.1.1"

    @responses.activate
    @patch("greynoise_lookup.lookup.reverse_dns", return_value="No PTR")
    def test_multiple_ips(self, mock_dns, tmp_path):
        for ip in ["8.8.8.8", "1.1.1.1"]:
            responses.add(responses.GET, f"{GN_BASE}/{ip}", json=_gn_response(ip))
        args, output = _make_args(tmp_path, ["8.8.8.8", "1.1.1.1"])
        exit_code = run(args)
        assert exit_code == 0

        with open(output, newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2

    @responses.activate
    @patch("greynoise_lookup.lookup.reverse_dns", return_value="dns.google.")
    def test_json_format_output(self, mock_dns, tmp_path):
        responses.add(responses.GET, f"{GN_BASE}/8.8.8.8", json=_gn_response())
        args, output = _make_args(
            tmp_path, ["8.8.8.8"], format="json",
        )
        exit_code = run(args)
        assert exit_code == 0

        data = json.loads(open(output).read())
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["ip"] == "8.8.8.8"
        assert data[0]["ptr"] == "dns.google."


class TestBuildParserFormat:
    def test_format_default_csv(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.format == "csv"

    def test_format_json(self):
        parser = build_parser()
        args = parser.parse_args(["--format", "json"])
        assert args.format == "json"

    def test_format_json_changes_default_output(self):
        parser = build_parser()
        args = parser.parse_args(["--format", "json"])
        assert _resolve_output_path(args) == "results.json"

    def test_format_csv_default_output(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert _resolve_output_path(args) == "results.csv"

    def test_explicit_output_overrides_format(self):
        parser = build_parser()
        args = parser.parse_args(["--format", "json", "-o", "custom.out"])
        assert _resolve_output_path(args) == "custom.out"
