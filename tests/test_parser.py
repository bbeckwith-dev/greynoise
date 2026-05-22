import pytest

from greynoise_lookup.models import ClassifiedEntry, EntryType
from greynoise_lookup.parser import (
    classify_entry,
    expand_subnet,
    parse_input_file,
)


class TestClassifyEntry:
    def test_valid_ipv4(self):
        result = classify_entry("8.8.8.8")
        assert result.entry_type == EntryType.IP
        assert result.value == "8.8.8.8"

    def test_valid_ipv4_with_whitespace(self):
        result = classify_entry("  10.0.0.1  \n")
        assert result.entry_type == EntryType.IP
        assert result.value == "10.0.0.1"

    def test_ipv6_rejected(self):
        result = classify_entry("2001:4860:4860::8888")
        assert result.entry_type == EntryType.INVALID

    def test_valid_subnet(self):
        result = classify_entry("192.168.1.0/24")
        assert result.entry_type == EntryType.SUBNET
        assert result.value == "192.168.1.0/24"

    def test_valid_subnet_small(self):
        result = classify_entry("10.0.0.0/30")
        assert result.entry_type == EntryType.SUBNET
        assert result.value == "10.0.0.0/30"

    def test_invalid_subnet(self):
        result = classify_entry("not/a/subnet")
        assert result.entry_type == EntryType.INVALID

    def test_asn_uppercase(self):
        result = classify_entry("AS7029")
        assert result.entry_type == EntryType.ASN
        assert result.value == "7029"

    def test_asn_with_n(self):
        result = classify_entry("ASN1234")
        assert result.entry_type == EntryType.ASN
        assert result.value == "1234"

    def test_asn_lowercase(self):
        result = classify_entry("as7029")
        assert result.entry_type == EntryType.ASN
        assert result.value == "7029"

    def test_asn_mixed_case(self):
        result = classify_entry("AsN999")
        assert result.entry_type == EntryType.ASN
        assert result.value == "999"

    def test_rejects_word_containing_as(self):
        result = classify_entry("fast")
        assert result.entry_type == EntryType.INVALID

    def test_rejects_word_containing_case(self):
        result = classify_entry("case")
        assert result.entry_type == EntryType.INVALID

    def test_rejects_word_baseline(self):
        result = classify_entry("BASELINE")
        assert result.entry_type == EntryType.INVALID

    def test_empty_string(self):
        result = classify_entry("")
        assert result.entry_type == EntryType.INVALID

    def test_whitespace_only(self):
        result = classify_entry("   ")
        assert result.entry_type == EntryType.INVALID

    def test_gibberish(self):
        result = classify_entry("hello world")
        assert result.entry_type == EntryType.INVALID


class TestExpandSubnet:
    def test_slash_30(self):
        ips = expand_subnet("10.0.0.0/30")
        assert len(ips) == 4
        assert ips[0] == "10.0.0.0"
        assert ips[3] == "10.0.0.3"

    def test_slash_32(self):
        ips = expand_subnet("10.0.0.1/32")
        assert ips == ["10.0.0.1"]

    def test_respects_max_ips(self):
        ips = expand_subnet("10.0.0.0/24", max_ips=10)
        assert len(ips) == 10

    def test_invalid_subnet_raises(self):
        with pytest.raises(ValueError):
            expand_subnet("not_a_subnet")


class TestParseInputFile:
    def test_reads_mixed_entries(self, tmp_input_file):
        path = tmp_input_file(["8.8.8.8", "AS7029", "10.0.0.0/30", "garbage"])
        entries = parse_input_file(path)
        assert len(entries) == 4
        assert entries[0].entry_type == EntryType.IP
        assert entries[1].entry_type == EntryType.ASN
        assert entries[2].entry_type == EntryType.SUBNET
        assert entries[3].entry_type == EntryType.INVALID

    def test_skips_blank_lines(self, tmp_input_file):
        path = tmp_input_file(["8.8.8.8", "", "  ", "1.1.1.1"])
        entries = parse_input_file(path)
        assert len(entries) == 2

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_input_file("/nonexistent/path.txt")

    def test_bounds_total_lines(self, tmp_input_file):
        lines = [f"10.0.0.{i}" for i in range(300)]
        path = tmp_input_file(lines)
        entries = parse_input_file(path, max_entries=100)
        assert len(entries) == 100
