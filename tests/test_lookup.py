from unittest.mock import patch, MagicMock

import pytest
import responses

from greynoise_lookup.lookup import (
    query_greynoise,
    reverse_dns,
    process_ip,
    resolve_asn_to_networks,
)
from greynoise_lookup.models import LookupResult

GN_URL = "https://api.greynoise.io/v3/community/8.8.8.8"
SHADOW_URL = "https://api.shadowserver.org/net/asn"


class TestReverseDns:
    @patch("greynoise_lookup.lookup.dns_resolver")
    def test_returns_ptr_record(self, mock_resolver):
        mock_resolver.resolve.return_value = [MagicMock(__str__=lambda _: "dns.google.")]
        result = reverse_dns("8.8.8.8")
        assert result == "dns.google."

    @patch("greynoise_lookup.lookup.dns_resolver")
    def test_nxdomain_returns_no_ptr(self, mock_resolver):
        import dns.resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        assert reverse_dns("192.168.1.1") == "No PTR"

    @patch("greynoise_lookup.lookup.dns_resolver")
    def test_timeout_returns_no_ptr(self, mock_resolver):
        import dns.exception
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        assert reverse_dns("10.0.0.1") == "No PTR"

    @patch("greynoise_lookup.lookup.dns_resolver")
    def test_no_nameservers_returns_no_ptr(self, mock_resolver):
        import dns.resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()
        assert reverse_dns("10.0.0.2") == "No PTR"

    @patch("greynoise_lookup.lookup.dns_resolver")
    def test_no_answer_returns_no_ptr(self, mock_resolver):
        import dns.resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        assert reverse_dns("10.0.0.3") == "No PTR"


class TestQueryGreynoise:
    @responses.activate
    def test_success_response(self, sample_greynoise_success):
        responses.add(responses.GET, GN_URL, json=sample_greynoise_success)
        result = query_greynoise("8.8.8.8", api_key=None, pre_request_delay=0)
        assert result["noise"] is False
        assert result["riot"] is True
        assert result["name"] == "Google Public DNS"

    @responses.activate
    def test_sends_api_key_header(self):
        responses.add(responses.GET, GN_URL, json={"message": "ok"})
        query_greynoise("8.8.8.8", api_key="test-key-123", pre_request_delay=0)
        assert responses.calls[0].request.headers["key"] == "test-key-123"

    @responses.activate
    def test_no_api_key_header_when_none(self):
        responses.add(responses.GET, GN_URL, json={"message": "ok"})
        query_greynoise("8.8.8.8", api_key=None, pre_request_delay=0)
        assert "key" not in responses.calls[0].request.headers

    @patch("greynoise_lookup.lookup.time.sleep")
    @responses.activate
    def test_retries_on_server_error(self, mock_sleep):
        responses.add(responses.GET, GN_URL, status=500)
        responses.add(responses.GET, GN_URL, status=500)
        responses.add(responses.GET, GN_URL, json={"message": "ok"})
        result = query_greynoise("8.8.8.8", api_key=None, pre_request_delay=0)
        assert result["message"] == "ok"
        assert len(responses.calls) == 3

    @patch("greynoise_lookup.lookup.time.sleep")
    @responses.activate
    def test_returns_error_after_max_retries(self, mock_sleep):
        for _ in range(3):
            responses.add(responses.GET, GN_URL, status=500)
        result = query_greynoise("8.8.8.8", api_key=None, pre_request_delay=0)
        assert result["message"] == "API error after 3 attempts"

    @patch("greynoise_lookup.lookup.time.sleep")
    @responses.activate
    def test_rate_limit_429_retries(self, mock_sleep):
        responses.add(responses.GET, GN_URL, status=429)
        responses.add(responses.GET, GN_URL, json={"message": "ok"})
        result = query_greynoise("8.8.8.8", api_key=None, pre_request_delay=0)
        assert result["message"] == "ok"


class TestResolveAsnToNetworks:
    @responses.activate
    def test_returns_network_list(self):
        responses.add(
            responses.GET, SHADOW_URL,
            json=["192.168.0.0/24", "10.0.0.0/16"],
            match=[responses.matchers.query_param_matcher({"prefix": "7029"})],
        )
        networks = resolve_asn_to_networks("7029")
        assert networks == ["192.168.0.0/24", "10.0.0.0/16"]

    @responses.activate
    def test_respects_max_networks(self):
        nets = [f"10.{i}.0.0/24" for i in range(100)]
        responses.add(
            responses.GET, SHADOW_URL, json=nets,
            match=[responses.matchers.query_param_matcher({"prefix": "1234"})],
        )
        result = resolve_asn_to_networks("1234", max_networks=5)
        assert len(result) == 5

    @responses.activate
    def test_http_error_returns_empty(self):
        responses.add(
            responses.GET, SHADOW_URL, status=404,
            match=[responses.matchers.query_param_matcher({"prefix": "9999"})],
        )
        assert resolve_asn_to_networks("9999") == []

    @responses.activate
    def test_invalid_json_returns_empty(self):
        responses.add(
            responses.GET, SHADOW_URL, body="not json",
            match=[responses.matchers.query_param_matcher({"prefix": "5555"})],
        )
        assert resolve_asn_to_networks("5555") == []

    @responses.activate
    def test_filters_invalid_cidrs(self):
        responses.add(
            responses.GET, SHADOW_URL,
            json=["192.168.0.0/24", "not-a-cidr", "10.0.0.0/16", 42],
            match=[responses.matchers.query_param_matcher({"prefix": "1111"})],
        )
        result = resolve_asn_to_networks("1111")
        assert result == ["192.168.0.0/24", "10.0.0.0/16"]


class TestProcessIp:
    @responses.activate
    @patch("greynoise_lookup.lookup.reverse_dns", return_value="dns.google.")
    def test_produces_lookup_result(self, mock_dns, sample_greynoise_success):
        responses.add(responses.GET, GN_URL, json=sample_greynoise_success)
        result = process_ip("8.8.8.8", "8.8.8.8", api_key=None, pre_request_delay=0)
        assert isinstance(result, LookupResult)
        assert result.ptr == "dns.google."
        assert result.riot is True
        assert result.classification == "benign"

    @patch("greynoise_lookup.lookup.time.sleep")
    @responses.activate
    @patch("greynoise_lookup.lookup.reverse_dns", return_value="No PTR")
    def test_handles_api_failure_gracefully(self, mock_dns, mock_sleep):
        for _ in range(3):
            responses.add(responses.GET, GN_URL, status=500)
        result = process_ip("8.8.8.8", "8.8.8.8", api_key=None, pre_request_delay=0)
        assert result.message == "API error after 3 attempts"
        assert result.noise is None
