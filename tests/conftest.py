import pytest

from greynoise_lookup.models import LookupResult


@pytest.fixture()
def sample_greynoise_success() -> dict:
    return {
        "ip": "8.8.8.8",
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google Public DNS",
        "link": "https://viz.greynoise.io/riot/8.8.8.8",
        "last_seen": "2024-01-15",
        "message": "Success",
    }


@pytest.fixture()
def sample_greynoise_not_found() -> dict:
    return {
        "ip": "192.168.1.1",
        "noise": False,
        "riot": False,
        "classification": "unknown",
        "name": "unknown",
        "link": "",
        "last_seen": "",
        "message": "IP not observed scanning the internet or contained in RIOT data set.",
    }


@pytest.fixture()
def sample_lookup_result() -> LookupResult:
    return LookupResult(
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


@pytest.fixture()
def tmp_input_file(tmp_path):
    def _create(lines: list) -> str:
        path = tmp_path / "iplist.txt"
        path.write_text("\n".join(lines) + "\n")
        return str(path)
    return _create
