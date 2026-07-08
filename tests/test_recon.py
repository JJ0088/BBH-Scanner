from bbh_scanner.recon.passive import build_subfinder_seeds, run_passive
from bbh_scanner.recon.tools import ToolStatus


def test_build_subfinder_seeds():
    scopes = [
        {"normalized_type": "wildcard", "normalized_value": "*.acme.com"},
        {"normalized_type": "domain", "normalized_value": "https://foo.acme.com/"},
        {"normalized_type": "url", "normalized_value": "https://x.com/login"},  # ignorato
    ]
    seeds = build_subfinder_seeds(scopes)
    assert "acme.com" in seeds
    assert "foo.acme.com" in seeds
    assert all("login" not in s for s in seeds)


def test_run_passive_skips_when_no_tools(tmp_path):
    scopes = [{"normalized_type": "wildcard", "normalized_value": "*.acme.com"}]
    tools = {
        "subfinder": ToolStatus("subfinder", False, None),
        "dnsx": ToolStatus("dnsx", False, None),
        "httpx": ToolStatus("httpx", False, None),
    }
    result = run_passive("acme", scopes, tmp_path, tools=tools)
    # senza tool, cade sui seed come punto di partenza e salta gli step
    assert "subfinder" in result.skipped_steps
    assert "httpx" in result.skipped_steps
    assert result.subdomains == ["acme.com"]


def test_run_passive_no_seeds(tmp_path):
    result = run_passive("acme", [], tmp_path)
    assert "no-seeds" in result.skipped_steps
