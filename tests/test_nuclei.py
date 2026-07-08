from bbh_scanner.active.nuclei import build_targets, parse_nuclei_jsonl


def test_parse_jsonl():
    text = (
        '{"template-id":"tls-version","info":{"name":"TLS","severity":"info"},'
        '"matched-at":"https://a.com","host":"a.com"}\n'
        '{"template-id":"cve-2021-1","info":{"name":"RCE","severity":"high"},'
        '"matched-at":"https://b.com/x","host":"b.com"}\n'
        'riga-non-json\n'
    )
    findings = parse_nuclei_jsonl(text)
    assert len(findings) == 2
    assert findings[0].template_id == "tls-version"
    assert findings[0].severity == "info"
    assert findings[1].severity == "high"
    assert findings[1].name == "RCE"


def test_parse_empty():
    assert parse_nuclei_jsonl("") == []


def test_build_targets_merges_and_reduces():
    scopes = [
        {"normalized_value": "https://api.acme.com/"},
        {"normalized_value": "https://acme.com/login"},
        {"normalized_value": "https://acme.com/app.css"},  # asset statico → scartato
    ]
    alive = ["https://web.acme.com/", "https://api.acme.com/"]  # dup con scope
    targets = build_targets(scopes, alive)
    assert "https://api.acme.com/" in targets
    assert "https://web.acme.com/" in targets
    assert targets.count("https://api.acme.com/") == 1     # dedup
    assert all("app.css" not in t for t in targets)         # statico rimosso
