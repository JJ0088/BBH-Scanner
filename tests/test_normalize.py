from bbh_scanner.normalize import (
    detect_and_normalize,
    ensure_https_root,
    is_static_asset,
    normalize_url,
    reduce_urls,
    sha256_hex,
    strip_wildcard_to_domain,
)


def test_wildcard():
    assert detect_and_normalize("*.example.com") == ("wildcard", "*.example.com")


def test_bare_domain_becomes_https_root():
    ntype, nval = detect_and_normalize("example.com")
    assert ntype == "domain"
    assert nval == "https://example.com/"


def test_api_detection_by_host():
    ntype, nval = detect_and_normalize("api.example.com")
    assert ntype == "api"
    assert nval == "https://api.example.com/"


def test_api_detection_by_path():
    ntype, _ = detect_and_normalize("https://example.com/api/v1")
    assert ntype == "api"


def test_plain_url():
    ntype, nval = detect_and_normalize("https://example.com/login#frag")
    assert ntype == "url"
    assert "#frag" not in nval


def test_strip_wildcard():
    assert strip_wildcard_to_domain("*.foo.com") == "foo.com"


def test_ensure_https_root():
    assert ensure_https_root("foo.com") == "https://foo.com/"
    assert ensure_https_root("https://foo.com/") == "https://foo.com/"


def test_normalize_url_strips_tracking():
    assert normalize_url("https://a.com/x?utm_source=b&id=1") == "https://a.com/x?id=1"
    assert normalize_url("https://a.com/x?utm_source=b") == "https://a.com/x"


def test_is_static_asset():
    assert is_static_asset("https://a.com/app.css")
    assert not is_static_asset("https://a.com/api")


def test_reduce_urls_dedup_and_filter():
    urls = [
        "https://a.com/x#f",
        "https://a.com/x",
        "https://a.com/logo.png",
        "https://a.com/y?utm_source=z",
        "https://a.com/y",
    ]
    out = reduce_urls(urls)
    assert "https://a.com/logo.png" not in out
    assert out.count("https://a.com/x") == 1
    assert out.count("https://a.com/y") == 1


def test_sha256_hex_order_independent():
    assert sha256_hex(["a", "b", "c"]) == sha256_hex(["c", "a", "b"])
