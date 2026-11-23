"""Comprehensive offline unit tests for SSRF-hardened ingestion, state store, RSS, and prefilter."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from zerobom.ingest import (
    FetchError,
    IngestStateStore,
    SafeHttpFetcher,
    SsrfBlockedError,
    compute_content_sha256,
    discover_feed_entries,
    extract_article_text,
    extract_known_aliases,
    is_public_ip,
    is_valid_advisory_alias,
    load_sources_config,
    parse_feed_entries,
    parse_html_index_entries,
    parse_sitemap_entries,
    poll_feed_items,
    poll_feeds,
    prefilter_article,
    validate_fetch_url,
)
from zerobom.models import FeedKind, RawArticle, RoutingDecision, SourceFeedConfig, SourceTier

PUBLISHED_AT = datetime(2026, 5, 10, 9, 0, 0, tzinfo=UTC)


def _public_dns(_host: str, _port: int) -> tuple[str, ...]:
    return ("93.184.216.34",)


# ---------------------------------------------------------------------------
# 1. SSRF Defense, Bounded Streaming & HTML/Table Extraction
# ---------------------------------------------------------------------------


class TestSsrfAndFetcher:
    @pytest.mark.parametrize(
        ("ip_str", "expected"),
        [
            ("127.0.0.1", False),
            ("::1", False),
            ("10.0.0.1", False),
            ("172.16.0.1", False),
            ("192.168.1.1", False),
            ("169.254.169.254", False),
            ("fe80::1", False),
            ("::ffff:169.254.169.254", False),
            (".".join(("0", "0", "0", "0")), False),
            ("93.184.216.34", True),
            ("8.8.8.8", True),
            ("2606:4700:4700::1111", True),
        ],
    )
    def test_is_public_ip(self, ip_str: str, expected: bool) -> None:
        assert is_public_ip(ip_str) is expected

    def test_validate_fetch_url_blocks_schemes_creds_crlf_and_private_dns(self) -> None:
        for bad_url in (
            "file:///etc/passwd",
            "ftp://example.org/file",
            "javascript://alert(1)",
            "https://user:pass@example.org/advisory",
            "https://example.org/a\r\nb",
            "https://169.254.169.254/latest/meta-data/",
            "http://[::1]:8080/admin",
        ):
            with pytest.raises(FetchError):
                validate_fetch_url(bad_url, dns_resolver=_public_dns)

        with pytest.raises(SsrfBlockedError):
            validate_fetch_url(
                "https://rebind.example.org/advisory",
                dns_resolver=lambda _h, _p: ("93.184.216.34", "10.0.0.5"),
            )

    def test_redirect_to_imds_blocked_before_request(self) -> None:
        requested_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_urls.append(str(request.url))
            return httpx.Response(
                302,
                headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = SafeHttpFetcher(client=client, dns_resolver=_public_dns)

        with pytest.raises(SsrfBlockedError):
            fetcher.fetch_bytes("https://blog.example.org/redirect")

        # Crucial SSRF invariant: the IMDS URL was never requested over HTTP.
        assert requested_urls == ["https://blog.example.org/redirect"]
        client.close()

    def test_streaming_size_limit_content_type_and_max_redirects(self) -> None:
        class _ChunkedOverflowStream(httpx.SyncByteStream):
            def __iter__(self) -> Iterator[bytes]:
                yield b"x" * 300
                yield b"x" * 300

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url.endswith("/too-big-header"):
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/html", "Content-Length": "999999"},
                    content=b"ok",
                )
            if url.endswith("/too-big-stream"):
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/html"},
                    stream=_ChunkedOverflowStream(),
                )
            if url.endswith("/binary"):
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/octet-stream"},
                    content=b"\x00\x01",
                )
            if "/hop-" in url:
                hop_num = int(url.rsplit("-", 1)[-1])
                return httpx.Response(
                    302,
                    headers={"Location": f"https://blog.example.org/hop-{hop_num + 1}"},
                )
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = SafeHttpFetcher(
            client=client,
            dns_resolver=_public_dns,
            max_bytes=512,
            max_redirects=2,
        )

        with pytest.raises(FetchError, match="Content-Length"):
            fetcher.fetch_bytes("https://blog.example.org/too-big-header")

        with pytest.raises(FetchError, match="max_bytes"):
            fetcher.fetch_bytes("https://blog.example.org/too-big-stream")

        with pytest.raises(FetchError, match="Disallowed Content-Type"):
            fetcher.fetch_bytes("https://blog.example.org/binary")

        with pytest.raises(FetchError, match="redirect limit"):
            fetcher.fetch_bytes("https://blog.example.org/hop-0")

        client.close()

    def test_html_table_and_plain_text_extraction_and_default_redirects(self) -> None:
        html = (
            b"<html><head><title>Pre-CVE Advisory</title></head>"
            b"<body><article><h1>Requests SSRF Advisory</h1>"
            b"<p>A vulnerability affects requests prior to 2.31.0 when forwarding headers.</p>"
            b"<table><tr><th>Package</th><th>Fixed</th></tr>"
            b"<tr><td>requests</td><td>2.31.0</td></tr></table>"
            b"</article></body></html>"
        )

        title, body = extract_article_text(html, "text/html; charset=utf-8")
        assert title
        assert "requests prior to 2.31.0" in body
        assert "2.31.0" in body

        plain_title, plain_body = extract_article_text(
            b"Plain advisory text\x00with control char stripped.",
            "text/plain",
            fallback_title="Plain Title",
        )
        assert plain_title == "Plain Title"
        assert "\x00" not in plain_body
        assert plain_body == "Plain advisory textwith control char stripped."

        with SafeHttpFetcher() as default_fetcher:
            assert default_fetcher.client.follow_redirects is False


# ---------------------------------------------------------------------------
# 2. Parameterized SQLite State Store & Conditional HTTP 304
# ---------------------------------------------------------------------------


class TestIngestStateStore:
    def test_state_tracking_edit_detection_and_conditional_304(self, tmp_path: Path) -> None:
        store = IngestStateStore(tmp_path / "state.sqlite")
        url_a = "https://Blog.Example.org/posts/advisory/?utm_source=rss"
        url_b = "https://blog.example.org/posts/advisory"

        sha_v1 = compute_content_sha256("Initial advisory affecting requests < 2.31.0")
        assert store.has_changed(url_a, sha_v1) is True

        store.mark_seen(
            url_a,
            sha_v1,
            etag='"etag-v1"',
            last_modified="Mon, 15 Mar 2026 10:00:00 GMT",
            advisory_id="PRECVE-2026-1234ABCD",
            routing=RoutingDecision.AUTO,
            seen_at=PUBLISHED_AT,
        )
        assert store.count() == 1
        assert store.has_changed(url_b, sha_v1) is False

        cond = store.conditional_headers(url_b)
        assert cond == {
            "If-None-Match": '"etag-v1"',
            "If-Modified-Since": "Mon, 15 Mar 2026 10:00:00 GMT",
        }

        # Live blog edit changes content hash -> has_changed becomes True!
        sha_v2 = compute_content_sha256("Updated advisory affecting requests < 2.31.1")
        assert store.has_changed(url_b, sha_v2) is True

        # Fetcher respects 304 Not Modified cleanly.
        seen_headers: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_headers.append(dict(request.headers))
            return httpx.Response(304, headers={"ETag": '"etag-v1"'})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = SafeHttpFetcher(client=client, dns_resolver=_public_dns)
        article, resp = fetcher.fetch_article(
            url_b,
            source_name="Example Blog",
            conditional_headers=cond,
        )
        client.close()
        assert article is None
        assert resp.not_modified is True
        assert seen_headers[0].get("if-none-match") == '"etag-v1"'


# ---------------------------------------------------------------------------
# 3. Curated sources.yaml, XML Hardening & Feed Polling
# ---------------------------------------------------------------------------


class TestRssAndSourcesConfig:
    def test_load_repo_sources_yaml_and_reject_invalid_yaml(self, tmp_path: Path) -> None:
        repo_sources = Path(__file__).resolve().parent.parent / "sources.yaml"
        cfg = load_sources_config(repo_sources)
        assert cfg.version == 1
        assert len(cfg.feeds) >= 5
        assert any(feed.tier == SourceTier.TIER_1 for feed in cfg.feeds)
        assert any(feed.tier == SourceTier.TIER_2 for feed in cfg.feeds)

        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("version: 1\nfeeds: not-a-list\n", encoding="utf-8")
        with pytest.raises(ValueError, match="'feeds' must be a list"):
            load_sources_config(bad_yaml)

        with pytest.raises(ValueError, match="does not exist"):
            load_sources_config(tmp_path / "missing.yaml")

    def test_parse_feed_entries_blocks_dtd_and_unsafe_links(self) -> None:
        feed = SourceFeedConfig(
            name="Test Sec",
            url="https://blog.example.org/rss.xml",
            tier=SourceTier.TIER_1,
        )

        xxe_xml = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "bad">]><rss></rss>'
        with pytest.raises(FetchError, match="DOCTYPE/ENTITY"):
            parse_feed_entries(xxe_xml, feed)

        rss_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>Test Sec</title>
            <item>
              <title>Bad JS Link</title>
              <link>javascript://alert(1)</link>
            </item>
            <item>
              <title>Advisory One</title>
              <link>https://blog.example.org/posts/adv-1?utm_source=feed</link>
              <pubDate>Mon, 15 Mar 2026 10:00:00 GMT</pubDate>
            </item>
            <item>
              <title>Duplicate Advisory One</title>
              <link>https://blog.example.org/posts/adv-1</link>
            </item>
            <item>
              <title>Advisory Two</title>
              <link>https://blog.example.org/posts/adv-2</link>
            </item>
          </channel>
        </rss>"""

        entries = parse_feed_entries(rss_xml, feed, max_entries=10)
        assert len(entries) == 2
        assert entries[0].title == "Advisory One"
        assert entries[1].title == "Advisory Two"

        capped = parse_feed_entries(rss_xml, feed, max_entries=1)
        assert len(capped) == 1

    def test_poll_feeds_handles_disabled_unchanged_304_and_edited_articles(
        self,
        tmp_path: Path,
    ) -> None:
        poll_round = [1]

        rss_xml = b"""<?xml version="1.0"?>
        <rss version="2.0"><channel><title>Feed</title>
          <item><title>Post 1</title><link>https://blog.example.org/post-1</link></item>
        </channel></rss>"""

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url == "https://blog.example.org/rss.xml":
                return httpx.Response(
                    200, headers={"Content-Type": "application/xml"}, content=rss_xml
                )
            if url == "https://blog.example.org/post-1":
                if poll_round[0] == 1:
                    return httpx.Response(
                        200,
                        headers={"Content-Type": "text/plain", "ETag": '"v1"'},
                        content=b"Requests SSRF prior to 2.31.0.",
                    )
                if poll_round[0] == 2:
                    assert request.headers.get("if-none-match") == '"v1"'
                    return httpx.Response(304, headers={"ETag": '"v1"'})
                # Round 3: article edited live -> 200 with updated body!
                return httpx.Response(
                    200,
                    headers={"Content-Type": "text/plain", "ETag": '"v2"'},
                    content=b"Updated: Requests SSRF prior to 2.31.1.",
                )
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = SafeHttpFetcher(client=client, dns_resolver=_public_dns)
        store = IngestStateStore(tmp_path / "poll_state.sqlite")
        feeds = (
            SourceFeedConfig(
                name="Active Feed",
                url="https://blog.example.org/rss.xml",
                tier=SourceTier.TIER_1,
                enabled=True,
            ),
            SourceFeedConfig(
                name="Disabled Feed",
                url="https://disabled.example.org/rss.xml",
                tier=SourceTier.TIER_2,
                enabled=False,
            ),
        )

        # Round 1: initial discovery with default mark_seen=False leaves state unmarked so
        # transient downstream extraction errors remain retriable.
        r1 = poll_feeds(feeds, fetcher=fetcher, state_store=store)
        assert len(r1) == 1
        assert "2.31.0" in r1[0].body
        assert store.count() == 0

        # Simulating downstream completion persists hash + ETag validator.
        polled_items = poll_feed_items(feeds, fetcher=fetcher, state_store=store, mark_seen=False)
        assert len(polled_items) == 1
        assert polled_items[0].etag == '"v1"'
        store.mark_seen(
            polled_items[0].article.url,
            polled_items[0].content_sha256,
            etag=polled_items[0].etag,
            last_modified=polled_items[0].last_modified,
        )
        assert store.count() == 1

        # Round 2: 304 Not Modified -> 0 articles.
        poll_round[0] = 2
        r2 = poll_feeds(feeds, fetcher=fetcher, state_store=store)
        assert r2 == ()

        # Round 3: edited live article -> re-emitted without premature mark_seen!
        poll_round[0] = 3
        r3_items = poll_feed_items(feeds, fetcher=fetcher, state_store=store)
        assert len(r3_items) == 1
        assert "2.31.1" in r3_items[0].article.body
        # Unprocessed edit leaves prior v1 hash until caller marks seen.
        stored_before_mark = store.get("https://blog.example.org/post-1")
        assert stored_before_mark is not None
        assert stored_before_mark.content_sha256 == polled_items[0].content_sha256

        client.close()

    def test_load_sources_config_validates_kind_and_url_prefix(self, tmp_path: Path) -> None:
        valid_yaml = tmp_path / "valid_kinds.yaml"
        valid_yaml.write_text(
            "version: 1\nfeeds:\n"
            '  - name: "Vendor Sitemap"\n'
            '    url: "https://vendor.example.org/sitemap.xml"\n'
            '    tier: "tier_1"\n'
            '    kind: "sitemap"\n'
            '    url_prefix: "https://vendor.example.org/blog"\n'
            '  - name: "Blog Html Index"\n'
            '    url: "https://blog.example.org/security/"\n'
            '    tier: "tier_2"\n'
            '    kind: "html_index"\n'
            '    url_prefix: "https://blog.example.org/security/"\n'
            '  - name: "Auto Feed"\n'
            '    url: "https://auto.example.org/feed"\n'
            '    kind: "auto"\n',
            encoding="utf-8",
        )
        cfg = load_sources_config(valid_yaml)
        assert [f.kind for f in cfg.feeds] == [FeedKind.SITEMAP, FeedKind.HTML_INDEX, FeedKind.AUTO]
        assert cfg.feeds[0].url_prefix == "https://vendor.example.org/blog"

        bad_kind = tmp_path / "bad_kind.yaml"
        bad_kind.write_text(
            'version: 1\nfeeds:\n  - name: "X"\n    url: "https://a.example/x"\n    kind: "js"\n',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Invalid source feed kind"):
            load_sources_config(bad_kind)

        missing_prefix = tmp_path / "missing_prefix.yaml"
        missing_prefix.write_text(
            'version: 1\nfeeds:\n  - name: "X"\n'
            '    url: "https://a.example/blog/"\n    kind: "html_index"\n',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="url_prefix"):
            load_sources_config(missing_prefix)

        cross_origin = tmp_path / "cross_origin.yaml"
        cross_origin.write_text(
            'version: 1\nfeeds:\n  - name: "X"\n'
            '    url: "https://a.example/blog/"\n    kind: "html_index"\n'
            '    url_prefix: "https://evil.example/blog/"\n',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="same origin"):
            load_sources_config(cross_origin)

    def test_parse_sitemap_entries_prefix_lastmod_sorting_and_xxe(self) -> None:
        feed = SourceFeedConfig(
            name="Sitemap Sec",
            url="https://vendor.example.org/sitemap.xml",
            tier=SourceTier.TIER_1,
            kind=FeedKind.SITEMAP,
            url_prefix="https://vendor.example.org/blog",
        )

        xxe_sitemap = b'<?xml version="1.0"?><!DOCTYPE urlset [<!ENTITY xxe "bad">]><urlset/>'
        with pytest.raises(FetchError, match="DOCTYPE"):
            parse_sitemap_entries(xxe_sitemap, feed)

        sitemap_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url>
            <loc>https://vendor.example.org/blog/older-advisory</loc>
            <lastmod>2026-01-10T00:00:00Z</lastmod>
          </url>
          <url>
            <loc>https://vendor.example.org/blog-archive/unrelated-post</loc>
            <lastmod>2026-11-18</lastmod>
          </url>
          <url>
            <loc>javascript://alert(1)</loc>
            <lastmod>2026-11-18</lastmod>
          </url>
          <url>
            <loc>https://vendor.example.org/blog/newest-advisory.html</loc>
            <lastmod>2026-11-15</lastmod>
          </url>
          <url>
            <loc>https://vendor.example.org/blog/older-advisory?utm_source=sitemap</loc>
            <lastmod>2026-01-01</lastmod>
          </url>
          <url>
            <loc>https://vendor.example.org/blog/undated-entry</loc>
          </url>
        </urlset>"""

        entries = parse_sitemap_entries(sitemap_xml, feed, max_entries=10)
        assert [e.url for e in entries] == [
            "https://vendor.example.org/blog/newest-advisory.html",
            "https://vendor.example.org/blog/older-advisory",
            "https://vendor.example.org/blog/undated-entry",
        ]
        assert entries[0].title == "newest advisory"
        assert entries[0].published_at == datetime(2026, 11, 15, 0, 0, tzinfo=UTC)

        top_one = parse_sitemap_entries(sitemap_xml, feed, max_entries=1)
        assert [e.url for e in top_one] == ["https://vendor.example.org/blog/newest-advisory.html"]

    def test_parse_html_index_entries_same_origin_prefix_and_exclusions(self) -> None:
        feed = SourceFeedConfig(
            name="Index Blog",
            url="https://blog.example.org/advisories/",
            tier=SourceTier.TIER_1,
            kind=FeedKind.HTML_INDEX,
            url_prefix="https://blog.example.org/advisories/",
        )
        html = b"""<!DOCTYPE html>
        <html>
          <head><title>Security Advisories</title></head>
          <body>
            <script>var decoy = '<a href="/advisories/not-a-link">Fake</a>';</script>
            <nav>
              <a href="/advisories/">All Advisories</a>
              <a href="https://blog.example.org/advisories/#top">Top</a>
              <a href="https://other.example.org/advisories/external-post">External</a>
              <a href="javascript:void(0)">JS</a>
              <a href="mailto:sec@example.org">Mail</a>
              <a href="/careers/security-engineer">Hiring</a>
            </nav>
            <main>
              <a href="/advisories/ruby2shell-rce#details">Critical Ruby2Shell RCE Advisory</a>
              <a href="https://blog.example.org/advisories/ruby2shell-rce?utm_source=web">Dup</a>
              <a href="kernel-update-2026">   </a>
            </main>
          </body>
        </html>"""

        entries = parse_html_index_entries(html, feed)
        assert [e.url for e in entries] == [
            "https://blog.example.org/advisories/ruby2shell-rce",
            "https://blog.example.org/advisories/kernel-update-2026",
        ]
        assert entries[0].title == "Critical Ruby2Shell RCE Advisory"
        assert entries[1].title == "kernel update 2026"

    def test_discover_feed_entries_auto_fallback_and_xxe_safety(self) -> None:
        auto_with_prefix = SourceFeedConfig(
            name="Auto Blog",
            url="https://blog.example.org/posts/",
            tier=SourceTier.TIER_2,
            kind=FeedKind.AUTO,
            url_prefix="https://blog.example.org/posts/",
        )
        auto_no_prefix = SourceFeedConfig(
            name="Auto No Prefix",
            url="https://blog.example.org/feed",
            tier=SourceTier.TIER_2,
            kind=FeedKind.AUTO,
        )

        rss_bytes = b"""<?xml version="1.0"?>
        <rss version="2.0"><channel><title>T</title>
          <item><title>RSS Post</title><link>https://blog.example.org/posts/rss-1</link></item>
        </channel></rss>"""
        assert (
            len(discover_feed_entries(rss_bytes, auto_with_prefix, content_type="application/xml"))
            == 1
        )

        sitemap_bytes = b"""<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://blog.example.org/posts/sm-1</loc></url>
        </urlset>"""
        sm_entries = discover_feed_entries(
            sitemap_bytes, auto_with_prefix, content_type="application/xml"
        )
        assert [e.url for e in sm_entries] == ["https://blog.example.org/posts/sm-1"]

        html_bytes = b"""<!DOCTYPE html>
        <html><body><a href="/posts/html-advisory">HTML Advisory</a></body></html>"""
        html_entries = discover_feed_entries(html_bytes, auto_with_prefix, content_type="text/html")
        assert [e.url for e in html_entries] == ["https://blog.example.org/posts/html-advisory"]
        assert discover_feed_entries(html_bytes, auto_no_prefix, content_type="text/html") == ()

        xxe_xml = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "bad">]><urlset/>'
        with pytest.raises(FetchError, match="DOCTYPE"):
            discover_feed_entries(xxe_xml, auto_with_prefix, content_type="application/xml")


# ---------------------------------------------------------------------------
# 4. Deterministic Pre-LLM Filter
# ---------------------------------------------------------------------------


class TestPrefilter:
    def test_prefilter_passes_precve_and_newly_reserved_cve_drops_marketing(self) -> None:
        precve = RawArticle(
            url="https://blog.example.org/pre-cve",
            title="Zero-day SSRF in Python requests",
            body="We found an unauthenticated SSRF vulnerability in PyPI requests prior to 2.31.0.",
            source_name="Project Zero",
            source_tier=SourceTier.TIER_1,
            published_at=PUBLISHED_AT,
        )
        res_precve = prefilter_article(precve)
        assert res_precve.passed is True
        assert res_precve.score >= 0.7
        assert res_precve.extracted_aliases == ()

        reserved_cve = RawArticle(
            url="https://blog.example.org/reserved-cve",
            title="Prototype pollution in npm lodash (CVE-2026-99999)",
            body=(
                "Tracked as CVE-2026-99999 and GHSA-2345-cfgh-jmpq prior to NVD publication; "
                "upgrade npm lodash before 4.17.21."
            ),
            source_name="Wiz Research",
            source_tier=SourceTier.TIER_1,
            published_at=PUBLISHED_AT,
        )
        res_cve = prefilter_article(reserved_cve)
        assert res_cve.passed is True
        assert res_cve.extracted_aliases == ("CVE-2026-99999", "GHSA-2345-cfgh-jmpq")

        vuln_with_promo = RawArticle(
            url="https://blog.example.org/vuln-footer",
            title="RCE in Apache log4j-core",
            body=(
                "Remote code execution affects Maven log4j-core versions 2.0 to 2.14.1. "
                "Visit our RSA Conference booth next month!"
            ),
            source_name="Research",
            source_tier=SourceTier.TIER_2,
            published_at=PUBLISHED_AT,
        )
        assert prefilter_article(vuln_with_promo).passed is True

        marketing = RawArticle(
            url="https://blog.example.org/series-b",
            title="Announcing our Series B funding and upcoming webinar!",
            body=(
                "Register now for our live webinar, visit our conference booth, and check open "
                "positions—we're hiring across engineering!"
            ),
            source_name="Vendor Blog",
            source_tier=SourceTier.UNKNOWN,
            published_at=PUBLISHED_AT,
        )
        res_mkt = prefilter_article(marketing)
        assert res_mkt.passed is False
        assert len(res_mkt.marketing_signals) >= 3

    def test_extracts_precve_advisory_aliases_and_validates_format(self) -> None:
        zdi_article = RawArticle(
            url="https://cloudlinux.example.org/security/zdi-can-33367",
            title="CloudLinux Advisory Tracking ZDI-CAN-33367 and ZDI-26-101",
            body=(
                "Fixes CloudLinux kernel regression ZDI-CAN-33367 (also seen as TALOS-2026-1234, "
                "VU#123456, RUSTSEC-2026-0001). Already applied CVE-2026-43284? That older patch "
                "does not protect your rpm kernel-5.14.0-687.60.1.el9_8 workloads."
            ),
            source_name="CloudLinux Blog",
            source_tier=SourceTier.TIER_1,
            published_at=PUBLISHED_AT,
        )
        aliases = extract_known_aliases(f"{zdi_article.title}\n{zdi_article.body}")
        assert aliases == (
            "CVE-2026-43284",
            "ZDI-CAN-33367",
            "ZDI-26-101",
            "TALOS-2026-1234",
            "VU#123456",
            "RUSTSEC-2026-0001",
        )
        pf = prefilter_article(zdi_article)
        assert pf.passed is True
        assert "precve_id" in pf.vuln_signals

        assert is_valid_advisory_alias("zdi-can-33367") == "ZDI-CAN-33367"
        assert is_valid_advisory_alias("ghsa-2345-CFGH-jmpq") == "GHSA-2345-cfgh-jmpq"
        assert is_valid_advisory_alias("NOT-AN-ID-123") is None

    def test_expanded_enterprise_vuln_and_software_signals_and_guards(self) -> None:
        smuggling_dotnet = RawArticle(
            url="https://research.example.org/dotnet-smuggling",
            title="HTTP Request Smuggling and JWT Bypass in .NET Core and Keycloak",
            body=(
                "Researchers demonstrated request smuggling against Envoy and .NET Core "
                "for versions < 8.0.12 alongside a Keycloak JWT bypass."
            ),
            source_name="Research Lab",
            source_tier=SourceTier.TIER_1,
            published_at=PUBLISHED_AT,
        )
        res_net = prefilter_article(smuggling_dotnet)
        assert res_net.passed is True
        assert "request_smuggling" in res_net.vuln_signals
        assert "auth_bypass" in res_net.vuln_signals
        assert "enterprise_middleware_web" in res_net.software_signals
        assert "enterprise_iam" in res_net.software_signals
        assert "version_range" in res_net.software_signals

        k8s_edge = RawArticle(
            url="https://research.example.org/k8s-fortios",
            title="Actively Exploited Container Escape in Kubernetes and FortiOS",
            body=(
                "An actively exploited container escape in containerd affects Kubernetes "
                "clusters and FortiOS appliances running unpatched builds."
            ),
            source_name="Research Lab",
            source_tier=SourceTier.TIER_1,
            published_at=PUBLISHED_AT,
        )
        res_k8s = prefilter_article(k8s_edge)
        assert res_k8s.passed is True
        assert {"zero_day", "priv_esc"}.issubset(set(res_k8s.vuln_signals))
        assert {"cloud_native_k8s", "enterprise_edge_vpn"}.issubset(set(res_k8s.software_signals))

        # Regression guard: a single CVE mention must NOT double-count into 2 vuln_signals.
        webinar_with_cve = RawArticle(
            url="https://vendor.example.org/webinar-recap",
            title="Register now for our live webinar mentioning CVE-2026-99999",
            body="Join our live webinar and visit our RSA Conference booth after Series B funding.",
            source_name="Vendor Blog",
            source_tier=SourceTier.UNKNOWN,
            published_at=PUBLISHED_AT,
        )
        res_webinar = prefilter_article(webinar_with_cve)
        assert res_webinar.vuln_signals == ("cve",)
        assert res_webinar.software_signals == ()
        assert res_webinar.passed is False

        # Regression guard: routine product bugfix with prose words ("fixed in", "chart", "vault")
        # must not accidentally trigger both vuln and software gates simultaneously.
        routine_changelog = RawArticle(
            url="https://vendor.example.org/changelog",
            title="Dashboard UI Improvements and Chart Rendering Fixes",
            body=(
                "Minor layout alignment issues were fixed in the analytics chart and dark vault "
                "theme boundary view."
            ),
            source_name="Vendor Blog",
            source_tier=SourceTier.UNKNOWN,
            published_at=PUBLISHED_AT,
        )
        res_changelog = prefilter_article(routine_changelog)
        assert res_changelog.software_signals == ()
        assert res_changelog.passed is False


class TestPreReleaseSecurityRegressions:
    def test_rejects_utf16_le_and_be_entity_expansion_xml(self) -> None:
        feed = SourceFeedConfig(
            name="Untrusted Feed",
            url="https://feed.example.org/rss.xml",
            tier=SourceTier.TIER_2,
        )
        bombs_xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
            '<rss version="2.0"><channel><title>&lol2;</title></channel></rss>'
        )
        for encoding in ("utf-16-le", "utf-16-be", "utf-16"):
            encoded = bombs_xml.encode(encoding)
            with pytest.raises(FetchError, match=r"DOCTYPE|ENTITY|external entity"):
                parse_feed_entries(encoded, feed)

    def test_allows_doctype_and_entity_examples_inside_cdata_while_blocking_real_dtd(
        self,
    ) -> None:
        feed = SourceFeedConfig(
            name="ZDI Style Feed",
            url="https://feed.example.org/rss.xml",
            tier=SourceTier.TIER_1,
        )
        cdata_rss = b"""<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>ZDI Style Feed</title>
            <item>
              <title>Advisory With HTML Snippet In CDATA</title>
              <link>https://feed.example.org/posts/cdata-doctype</link>
              <description><![CDATA[<!DOCTYPE html><p>Example <!ENTITY xxe SYSTEM "file:///etc/passwd"></p>]]></description>
            </item>
          </channel>
        </rss>"""
        entries = parse_feed_entries(cdata_rss, feed)
        assert len(entries) == 1
        assert entries[0].url == "https://feed.example.org/posts/cdata-doctype"

        malformed_dtd = (
            b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY bad "x">]>'
            b"<rss><channel><item><title>Broken</title></rss>"
        )
        with pytest.raises(FetchError, match="DOCTYPE/ENTITY"):
            parse_feed_entries(malformed_dtd, feed)

    def test_fetcher_disables_trust_env_and_uses_versioned_user_agent(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from zerobom._version import DEFAULT_USER_AGENT

        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
        with SafeHttpFetcher() as fetcher:
            assert fetcher.client.trust_env is False
            assert fetcher.client.headers["user-agent"] == DEFAULT_USER_AGENT
