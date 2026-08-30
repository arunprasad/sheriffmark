from core.spa_detection import detect_spa


class TestDetectSpa:
    def test_create_react_app_shell_is_flagged(self):
        html = """<html><head></head><body>
        <noscript>You need to enable JavaScript to run this app.</noscript>
        <div id="root"></div>
        <script src="/static/js/main.abc123.chunk.js"></script>
        </body></html>"""

        signal = detect_spa(html, visible_text="")

        assert signal.is_spa is True
        assert "noscript_fallback_text" in signal.reasons
        assert "root_mount:root" in signal.reasons

    def test_vue_app_shell_is_flagged(self):
        html = (
            '<html><body><div id="app"></div>'
            '<script src="/static/js/app.js"></script></body></html>'
        )

        signal = detect_spa(html, visible_text="")

        assert signal.is_spa is True
        assert "root_mount:app" in signal.reasons

    def test_angular_marker_is_flagged_even_with_some_text(self):
        html = '<html ng-version="17.0.0"><body><app-root>Loading…</app-root></body></html>'

        signal = detect_spa(html, visible_text="Loading…")

        assert signal.is_spa is True
        assert "framework_marker:ng-version" in signal.reasons

    def test_nextjs_marker_is_flagged(self):
        html = (
            '<html><body><div id="__next"></div>'
            "<script>window.__NEXT_DATA__={}</script></body></html>"
        )

        signal = detect_spa(html, visible_text="")

        assert signal.is_spa is True
        assert any(r.startswith("root_mount:__next") for r in signal.reasons)
        assert "framework_marker:__NEXT_DATA__" in signal.reasons

    def test_ordinary_server_rendered_page_is_not_flagged(self):
        html = "<html><body><h1>Welcome</h1><p>Real content, lots of it.</p></body></html>"
        text = "Welcome " + "Real content, lots of it. " * 10

        signal = detect_spa(html, visible_text=text)

        assert signal.is_spa is False
        assert signal.reasons == ()

    def test_short_text_alone_is_not_enough_without_a_bundle_script(self):
        """A genuinely minimal but real page (e.g. a coming-soon
        placeholder) shouldn't be flagged just for being short."""
        html = "<html><body><h1>Coming soon</h1></body></html>"

        signal = detect_spa(html, visible_text="Coming soon")

        assert signal.is_spa is False

    def test_short_text_with_bundle_script_is_flagged(self):
        html = (
            "<html><body><div>Loading</div>"
            '<script src="/static/js/2.def456.chunk.js"></script></body></html>'
        )

        signal = detect_spa(html, visible_text="Loading")

        assert signal.is_spa is True
        assert "short_text_with_bundle_script" in signal.reasons

    def test_next_js_static_path_counts_as_a_bundle_script(self):
        html = (
            "<html><body><div>x</div>"
            '<script src="/_next/static/chunks/main.js"></script></body></html>'
        )

        signal = detect_spa(html, visible_text="x")

        assert signal.is_spa is True
        assert "short_text_with_bundle_script" in signal.reasons
