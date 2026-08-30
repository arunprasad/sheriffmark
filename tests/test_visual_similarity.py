"""Tests for core/visual_similarity.py. Both comparison functions are
tested for real (not mocked) — the value here is in the heuristic
actually working, not in the import boundary — but the whole module is
skipped via importorskip if requirements-visual.txt isn't installed,
same "optional dependency" treatment as everywhere else in core/.

Thresholds and test fixtures here were calibrated by direct
measurement, not guessed — see core/visual_similarity.py's threshold
comments for the numbers. An earlier version of
this test used a nearly-blank page and a single-ellipse "logo," which
turned out to be poor stand-ins for real content (a flat page is
unrealistically sensitive to any added detail; a 3-shape logo doesn't
give ORB enough to latch onto) — both were found and fixed via this
same live-calibration pass, not assumed correct on the first write.
"""

import io
import random

import pytest

pytest.importorskip("imagehash")
pytest.importorskip("cv2")

from PIL import Image, ImageDraw  # noqa: E402

from core.visual_similarity import compare_page_similarity, find_logo_in_screenshot  # noqa: E402


def _png_bytes(image: Image.Image) -> bytes:
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


def _login_page(button_text: str = "Sign in", size=(400, 300)) -> Image.Image:
    """A page busy enough to be a realistic phash subject — a single
    flat-color page is unrealistically sensitive to any added detail,
    which is exactly what an earlier version of this test got wrong."""
    img = Image.new("RGB", size, color=(245, 246, 248))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, size[0], 60], fill=(30, 100, 220))  # header band
    draw.text((20, 20), "Acme Bank", fill=(255, 255, 255))
    draw.rectangle([100, 100, 300, 130], fill=(255, 255, 255))  # email field
    draw.rectangle([100, 145, 300, 175], fill=(255, 255, 255))  # password field
    draw.rectangle([100, 190, 300, 220], fill=(30, 100, 220))  # button
    draw.text((150, 198), button_text, fill=(255, 255, 255))
    draw.text((100, 250), "Forgot your password?", fill=(100, 100, 100))
    return img


def _noise_page(seed: int, size=(400, 300)) -> bytes:
    rng = random.Random(seed)
    img = Image.new("RGB", size)
    pixels = img.load()
    for x in range(size[0]):
        for y in range(size[1]):
            pixels[x, y] = (rng.randrange(256), rng.randrange(256), rng.randrange(256))
    return _png_bytes(img)


class TestComparePageSimilarity:
    def test_identical_images_match(self):
        page = _png_bytes(_login_page())

        result = compare_page_similarity(page, page)

        assert result.is_match is True
        assert result.score == 1.0
        assert isinstance(result.is_match, bool)  # not a numpy bool leaking through

    def test_minor_edit_still_matches(self):
        """A convincing clone doesn't need to be pixel-identical — per
        how this was scoped: 'close enough to trick users' should
        count. A one-word button change is exactly that kind of edit."""
        original = _login_page(button_text="Sign in")
        clone = _login_page(button_text="Log in")

        result = compare_page_similarity(_png_bytes(original), _png_bytes(clone))

        assert result.is_match is True

    def test_same_layout_different_color_scheme_still_matches(self):
        original = _login_page()
        recolored = Image.new("RGB", (400, 300), color=(245, 246, 248))
        draw = ImageDraw.Draw(recolored)
        draw.rectangle([0, 0, 400, 60], fill=(180, 30, 30))  # different header color
        draw.text((20, 20), "Acme Bank", fill=(255, 255, 255))
        draw.rectangle([100, 100, 300, 130], fill=(255, 255, 255))
        draw.rectangle([100, 145, 300, 175], fill=(255, 255, 255))
        draw.rectangle([100, 190, 300, 220], fill=(180, 30, 30))
        draw.text((150, 198), "Sign in", fill=(255, 255, 255))
        draw.text((100, 250), "Forgot your password?", fill=(100, 100, 100))

        result = compare_page_similarity(_png_bytes(original), _png_bytes(recolored))

        assert result.is_match is True

    def test_unrelated_random_images_do_not_match(self):
        page_a = _noise_page(seed=1)
        page_b = _noise_page(seed=2)

        result = compare_page_similarity(page_a, page_b)

        assert result.is_match is False

    def test_corrupt_image_fails_closed(self):
        result = compare_page_similarity(b"not-an-image", b"also-not-an-image")

        assert result.is_match is False
        assert result.score == 0.0


class TestFindLogoInScreenshot:
    def _logo(self) -> Image.Image:
        """Enough distinct features (outline, filled polygon, text, a
        diagonal line) for ORB to find real keypoints — a bare single
        shape turned out to be too little detail to match reliably."""
        logo = Image.new("RGB", (160, 160), color=(255, 255, 255))
        draw = ImageDraw.Draw(logo)
        draw.ellipse([10, 10, 150, 150], outline=(30, 100, 220), width=6)
        draw.polygon([(80, 30), (120, 90), (80, 150), (40, 90)], fill=(30, 100, 220))
        draw.rectangle([60, 70, 100, 110], fill=(255, 255, 255))
        draw.text((20, 20), "ACME", fill=(20, 20, 20))
        draw.line([(0, 0), (160, 160)], fill=(200, 0, 0), width=2)
        return logo

    def test_logo_pasted_into_a_page_is_detected(self):
        logo = self._logo()
        page = Image.new("RGB", (600, 450), color=(245, 245, 245))
        draw = ImageDraw.Draw(page)
        draw.rectangle([0, 0, 600, 90], fill=(230, 230, 230))  # header band
        page.paste(logo, (40, 15))
        draw.text((250, 300), "Some other page content here", fill=(0, 0, 0))

        result = find_logo_in_screenshot(_png_bytes(logo), _png_bytes(page))

        assert result.is_match is True

    def test_resized_logo_is_still_detected(self):
        logo = self._logo()
        resized = logo.resize((100, 100))
        page = Image.new("RGB", (600, 450), color=(245, 245, 245))
        page.paste(resized, (300, 200))

        result = find_logo_in_screenshot(_png_bytes(logo), _png_bytes(page))

        assert result.is_match is True

    def test_logo_absent_from_an_unrelated_page_is_not_detected(self):
        logo = self._logo()
        unrelated_page = _noise_page(seed=42, size=(600, 450))

        result = find_logo_in_screenshot(_png_bytes(logo), unrelated_page)

        assert result.is_match is False

    def test_logo_absent_from_a_plain_text_page_is_not_detected(self):
        logo = self._logo()
        plain_page = Image.new("RGB", (600, 450), color=(245, 245, 245))
        draw = ImageDraw.Draw(plain_page)
        draw.text((250, 300), "Just a normal page, no logo here", fill=(0, 0, 0))

        result = find_logo_in_screenshot(_png_bytes(logo), _png_bytes(plain_page))

        assert result.is_match is False

    def test_corrupt_image_fails_closed(self):
        result = find_logo_in_screenshot(b"not-an-image", b"also-not-an-image")

        assert result.is_match is False
        assert result.score == 0.0
