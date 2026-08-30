"""Visual similarity detection against a brand's user-uploaded reference
images (core/screenshot.py captures the candidate side; users upload
the reference side via web/api/routes/brands.py). Two distinct
techniques for two distinct questions, deliberately simple rather than
a heavier CV/ML approach:

- `compare_page_similarity` (imagehash perceptual hash): "does this
  whole page look like that whole page?" — catches a cloned/near-
  identical phishing page. Robust to minor rendering differences
  (a few pixels off, slightly different font rendering), which matters
  because the goal is catching something "close enough to trick users,"
  not a byte-identical copy.
- `find_logo_in_screenshot` (OpenCV ORB feature matching): "does this
  specific logo appear somewhere in this screenshot?" — a different
  question from whole-page similarity, since a copied logo can sit in
  one corner of an otherwise different-looking page. Needs local
  feature matching, not a global hash.

Both are optional dependencies (requirements-visual.txt), lazy-imported
so their absence is a clean, caught "no match" rather than a startup
failure — same treatment as core/browser_crawler.py's Playwright import.
Both fail closed: a corrupt/unreadable image returns "no match" rather
than raising, since a badly-uploaded reference image shouldn't take
down the whole pipeline.
"""

import io
from dataclasses import dataclass

# Perceptual-hash Hamming distance (out of 64 bits for the default 8x8
# phash) at or below which two pages count as visually similar. Not
# pixel-identical by design — a convincing clone that's "close enough
# to trick users" should still match, per how this was scoped.
# Calibrated by direct measurement: a lossless
# resave scores 0, a one-character text change scores 4, the same
# layout in a different flat color scores 14; two unrelated random
# pages score 32-36. 18 sits with margin above realistic "same site,
# minor edit" distances and well below "unrelated content."
PHASH_MAX_DISTANCE = 18

# Minimum "good" ORB keypoint matches (Lowe's ratio test, 0.75) to call
# a logo present. Calibrated by direct measurement against a
# multi-feature synthetic logo (shapes + text + a line, not a single
# bare ellipse — real logos have that much detail too): a real match
# scored 18-22 good matches at original and resized scale; two
# unrelated pages scored 0. 12 sits well below real matches and above
# the noise floor.
MIN_LOGO_MATCHES = 12
_LOWE_RATIO = 0.75


@dataclass(frozen=True)
class SimilarityResult:
    is_match: bool
    score: float  # meaning differs by comparison type — see each function
    detail: str


def compare_page_similarity(reference_image: bytes, candidate_image: bytes) -> SimilarityResult:
    try:
        import imagehash
        from PIL import Image

        hash_a = imagehash.phash(Image.open(io.BytesIO(reference_image)))
        hash_b = imagehash.phash(Image.open(io.BytesIO(candidate_image)))
        distance = hash_a - hash_b
    except ImportError:
        return SimilarityResult(is_match=False, score=0.0, detail="imagehash not installed")
    except Exception:
        return SimilarityResult(is_match=False, score=0.0, detail="comparison failed")

    similarity = max(0.0, 1 - distance / 64)
    return SimilarityResult(
        # imagehash/numpy return numpy scalar types (np.bool_, np.int64)
        # here, not plain Python ones — cast explicitly so callers (JSON
        # serialization, `is True`-style identity checks) get real bool.
        is_match=bool(distance <= PHASH_MAX_DISTANCE),
        score=round(float(similarity), 3),
        detail=f"hamming_distance={distance}",
    )


def find_logo_in_screenshot(logo_image: bytes, candidate_image: bytes) -> SimilarityResult:
    try:
        import cv2
        import numpy as np
    except ImportError:
        return SimilarityResult(is_match=False, score=0.0, detail="opencv not installed")

    try:
        logo_arr = cv2.imdecode(np.frombuffer(logo_image, dtype=np.uint8), cv2.IMREAD_GRAYSCALE)
        candidate_arr = cv2.imdecode(
            np.frombuffer(candidate_image, dtype=np.uint8), cv2.IMREAD_GRAYSCALE
        )
        if logo_arr is None or candidate_arr is None:
            return SimilarityResult(is_match=False, score=0.0, detail="decode failed")

        orb = cv2.ORB_create(nfeatures=500)
        _, logo_descriptors = orb.detectAndCompute(logo_arr, None)
        _, candidate_descriptors = orb.detectAndCompute(candidate_arr, None)
        if (
            logo_descriptors is None
            or candidate_descriptors is None
            or len(logo_descriptors) < 2
            or len(candidate_descriptors) < 2
        ):
            return SimilarityResult(is_match=False, score=0.0, detail="insufficient features")

        matcher = cv2.BFMatcher(cv2.NORM_HAMMING)
        matches = matcher.knnMatch(logo_descriptors, candidate_descriptors, k=2)
        good_matches = [m for m, n in matches if m.distance < _LOWE_RATIO * n.distance]
    except Exception:
        return SimilarityResult(is_match=False, score=0.0, detail="comparison failed")

    count = len(good_matches)
    return SimilarityResult(
        is_match=count >= MIN_LOGO_MATCHES, score=float(count), detail=f"good_matches={count}"
    )
