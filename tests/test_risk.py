from core.risk import RiskFactors, bucket_for_score, levenshtein, score_finding, tld_risk_bucket


class TestLevenshtein:
    def test_identical_strings(self):
        assert levenshtein("example", "example") == 0

    def test_one_substitution(self):
        assert levenshtein("example", "exarnple") == 2  # m -> rn is a 2-edit swap
        assert levenshtein("exarnple", "exarnple") == 0

    def test_single_char_typo(self):
        assert levenshtein("example", "examples") == 1
        assert levenshtein("example", "examp1e") == 1

    def test_empty_string(self):
        assert levenshtein("", "abc") == 3
        assert levenshtein("abc", "") == 3


class TestTldRiskBucket:
    def test_common_tlds_are_high_risk(self):
        assert tld_risk_bucket("com") == "high"
        assert tld_risk_bucket("COM") == "high"
        assert tld_risk_bucket("net") == "high"

    def test_other_tlds_are_medium_risk(self):
        assert tld_risk_bucket("xyz") == "medium"


class TestBucketForScore:
    """Same thresholds score_finding derives internally, exposed
    standalone for a caller (worker/pipeline.py's _record_finding)
    that ends up bumping a score after score_finding already ran."""

    def test_matches_score_finding_thresholds(self):
        assert bucket_for_score(0) == "low"
        assert bucket_for_score(29) == "low"
        assert bucket_for_score(30) == "medium"
        assert bucket_for_score(59) == "medium"
        assert bucket_for_score(60) == "high"
        assert bucket_for_score(100) == "high"


class TestScoreFinding:
    def test_low_risk_baseline(self):
        result = score_finding(RiskFactors())
        assert result.bucket == "low"
        assert result.score == 0
        assert result.factors == []

    def test_close_typo_on_risky_tld_with_mail_is_high(self):
        result = score_finding(
            RiskFactors(edit_distance=1, tld="com", has_mx=True, live_https=True)
        )
        assert result.bucket == "high"
        assert "edit_distance<=1" in result.factors
        assert "high_risk_tld" in result.factors
        assert "mx_configured" in result.factors
        assert "live_https" in result.factors

    def test_combosquat_keyword_contributes(self):
        baseline = score_finding(RiskFactors(edit_distance=5))
        with_keyword = score_finding(RiskFactors(edit_distance=5, combosquat_keyword=True))
        assert with_keyword.score > baseline.score
        assert "combosquat_keyword" in with_keyword.factors

    def test_score_never_exceeds_100(self):
        result = score_finding(
            RiskFactors(
                edit_distance=1,
                tld="com",
                has_mx=True,
                live_https=True,
                combosquat_keyword=True,
            )
        )
        assert result.score <= 100
