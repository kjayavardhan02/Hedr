from app.core.scoring import (
    DEFAULT_SEVERITY,
    DEFAULT_WEIGHT,
    get_severity,
    get_weight,
    grade_for_score,
)


def test_known_headers_return_table_values():
    assert get_weight("content-security-policy") == 40
    assert get_weight("Strict-Transport-Security") == 20  # case-insensitive
    assert get_severity("content-security-policy") == "critical"
    assert get_severity("X-Frame-Options") == "medium"


def test_unknown_header_falls_back_to_defaults():
    assert get_weight("x-totally-made-up-header") == DEFAULT_WEIGHT
    assert get_severity("x-totally-made-up-header") == DEFAULT_SEVERITY


def test_grade_boundaries():
    assert grade_for_score(100) == "A"
    assert grade_for_score(90) == "A"
    assert grade_for_score(89.9) == "B"
    assert grade_for_score(80) == "B"
    assert grade_for_score(79.9) == "C"
    assert grade_for_score(70) == "C"
    assert grade_for_score(69.9) == "D"
    assert grade_for_score(60) == "D"
    assert grade_for_score(59.9) == "F"
    assert grade_for_score(0) == "F"
