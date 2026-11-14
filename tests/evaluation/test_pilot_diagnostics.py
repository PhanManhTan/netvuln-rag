from evaluation.pilot import answer_diagnostics


def test_unsupported_upgrade_is_flagged_without_erasing_a_correct_primary_claim():
    diagnostic = answer_diagnostics("OpenSSH 9.6p1 bị ảnh hưởng. Khuyến nghị cập nhật lên 9.6p2.",
                                    "OpenSSH 9.6p1 affected", "OpenSSH 9.6p1 on Ubuntu 24.04")
    assert diagnostic["unsupported_recommendation_versions"] == ["9.6p2"]


def test_known_labels_do_not_imply_complete_semantic_correctness():
    diagnostic = answer_diagnostics("Khuyến nghị cập nhật lên 9.8p1.", "Fixed version 9.8p1.", "OpenSSH 9.6p1")
    assert diagnostic["unsupported_recommendation_versions"] == []
    assert diagnostic["scope"] == "heuristic_diagnostics_not_complete_semantic_scoring"


def test_open_ended_range_does_not_match_the_pilots_bounded_official_interval():
    diagnostic = answer_diagnostics("Ảnh hưởng từ 9.0p1 trở lên.", "", "OpenSSH 9.6p1")
    assert diagnostic["unbounded_range_conflicts"] == [{"claimed_lower": "9.0p1", "claimed_upper": None,
                                                       "official_lower": "8.5p1", "official_upper": "9.7p1"}]
