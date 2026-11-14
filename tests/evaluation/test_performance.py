import pytest

from evaluation.performance import format_performance, summarize_performance


def test_efficiency_counts_failed_and_filtered_calls_without_mismatching_throughput_samples():
    rows = [
        {"error": "Filtered", "latency_seconds": 3.2, "llm_requests": [
            {"succeeded": False, "latency_seconds": 2},
            {"succeeded": True, "latency_seconds": 1, "input_tokens": 10, "output_tokens": 20, "total_tokens": 30},
        ]},
        {"latency_seconds": 3.5, "llm_requests": [
            {"succeeded": True, "latency_seconds": 3, "input_tokens": 30, "output_tokens": 60, "total_tokens": 90},
        ]},
        {"latency_seconds": 0.1, "llm_requests": []},
    ]
    usage = summarize_performance(rows)
    assert usage["attempts"] == 3
    assert usage["retry_attempts"] == usage["failed_attempts"] == 1
    assert usage["failed_request_rate"] == pytest.approx(1 / 3)
    assert usage["total_tokens"] == 120
    assert usage["average_total_tokens_per_question"] is None  # Failed request has no token count.
    assert usage["average_request_latency_seconds"] == usage["p50_request_latency_seconds"] == 2
    assert usage["p95_request_latency_seconds"] == pytest.approx(2.9)
    assert usage["p99_request_latency_seconds"] == pytest.approx(2.98)
    assert usage["output_tokens_per_second"] == 20
    assert usage["throughput_reported_attempts"] == 2
    assert usage["questions_with_llm_call"] == 2
    assert format_performance(usage, "total_tokens") == "120 (2/3 calls)"


def test_efficiency_distinguishes_missing_instrumentation_and_zero_calls():
    missing = summarize_performance([{}])
    zero = summarize_performance([{"llm_requests": []}])
    assert missing["attempts"] is missing["total_tokens"] is None
    assert format_performance(missing, "total_tokens") == "NOT RECORDED"
    assert zero["attempts"] == zero["total_tokens"] == zero["average_total_tokens_per_question"] == 0
    assert zero["failed_request_rate"] is zero["output_tokens_per_second"] is None
    assert format_performance(zero, "total_tokens") == "0"


def test_mean_tokens_includes_zero_call_responses_and_requires_full_log_coverage():
    called = {"llm_requests": [{"succeeded": True, "total_tokens": 100, "latency_seconds": 2}]}
    usage = summarize_performance([called, {"llm_requests": []}])
    assert usage["average_total_tokens_per_question"] == 50
    partial = summarize_performance([called, {}])
    assert partial["request_log_coverage"] == 0.5
    assert partial["total_tokens"] == 100
    assert partial["average_total_tokens_per_question"] is None


def test_throughput_uses_only_successful_requests_with_both_usage_and_positive_duration():
    usage = summarize_performance([{"llm_requests": [
        {"succeeded": True, "latency_seconds": 2, "output_tokens": 10},
        {"succeeded": True, "latency_seconds": 20},
        {"succeeded": False, "latency_seconds": 30, "output_tokens": 900},
        {"succeeded": True, "latency_seconds": 0, "output_tokens": 100},
        {"succeeded": True, "latency_seconds": float("nan"), "output_tokens": 100},
    ]}])
    assert usage["throughput_reported_attempts"] == 1
    assert usage["output_tokens_per_second"] == 5


def test_ttft_uses_only_measured_attempts_and_preserves_missing_old_logs():
    usage = summarize_performance([{"llm_requests": [
        {"succeeded": True, "ttft_seconds": 0.2, "latency_seconds": 1},
        {"succeeded": False, "ttft_seconds": 0.8, "latency_seconds": 2},
        {"succeeded": True, "latency_seconds": 3},
    ]}])
    assert usage["average_ttft_seconds"] == 0.5
    assert usage["p95_ttft_seconds"] == pytest.approx(0.77)
    assert usage["ttft_reported_attempts"] == 2
    assert format_performance(usage, "average_ttft_seconds") == "0.500s (2/3 calls)"
    old = summarize_performance([{"llm_requests": [{"succeeded": True, "latency_seconds": 1}]}])
    assert old["average_ttft_seconds"] is None
    assert format_performance(old, "average_ttft_seconds") == "NOT RECORDED"
