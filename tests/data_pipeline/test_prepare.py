import sys
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from config.settings import Settings
from data_pipeline import prepare


@pytest.mark.parametrize(("statuses", "expected"), [([0, 0], 0), ([2], 2), ([0, 1], 1)])
def test_prepare_with_evaluation_propagates_status(monkeypatch, statuses, expected):
    settings = Settings()
    monkeypatch.setattr(prepare, "get_settings", lambda: settings)
    monkeypatch.setattr(prepare, "check_new_collection", Mock())
    monkeypatch.setattr(prepare, "crawl_product", Mock(return_value={settings.data_source: settings.raw_data_dir / "pinned"}))
    monkeypatch.setattr(prepare, "process_data", Mock(return_value=[{"product_id": "openssh", "record_count": 1, "chunk_count": 1}]))
    index = Mock(return_value=1)
    monkeypatch.setattr(prepare, "build_index", index)
    runner = Mock(side_effect=[SimpleNamespace(returncode=status) for status in statuses])
    monkeypatch.setattr(prepare.subprocess, "run", runner)
    monkeypatch.setattr(sys, "argv", ["prepare", "--product", "openssh", "--evaluate", "--eval-limit", "5"])

    assert prepare.main() == expected
    index.assert_called_once()
    commands = [
        call([sys.executable, "-m", "evaluation.build", "--from-processed"], check=False),
        call([sys.executable, "-m", "evaluation.run", "--modes", "llm_raw", "llm_bm25", "rag", "--limit", "5"], check=False),
    ]
    assert runner.call_args_list == commands[:len(statuses)]
