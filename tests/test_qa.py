"""Q&A over run results: retrieval stays grounded in the run state and answers are fact-checked."""
from __future__ import annotations

import pytest

from core.llm import MockLLM
from core.paths import DATA_DIR, load_json
from core.qa import answer, detect_topics
from graph import run


@pytest.fixture(scope="module")
def faulty():
    return run(load_json("alerts.json"), {"data_dir": str(DATA_DIR), "mode": "mock", "fault_mode": "all"})


def top(state):
    return max(state["incidents"], key=lambda i: i["severity"])


def test_critical_is_not_the_critic_topic():
    assert "critic" not in detect_topics("Why is INC-002 critical?")
    assert "critic" in detect_topics("What did the Critic reject?")


def test_why_question_explains_the_score_with_alert_ids(faulty):
    inc = top(faulty)
    r = answer(f"Why is {inc['id']} critical?", faulty, MockLLM())
    assert r["incidents"] == [inc["id"]]
    assert any(f"score {inc['severity']} = 45" in f for f in r["facts"])
    assert r["alerts"] and r["fact_check"]["passed"]


def test_entity_lookup_by_ip_and_host(faulty):
    assert answer("Tell me about 185.220.101.45", faulty, MockLLM())["incidents"] == [top(faulty)["id"]]
    r = answer("What should we do about the phishing on WS-MKT07?", faulty, MockLLM())
    assert len(r["incidents"]) == 1 and any("playbook step" in f for f in r["facts"])


def test_critic_question_lists_rejections(faulty):
    facts = answer("What did the Critic reject?", faulty, MockLLM())["facts"]
    assert len(facts) == 3 and all("REJECTED" in f for f in facts)


def test_research_and_factcheck_topics(faulty):
    assert "LLM" in answer("How did the Research agent investigate?", faulty, MockLLM())["facts"][0]
    assert "rewritten" in answer("Did the fact-check catch anything?", faulty, MockLLM())["facts"][0]


def test_off_topic_question_is_declined(faulty):
    assert answer("what is the weather", faulty, MockLLM())["answer"].startswith("I can only answer")
