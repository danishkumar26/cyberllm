# Tests for CyberLLM analyzer (offline, provider-free where possible).

from cyberllm.analyzer import AnalyzedEvent
from cyberllm.config import Settings
from cyberllm.mitre import map_to_mitre


def test_settings_defaults():
    s = Settings()
    assert s.provider == "ollama"
    assert s.model == "llama3.2"
    assert s.enable_mitre is True
    assert s.enable_ti is False


def test_mitre_mapping_known():
    m = map_to_mitre("Failed password for root from 203.0.113.5")
    assert m is not None
    assert m.technique_id == "T1110.001"
    assert m.tactic == "Credential Access"


def test_mitre_mapping_unknown():
    m = map_to_mitre("this is just a normal log line with no indicators")
    assert m is None


def test_mitre_mapping_case_insensitive():
    m1 = map_to_mitre("FAILED PASSWORD for root")
    m2 = map_to_mitre("failed password for root")
    assert m1 is not None and m2 is not None
    assert m1.technique_id == m2.technique_id


def test_analyzed_event_defaults():
    e = AnalyzedEvent(source="test.log", severity="medium", confidence=0.7, summary="test")
    assert e.source == "test.log"
    assert e.severity == "medium"
    assert e.confidence == 0.7
    assert e.indicators == []
    assert e.mitre_technique is None
