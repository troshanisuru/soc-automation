import pytest

from ai_engine.config.loader import ConfigError
from ai_engine.gate import validator as validator_module
from ai_engine.gate.scoring import (
    _decide,
    apply_gate,
    compute_risk_score,
    determine_final_decision,
    get_asset_criticality,
    technique_severity,
)
from ai_engine.gate.validator import validate_incident_state
from ai_engine.tests.helpers import fill_stages, make_event, make_incident


@pytest.fixture
def prod_incident():
    """Scenario A shape: WAF + Wazuh evidence against a prod web asset."""
    return make_incident(
        [
            make_event("evt-101", 0, source="waf", severity=9, asset="prod-web-server"),
            make_event("evt-102", 5, source="wazuh", severity=8, asset="prod-web-server"),
        ]
    )


def moderate_incident(action="soft_rate_limit"):
    inc = make_incident([make_event("evt-201", 0, source="wazuh", severity=6, asset="internal-web")], asset="internal-web")
    return fill_stages(inc, techniques=("T1110",), action=action, cite=("evt-201",))


def low_incident():
    inc = make_incident([make_event("evt-301", 0, source="flowlog", severity=2, asset="dev-box")], asset="dev-box")
    return fill_stages(inc, techniques=("T1595",), action="soft_rate_limit", cite=("evt-301",))


# ------------------------------------------------------------------ validator
def test_validator_detects_hallucinated_event_ids(prod_incident):
    fill_stages(prod_incident)
    prod_incident.triage.cited_event_ids.append("evt-fake-999")
    validate_incident_state(prod_incident)
    assert len(prod_incident.validation_errors) == 1
    assert "evt-fake-999" in prod_incident.validation_errors[0]


def test_validator_detects_unknown_mitre_technique(prod_incident):
    fill_stages(prod_incident, techniques=("T9999",))  # well-formed but not in the reference
    validate_incident_state(prod_incident)
    assert len(prod_incident.validation_errors) == 1
    assert "T9999" in prod_incident.validation_errors[0]


def test_validator_clean_state_passes(prod_incident):
    validate_incident_state(fill_stages(prod_incident))
    assert prod_incident.validation_errors == []


def test_validator_is_idempotent_across_stage_calls(prod_incident):
    fill_stages(prod_incident, techniques=("T9999",))
    for _ in range(3):  # it runs after every stage and re-checks the whole state
        validate_incident_state(prod_incident)
    assert len(prod_incident.validation_errors) == 1


def test_validator_rejects_empty_citations(prod_incident):
    """An agent must not be able to pass the evidence check by citing nothing."""
    fill_stages(prod_incident, cite=())
    validate_incident_state(prod_incident)
    assert any("Triage cited no evidence" in e for e in prod_incident.validation_errors)
    assert any("MITRE agent cited no evidence" in e for e in prod_incident.validation_errors)
    assert any("Decision agent cited no evidence" in e for e in prod_incident.validation_errors)


def test_validator_allows_uncited_no_action(prod_incident):
    fill_stages(prod_incident, action="no_action")
    prod_incident.decision.cited_event_ids.clear()
    validate_incident_state(prod_incident)
    assert not any("Decision" in e for e in prod_incident.validation_errors)


def test_validator_flags_justification_for_unproposed_technique(prod_incident):
    fill_stages(prod_incident, techniques=("T1190",))
    prod_incident.mitre.justification["T1021"] = "not proposed"
    validate_incident_state(prod_incident)
    assert any("T1021" in e for e in prod_incident.validation_errors)


def test_validator_fails_closed_when_reference_unavailable(prod_incident, monkeypatch):
    def boom():
        raise ConfigError("reference missing")

    monkeypatch.setattr(validator_module, "load_mitre_techniques", boom)
    fill_stages(prod_incident)
    validate_incident_state(prod_incident)  # must not raise
    assert any("fail closed" in e for e in prod_incident.validation_errors)
    assert determine_final_decision(prod_incident) == "escalate"


# ------------------------------------------------------------------ scoring and decisions
def test_high_risk_scenario_is_autonomous(prod_incident):
    fill_stages(prod_incident)  # T1190 + T1071 (C2), 2 sources, prod asset, severity 9
    state = apply_gate(prod_incident)
    assert state.risk_score >= 0.75
    assert state.final_decision == "autonomous"


def test_moderate_risk_with_soft_action_is_soft_contain():
    state = apply_gate(moderate_incident("soft_rate_limit"))
    assert 0.45 <= state.risk_score < 0.75
    assert state.final_decision == "soft_contain"


def test_soft_tier_with_invasive_action_escalates():
    """Plan section 5: soft tier executes only soft_rate_limit, otherwise escalate."""
    state = apply_gate(moderate_incident("block_ip_waf"))
    assert 0.45 <= state.risk_score < 0.75
    assert state.final_decision == "escalate"


def test_low_risk_escalates():
    state = apply_gate(low_incident())
    assert state.risk_score < 0.45
    assert state.final_decision == "escalate"


def test_validation_errors_force_escalate_even_at_high_score(prod_incident):
    fill_stages(prod_incident)
    prod_incident.decision.cited_event_ids.append("evt-fake-hallucination")
    validate_incident_state(prod_incident)
    state = apply_gate(prod_incident)
    assert state.risk_score >= 0.75           # score alone would be autonomous...
    assert state.final_decision == "escalate"  # ...but errors override it


@pytest.mark.parametrize("stage", ["triage", "mitre", "decision"])
def test_failed_agent_stage_forces_escalate(prod_incident, stage):
    """Regression: a None stage (timeout/crash) previously did not force escalation."""
    fill_stages(prod_incident)
    setattr(prod_incident, stage, None)
    assert apply_gate(prod_incident).final_decision == "escalate"


def test_no_action_on_high_risk_incident_escalates(prod_incident):
    """A model that wants to ignore a high-risk incident looks like a successful injection."""
    fill_stages(prod_incident, action="no_action")
    state = apply_gate(prod_incident)
    assert state.risk_score >= 0.75
    assert state.final_decision == "escalate"


def test_preset_risk_score_is_never_trusted():
    state = low_incident()
    state.risk_score = 1.0  # forged / stale
    assert determine_final_decision(state) == "escalate"


def test_threshold_comparison_uses_unrounded_score(prod_incident):
    """Regression: rounding to 3 d.p. before comparing let 0.7496 count as >= 0.75."""
    fill_stages(prod_incident, action="soft_rate_limit")
    assert _decide(prod_incident, 0.7496, 0.75, 0.45) == "soft_contain"
    fill_stages(prod_incident, action="block_ip_waf")
    assert _decide(prod_incident, 0.75, 0.75, 0.45) == "autonomous"


def test_score_counts_only_cited_events(prod_incident):
    fill_stages(prod_incident, cite=("evt-101",))
    one_source = compute_risk_score(prod_incident)
    fill_stages(prod_incident, cite=("evt-101", "evt-102"))
    two_sources = compute_risk_score(prod_incident)
    assert two_sources > one_source


def test_score_is_bounded_and_deterministic(prod_incident):
    fill_stages(prod_incident)
    scores = {compute_risk_score(prod_incident) for _ in range(5)}
    assert len(scores) == 1 and 0.0 <= scores.pop() <= 1.0


# ------------------------------------------------------------------ asset map / severity
@pytest.mark.parametrize(
    "tag,expected",
    [
        ("prod-web-server", 0.9),   # highest matching token wins
        ("db01", 1.0),              # trailing digits stripped
        ("dev-db", 1.0),            # conservative: highest tier wins
        ("Wazuh-Mgmt", 0.85),
        ("feedback-web", 0.7),      # regression: substring 'db' inside 'feedback' used to give 1.0
        ("latest-box", 0.5),        # regression: substring 'test' inside 'latest' used to give 0.2
        ("unknown-host", 0.5),      # default
    ],
)
def test_asset_criticality_uses_whole_tokens(tag, expected):
    assert get_asset_criticality(tag) == expected


def test_lateral_movement_outranks_initial_access():
    assert technique_severity("T1021") > technique_severity("T1190")


def test_unknown_technique_never_raises_the_score():
    assert technique_severity("T9999") == 0.0
