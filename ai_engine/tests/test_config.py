import copy

import pytest
import yaml

from ai_engine.config import loader
from ai_engine.config.loader import (
    ConfigError,
    get_agent_config,
    load_mitre_reference,
    load_models,
    load_thresholds,
    reload_config,
    validate_all_config,
)


@pytest.fixture(autouse=True)
def fresh_config(monkeypatch):
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    reload_config()
    yield
    reload_config()


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data) if not isinstance(data, str) else data)
    return path


def default(path):
    return yaml.safe_load(path.read_text())


def test_shipped_configuration_is_valid_and_consistent():
    validate_all_config()  # incl. every technique tactic having a tactic weight


def test_agent_configs_are_cached_and_immutable():
    assert get_agent_config("triage_agent") is get_agent_config("triage_agent")
    with pytest.raises(Exception):
        get_agent_config("triage_agent").model = "other"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["weights"].update(mitre_severity=0.9),                    # does not sum to 1
        lambda d: d["gate"].update(soft_threshold=0.9),                       # soft >= autonomous
        lambda d: d["gate"].update(autonomous_threshold=1.5),                 # out of range
        lambda d: d["weights"].pop("source_diversity"),                       # missing weight
        lambda d: d["correlation"].update(window_seconds=-5),
        lambda d: d["correlation"].update(window_seconds=float("nan")),
        lambda d: d.pop("tactic_weights"),
        lambda d: d["asset_criticality"]["tiers"].update(db="high"),
    ],
)
def test_bad_thresholds_fail_closed(tmp_path, mutate):
    data = copy.deepcopy(default(loader.THRESHOLDS_PATH))
    mutate(data)
    with pytest.raises(ConfigError):
        load_thresholds(write(tmp_path, "t.yaml", data))


def test_missing_and_malformed_files_fail_closed(tmp_path):
    with pytest.raises(ConfigError):
        load_thresholds(tmp_path / "nope.yaml")
    with pytest.raises(ConfigError):
        load_thresholds(write(tmp_path, "bad.yaml", "a: [unclosed"))
    with pytest.raises(ConfigError):
        load_thresholds(write(tmp_path, "list.yaml", "- 1\n- 2\n"))


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example:11434",         # host not allow-listed
        "file:///etc/passwd",                # wrong scheme
        "ftp://localhost/x",
        "http://user:pw@localhost:11434",    # embedded credentials
        "localhost:11434",                   # no scheme
    ],
)
def test_ollama_url_is_restricted(monkeypatch, url):
    monkeypatch.setenv("OLLAMA_BASE_URL", url)
    with pytest.raises(ConfigError):
        load_models()


def test_allowed_host_via_env_is_accepted_and_normalised(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/some/path?x=1")
    assert load_models()["triage_agent"].base_url == "http://127.0.0.1:11434"


@pytest.mark.parametrize(
    "patch_agent",
    [{"model": "llama3;rm -rf"}, {"temperature": 9}, {"num_predict": 0}, {"keep_alive": "forever"}, {"num_ctx": 10}],
)
def test_bad_agent_settings_fail_closed(tmp_path, patch_agent):
    data = copy.deepcopy(default(loader.MODELS_PATH))
    data["triage_agent"].update(patch_agent)
    with pytest.raises(ConfigError):
        load_models(write(tmp_path, "m.yaml", data))


def test_unknown_agent_is_an_error_not_a_silent_default():
    with pytest.raises(ConfigError):
        get_agent_config("tryage_agent")


def test_mitre_reference_rejects_bad_entries(tmp_path):
    cases = [
        '{"techniques": []}',
        '{"techniques": [{"id": "T1190.001", "name": "x", "tactic": "y"}]}',
        '{"techniques": [{"id": "T1190", "name": "x", "tactic": "y"}, {"id": "T1190", "name": "x", "tactic": "y"}]}',
        '{"techniques": [{"id": "T1190", "name": "", "tactic": "y"}]}',
        "not json",
    ]
    for i, body in enumerate(cases):
        p = tmp_path / f"m{i}.json"
        p.write_text(body)
        with pytest.raises(ConfigError):
            load_mitre_reference(p)


def test_reference_covers_both_plan_scenarios():
    ref = load_mitre_reference()
    for needed in ("T1190", "T1071", "T1021", "T1210"):  # web exploit -> C2, lateral movement
        assert needed in ref
