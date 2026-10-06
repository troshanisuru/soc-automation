"""Validated, cached configuration loaders.

This is the only module that reads config/reference files. Everything is validated at
load time and **fails closed** (ConfigError) rather than silently falling back to
hard-coded defaults: a silent fallback inside a security gate hides tampering and typos.
Loaded objects are immutable (frozen dataclasses / read-only mappings) and cached, so
the files are parsed once, not on every agent call.
"""

import json
import math
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse

import yaml

CONFIG_DIR = Path(__file__).resolve().parent
REFERENCE_DIR = CONFIG_DIR.parent / "reference"
THRESHOLDS_PATH = CONFIG_DIR / "thresholds.yaml"
MODELS_PATH = CONFIG_DIR / "models.yaml"
MITRE_PATH = REFERENCE_DIR / "mitre_attack.json"

MAX_CONFIG_BYTES = 1_000_000
WEIGHT_KEYS = ("mitre_severity", "asset_criticality", "source_diversity", "signature_confidence")
AGENT_NAMES = ("triage_agent", "mitre_agent", "decision_agent")

_MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9._:\-/]{1,100}$")
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}$")
_KEEP_ALIVE_RE = re.compile(r"^(\d{1,5}[smh]|0|-1)$")


class ConfigError(RuntimeError):
    """Raised when configuration is missing, malformed, or out of range."""


# --------------------------------------------------------------------------- helpers
def _read_text(path: Path) -> str:
    try:
        if not path.is_file():
            raise ConfigError(f"Missing config file: {path}")
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"Config file too large: {path}")
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc


def _read_yaml(path: Path) -> Dict[str, Any]:
    try:
        data = yaml.safe_load(_read_text(path))  # safe_load: never constructs arbitrary objects
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping at the top level")
    return data


def _number(value: Any, name: str, lo: float, hi: float, *, integer: bool = False) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be a number (got {value!r})")
    if not math.isfinite(value):
        raise ConfigError(f"{name} must be finite")
    if integer and int(value) != value:
        raise ConfigError(f"{name} must be an integer (got {value!r})")
    if not lo <= value <= hi:
        raise ConfigError(f"{name}={value} out of range [{lo}, {hi}]")
    return int(value) if integer else float(value)


def _section(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"'{key}' section is missing or not a mapping")
    return value


# --------------------------------------------------------------------------- thresholds
@dataclass(frozen=True)
class Thresholds:
    autonomous_threshold: float
    soft_threshold: float
    weights: Mapping[str, float]
    tactic_weights: Mapping[str, float]
    asset_tiers: Mapping[str, float]
    asset_default: float
    window_seconds: int
    max_incident_seconds: int
    max_events_per_incident: int
    max_open_incidents: int
    dedupe_ttl_seconds: int
    dedupe_max_entries: int
    processing_ttl_seconds: int
    cooldown_seconds: int


def load_thresholds(path: Optional[Path] = None) -> Thresholds:
    data = _read_yaml(path or THRESHOLDS_PATH)
    corr, gate = _section(data, "correlation"), _section(data, "gate")

    raw_weights = _section(data, "weights")
    if set(raw_weights) != set(WEIGHT_KEYS):
        raise ConfigError(f"weights must have exactly the keys {WEIGHT_KEYS}")
    weights = {k: _number(raw_weights[k], f"weights.{k}", 0.0, 1.0) for k in WEIGHT_KEYS}
    if not math.isclose(sum(weights.values()), 1.0, abs_tol=1e-6):
        raise ConfigError(f"weights must sum to 1.0 (got {sum(weights.values())})")

    autonomous = _number(gate.get("autonomous_threshold"), "gate.autonomous_threshold", 0.0, 1.0)
    soft = _number(gate.get("soft_threshold"), "gate.soft_threshold", 0.0, 1.0)
    if not soft < autonomous:
        raise ConfigError("gate.soft_threshold must be strictly below gate.autonomous_threshold")

    tactic_weights = {
        str(k): _number(v, f"tactic_weights.{k}", 0.0, 1.0)
        for k, v in _section(data, "tactic_weights").items()
    }
    if not tactic_weights:
        raise ConfigError("tactic_weights must not be empty")

    asset = _section(data, "asset_criticality")
    tiers = {
        str(k).lower(): _number(v, f"asset_criticality.tiers.{k}", 0.0, 1.0)
        for k, v in _section(asset, "tiers").items()
    }

    return Thresholds(
        autonomous_threshold=autonomous,
        soft_threshold=soft,
        weights=MappingProxyType(weights),
        tactic_weights=MappingProxyType(tactic_weights),
        asset_tiers=MappingProxyType(tiers),
        asset_default=_number(asset.get("default"), "asset_criticality.default", 0.0, 1.0),
        window_seconds=_number(corr.get("window_seconds"), "correlation.window_seconds", 1, 3600, integer=True),
        max_incident_seconds=_number(corr.get("max_incident_seconds"), "correlation.max_incident_seconds", 1, 86400, integer=True),
        max_events_per_incident=_number(corr.get("max_events_per_incident"), "correlation.max_events_per_incident", 1, 100000, integer=True),
        max_open_incidents=_number(corr.get("max_open_incidents"), "correlation.max_open_incidents", 1, 10_000_000, integer=True),
        dedupe_ttl_seconds=_number(corr.get("dedupe_ttl_seconds"), "correlation.dedupe_ttl_seconds", 1, 604800, integer=True),
        dedupe_max_entries=_number(corr.get("dedupe_max_entries"), "correlation.dedupe_max_entries", 1, 100_000_000, integer=True),
        processing_ttl_seconds=_number(corr.get("processing_ttl_seconds"), "correlation.processing_ttl_seconds", 1, 86400, integer=True),
        cooldown_seconds=_number(data.get("cooldown_seconds"), "cooldown_seconds", 0, 604800, integer=True),
    )


# --------------------------------------------------------------------------- models
@dataclass(frozen=True)
class AgentConfig:
    agent_name: str
    model: str
    num_predict: int
    temperature: float
    timeout_seconds: float
    num_ctx: int
    keep_alive: str
    base_url: str


def load_models(path: Optional[Path] = None) -> Mapping[str, AgentConfig]:
    data = _read_yaml(path or MODELS_PATH)

    raw_url = os.environ.get("OLLAMA_BASE_URL") or data.get("ollama_base_url")
    if not isinstance(raw_url, str):
        raise ConfigError("ollama_base_url must be a string")
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError("ollama_base_url must be an http(s) URL with a host")
    if parsed.username or parsed.password:
        raise ConfigError("ollama_base_url must not embed credentials")

    allowed = data.get("allowed_hosts")
    if not isinstance(allowed, list) or not allowed or not all(isinstance(h, str) for h in allowed):
        raise ConfigError("allowed_hosts must be a non-empty list of host names")
    if parsed.hostname.lower() not in {h.lower() for h in allowed}:
        raise ConfigError(f"Ollama host {parsed.hostname!r} is not in allowed_hosts")
    base_url = f"{parsed.scheme}://{parsed.netloc}"  # drop any path/query/fragment

    defaults = data.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise ConfigError("'defaults' must be a mapping")

    agents: Dict[str, AgentConfig] = {}
    for name in AGENT_NAMES:
        raw = data.get(name)
        if not isinstance(raw, dict):
            raise ConfigError(f"Missing or invalid config for {name}")
        merged = {**defaults, **raw}
        model = merged.get("model")
        if not isinstance(model, str) or not _MODEL_NAME_RE.match(model):
            raise ConfigError(f"{name}.model is missing or has illegal characters")
        keep_alive = str(merged.get("keep_alive", "5m"))
        if not _KEEP_ALIVE_RE.match(keep_alive):
            raise ConfigError(f"{name}.keep_alive {keep_alive!r} is invalid (e.g. '30m')")
        agents[name] = AgentConfig(
            agent_name=name,
            model=model,
            num_predict=_number(merged.get("num_predict"), f"{name}.num_predict", 16, 4096, integer=True),
            temperature=_number(merged.get("temperature"), f"{name}.temperature", 0.0, 2.0),
            timeout_seconds=_number(merged.get("timeout_seconds", 60), f"{name}.timeout_seconds", 1, 600),
            num_ctx=_number(merged.get("num_ctx", 4096), f"{name}.num_ctx", 1024, 131072, integer=True),
            keep_alive=keep_alive,
            base_url=base_url,
        )
    return MappingProxyType(agents)


# --------------------------------------------------------------------------- MITRE reference
@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


def load_mitre_reference(path: Optional[Path] = None) -> Mapping[str, Technique]:
    try:
        data = json.loads(_read_text(path or MITRE_PATH))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in MITRE reference: {exc}") from exc
    items = data.get("techniques") if isinstance(data, dict) else None
    if not isinstance(items, list) or not items:
        raise ConfigError("MITRE reference must contain a non-empty 'techniques' list")

    reference: Dict[str, Technique] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ConfigError("Each MITRE technique must be an object")
        tid, name, tactic = item.get("id"), item.get("name"), item.get("tactic")
        if not isinstance(tid, str) or not _TECHNIQUE_ID_RE.match(tid):
            raise ConfigError(f"Invalid MITRE technique id: {tid!r}")
        if not isinstance(name, str) or not name or not isinstance(tactic, str) or not tactic:
            raise ConfigError(f"Technique {tid} needs a non-empty name and tactic")
        if tid in reference:
            raise ConfigError(f"Duplicate MITRE technique id: {tid}")
        reference[tid] = Technique(id=tid, name=name, tactic=tactic)
    return MappingProxyType(reference)


# --------------------------------------------------------------------------- cached accessors
@lru_cache(maxsize=1)
def get_thresholds() -> Thresholds:
    return load_thresholds()


@lru_cache(maxsize=1)
def _models() -> Mapping[str, AgentConfig]:
    return load_models()


def get_agent_config(agent_name: str) -> AgentConfig:
    try:
        return _models()[agent_name]
    except KeyError:
        raise ConfigError(f"Unknown agent {agent_name!r}; expected one of {AGENT_NAMES}") from None


@lru_cache(maxsize=1)
def get_mitre_reference() -> Mapping[str, Technique]:
    return load_mitre_reference()


def reload_config() -> None:
    """Drop cached config (used by tests and an explicit operator reload)."""
    get_thresholds.cache_clear()
    _models.cache_clear()
    get_mitre_reference.cache_clear()


def validate_all_config() -> None:
    """Fail-fast startup check: raises ConfigError if anything is wrong or inconsistent."""
    thresholds = get_thresholds()
    for name in AGENT_NAMES:
        get_agent_config(name)
    for technique in get_mitre_reference().values():
        if technique.tactic not in thresholds.tactic_weights:
            raise ConfigError(
                f"Technique {technique.id} uses tactic {technique.tactic!r} with no entry in tactic_weights"
            )
