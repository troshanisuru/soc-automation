# Prototype v1 (superseded)
This was the first working version of the SOC reasoning pipeline:
a single LLM triage call with no deterministic gate, no evidence
validation, and no multi-agent correlation. It has been fully
superseded by ai_engine/, which adds a deterministic correlation
layer, a three-agent chain (triage/MITRE/decision), schema-constrained
evidence validation, and a fail-closed gate before any action.
Kept here for reference only — not imported by anything in ai_engine/.
