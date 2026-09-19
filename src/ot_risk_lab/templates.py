from __future__ import annotations


def starter_config() -> dict[str, object]:
    """Return a documented starter configuration users can edit."""
    return {
        "metadata": {
            "assessment_id": "RISK-001",
            "analyst": "",
            "organization": "",
            "scope": "Example OT scenario",
            "notes": [],
        },
        "asset": {
            "name": "Example PLC",
            "asset_type": "PLC",
            "zone": "Process Control",
            "criticality": 0.8,
            "safety_impact": 0.7,
            "availability_impact": 0.8,
            "internet_exposure": 0.1,
            "legacy_factor": 0.4,
        },
        "threat": {
            "name": "Example remote compromise scenario",
            "cvss": 8.0,
            "likelihood": 0.4,
            "likelihood_basis": "analyst",
            "impact": 0.8,
            "techniques": [],
            "cve_ids": [],
            "epss_probability": None,
            "epss_percentile": None,
            "cisa_kev": False,
            "evidence_date": None,
        },
        "mitigation": {
            "manual_effectiveness": 0.0,
            "controls": [
                {
                    "control_id": "CTRL-001",
                    "name": "OT/IT segmentation",
                    "effectiveness": 0.5,
                    "coverage": 0.8,
                    "confidence": 0.7,
                    "implementation": 1.0,
                    "csf_function": "PROTECT",
                    "evidence": "",
                    "reference": "",
                }
            ],
        },
        "simulation": {
            "iterations": 10000,
            "uncertainty": 0.1,
            "distribution": "truncated_normal",
            "seed": 42,
            "markov_steps": 24,
        },
        "decision": {
            "risk_tolerance": 30.0,
            "tolerance_label": "example-only; replace with organizational criterion",
        },
    }
