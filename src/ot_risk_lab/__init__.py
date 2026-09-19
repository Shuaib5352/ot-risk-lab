"""OT-RiskLab: transparent stochastic cyber-risk modeling for ICS/OT research."""

from .agreement import RatingRecord, agreement_diagnostics
from .doctor import runtime_diagnostics
from .markov import MarkovResult, simulate_attack_progression
from .models import (
    AnalysisConfig,
    AssessmentMetadata,
    AssetContext,
    ControlContext,
    DecisionContext,
    MarkovConfig,
    MitigationContext,
    RiskModelConfig,
    SimulationConfig,
    ThreatContext,
)
from .monte_carlo import MonteCarloResult, SensitivityEntry, run_monte_carlo
from .risk import baseline_risk, residual_risk
from .schema import analysis_config_schema, analysis_config_schema_text
from .study import StudyRecord, bootstrap_metric_intervals, evaluate_study
from .version import SOFTWARE_VERSION

__all__ = [
    "AnalysisConfig",
    "AssessmentMetadata",
    "AssetContext",
    "ControlContext",
    "DecisionContext",
    "MarkovConfig",
    "MitigationContext",
    "RiskModelConfig",
    "SimulationConfig",
    "ThreatContext",
    "baseline_risk",
    "residual_risk",
    "MonteCarloResult",
    "SensitivityEntry",
    "run_monte_carlo",
    "MarkovResult",
    "simulate_attack_progression",
    "StudyRecord",
    "bootstrap_metric_intervals",
    "evaluate_study",
    "RatingRecord",
    "agreement_diagnostics",
    "analysis_config_schema",
    "analysis_config_schema_text",
    "runtime_diagnostics",
]

__version__ = SOFTWARE_VERSION
