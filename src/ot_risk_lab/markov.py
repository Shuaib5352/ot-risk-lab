from __future__ import annotations

from dataclasses import dataclass

from .models import MarkovConfig

STATES = ("secure", "reconnaissance", "exploitation", "compromised")


def transition_matrix(normalized_risk: float, params: MarkovConfig | None = None) -> list[list[float]]:
    """Create a monotone four-state attack-progression transition matrix.

    The compromised state is absorbing. Coefficients are reference parameters and
    are configurable because the default values are not presented as calibrated
    incident transition rates.
    """
    params = params or MarkovConfig()
    r = max(0.0, min(1.0, float(normalized_risk)))
    p_sr = params.secure_to_recon_base + params.secure_to_recon_scale * r
    p_re = params.recon_to_exploit_base + params.recon_to_exploit_scale * r
    p_ec = params.exploit_to_compromise_base + params.exploit_to_compromise_scale * r
    return [
        [1.0 - p_sr, p_sr, 0.0, 0.0],
        [0.0, 1.0 - p_re, p_re, 0.0],
        [0.0, 0.0, 1.0 - p_ec, p_ec],
        [0.0, 0.0, 0.0, 1.0],
    ]


def _step(distribution: list[float], matrix: list[list[float]]) -> list[float]:
    return [sum(distribution[i] * matrix[i][j] for i in range(4)) for j in range(4)]


@dataclass(frozen=True)
class MarkovResult:
    states: tuple[str, str, str, str]
    matrix: tuple[tuple[float, float, float, float], ...]
    history: tuple[tuple[float, float, float, float], ...]

    @property
    def final(self) -> dict[str, float]:
        return dict(zip(self.states, self.history[-1]))

    @property
    def compromise_probability(self) -> float:
        return self.history[-1][3]

    @property
    def expected_compromise_step_within_horizon(self) -> float | None:
        final_probability = self.compromise_probability
        if final_probability <= 0.0:
            return None
        weighted = 0.0
        previous = self.history[0][3]
        for step, row in enumerate(self.history[1:], start=1):
            entered = max(0.0, row[3] - previous)
            weighted += step * entered
            previous = row[3]
        return weighted / final_probability

    def as_dict(self) -> dict[str, object]:
        return {
            "states": list(self.states),
            "matrix": [list(row) for row in self.matrix],
            "history": [list(row) for row in self.history],
            "final": self.final,
            "compromise_probability": self.compromise_probability,
            "expected_compromise_step_within_horizon": self.expected_compromise_step_within_horizon,
        }


def simulate_attack_progression(
    normalized_risk: float,
    steps: int = 24,
    params: MarkovConfig | None = None,
) -> MarkovResult:
    if steps < 1:
        raise ValueError("steps must be >= 1")
    matrix = transition_matrix(normalized_risk, params)
    distribution = [1.0, 0.0, 0.0, 0.0]
    history: list[tuple[float, float, float, float]] = [tuple(distribution)]  # type: ignore[arg-type]
    for _ in range(steps):
        distribution = _step(distribution, matrix)
        history.append(tuple(distribution))  # type: ignore[arg-type]
    frozen_matrix = tuple(tuple(float(v) for v in row) for row in matrix)
    return MarkovResult(STATES, frozen_matrix, tuple(history))
