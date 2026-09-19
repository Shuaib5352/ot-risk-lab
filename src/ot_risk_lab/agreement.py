from __future__ import annotations

import csv
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
import random
from typing import Iterable


@dataclass(frozen=True)
class RatingRecord:
    item_id: str
    analyst: str
    rating: str

    def __post_init__(self) -> None:
        for field_name in ("item_id", "analyst", "rating"):
            value = str(getattr(self, field_name)).strip()
            if not value:
                raise ValueError(f"{field_name} must not be empty")
            object.__setattr__(self, field_name, value)


def load_ratings_csv(path: Path) -> list[RatingRecord]:
    rows: list[RatingRecord] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"item_id", "analyst", "rating"}
        missing = sorted(required - set(reader.fieldnames or ()))
        if missing:
            raise ValueError("ratings CSV missing required column(s): " + ", ".join(missing))
        seen: set[tuple[str, str]] = set()
        for line_number, row in enumerate(reader, start=2):
            record = RatingRecord(row.get("item_id") or "", row.get("analyst") or "", row.get("rating") or "")
            key = (record.item_id, record.analyst)
            if key in seen:
                raise ValueError(f"line {line_number}: analyst {record.analyst!r} rated item {record.item_id!r} more than once")
            seen.add(key)
            rows.append(record)
    if not rows:
        raise ValueError("ratings CSV contains no ratings")
    return rows


def _nominal_alpha(records: Iterable[RatingRecord]) -> tuple[float | None, float, float, int, int, int, int]:
    by_item: dict[str, list[str]] = defaultdict(list)
    analysts: set[str] = set()
    categories: Counter[str] = Counter()
    total_ratings = 0
    for record in records:
        by_item[record.item_id].append(record.rating)
        analysts.add(record.analyst)
        categories[record.rating] += 1
        total_ratings += 1
    usable = {item: ratings for item, ratings in by_item.items() if len(ratings) >= 2}
    if not usable:
        raise ValueError("agreement analysis requires at least one item rated by two or more analysts")

    disagreement_pairs = 0
    total_pairs = 0
    agreement_pairs = 0
    unanimous = 0
    for ratings in usable.values():
        counts = Counter(ratings)
        n = len(ratings)
        ordered_pairs = n * (n - 1)
        agreeing = sum(count * (count - 1) for count in counts.values())
        agreement_pairs += agreeing
        disagreement_pairs += ordered_pairs - agreeing
        total_pairs += ordered_pairs
        if len(counts) == 1:
            unanimous += 1

    observed_disagreement = disagreement_pairs / total_pairs
    n_total = sum(categories.values())
    if n_total < 2:
        expected_disagreement = 0.0
    else:
        expected_disagreement = sum(count * (n_total - count) for count in categories.values()) / (n_total * (n_total - 1))
    alpha = None if expected_disagreement == 0.0 else 1.0 - (observed_disagreement / expected_disagreement)
    pairwise_agreement = agreement_pairs / total_pairs
    unanimous_fraction = unanimous / len(usable)
    return (
        alpha,
        pairwise_agreement,
        unanimous_fraction,
        len(by_item),
        len(usable),
        len(analysts),
        len(categories),
    )


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile requires data")
    position = (len(ordered) - 1) * q
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    fraction = position - low
    return ordered[low] * (1 - fraction) + ordered[high] * fraction


def agreement_diagnostics(
    records: list[RatingRecord],
    *,
    bootstrap: int = 1000,
    confidence: float = 0.95,
    seed: int = 42,
) -> dict[str, object]:
    if bootstrap < 100:
        raise ValueError("bootstrap repetitions must be >= 100")
    if not 0.5 < confidence < 1.0:
        raise ValueError("confidence must be between 0.5 and 1.0")
    alpha, pairwise, unanimous, item_count, usable_items, analysts, categories = _nominal_alpha(records)

    by_item: dict[str, list[RatingRecord]] = defaultdict(list)
    for record in records:
        by_item[record.item_id].append(record)
    usable_groups = [group for group in by_item.values() if len(group) >= 2]
    rng = random.Random(seed)
    alpha_samples: list[float] = []
    pair_samples: list[float] = []
    for _ in range(bootstrap):
        sampled: list[RatingRecord] = []
        for index in range(len(usable_groups)):
            group = usable_groups[rng.randrange(len(usable_groups))]
            sampled.extend(RatingRecord(f"boot-{index}", row.analyst, row.rating) for row in group)
        boot_alpha, boot_pair, *_ = _nominal_alpha(sampled)
        if boot_alpha is not None:
            alpha_samples.append(boot_alpha)
        pair_samples.append(boot_pair)
    tail = (1.0 - confidence) / 2.0
    alpha_ci = None if not alpha_samples else [_percentile(alpha_samples, tail), _percentile(alpha_samples, 1.0 - tail)]
    pair_ci = [_percentile(pair_samples, tail), _percentile(pair_samples, 1.0 - tail)]

    return {
        "method": "Krippendorff nominal alpha with item-level bootstrap",
        "items_total": item_count,
        "items_with_two_or_more_ratings": usable_items,
        "analysts": analysts,
        "categories": categories,
        "ratings": len(records),
        "krippendorff_alpha_nominal": alpha,
        "krippendorff_alpha_bootstrap_ci": alpha_ci,
        "pairwise_agreement": pairwise,
        "pairwise_agreement_bootstrap_ci": pair_ci,
        "unanimous_item_fraction": unanimous,
        "confidence": confidence,
        "bootstrap_repetitions": bootstrap,
        "seed": seed,
        "interpretation": (
            "Agreement statistics quantify consistency of subjective ratings; they do not establish rating validity. "
            "Items with fewer than two ratings are excluded from agreement coefficients."
        ),
    }


def render_agreement_markdown(result: dict[str, object]) -> str:
    alpha = result["krippendorff_alpha_nominal"]
    alpha_text = "n/a" if alpha is None else f"{float(alpha):.4f}"
    alpha_ci = result["krippendorff_alpha_bootstrap_ci"]
    alpha_ci_text = "n/a" if alpha_ci is None else f"{float(alpha_ci[0]):.4f}–{float(alpha_ci[1]):.4f}"
    pair_ci = result["pairwise_agreement_bootstrap_ci"]
    return "\n".join(
        [
            "# OT-RiskLab Analyst Agreement Diagnostics",
            "",
            f"- Method: **{result['method']}**",
            f"- Items: **{result['items_total']}** (usable: {result['items_with_two_or_more_ratings']})",
            f"- Analysts: **{result['analysts']}**",
            f"- Rating categories: **{result['categories']}**",
            f"- Nominal Krippendorff alpha: **{alpha_text}** (bootstrap CI {alpha_ci_text})",
            f"- Pairwise agreement: **{float(result['pairwise_agreement']):.4f}** "
            f"(bootstrap CI {float(pair_ci[0]):.4f}–{float(pair_ci[1]):.4f})",
            f"- Unanimous item fraction: **{float(result['unanimous_item_fraction']):.4f}**",
            "",
            str(result["interpretation"]),
            "",
        ]
    )
