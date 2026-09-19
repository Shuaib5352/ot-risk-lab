# Analyst inter-rater agreement

Many OT risk inputs are partly judgment based. v0.6 provides a reproducible way to quantify whether analysts assign subjective categories consistently.

Input format:

```csv
item_id,analyst,rating
SCN-001,Analyst-A,High
SCN-001,Analyst-B,High
```

Run:

```bash
ot-risk-lab agreement examples/analyst_ratings.csv --bootstrap 2000 --format markdown
```

The implementation reports:

- nominal Krippendorff alpha;
- pairwise agreement;
- fraction of items with unanimous ratings;
- item-level bootstrap confidence intervals.

Krippendorff alpha is appropriate here because the nominal form can accommodate more than two analysts and incomplete panels. The metric evaluates **consistency**, not correctness. High analyst agreement does not demonstrate empirical validity of the risk model.
