## Summary

Describe the change and why it is needed.

## Validation

- [ ] Unit tests added/updated where appropriate
- [ ] `ruff check src tests`
- [ ] `python -m compileall -q src tests`
- [ ] `coverage run -m unittest discover -s tests -v`
- [ ] Core regression benchmark passes or intentional drift is documented
- [ ] No sensitive OT/site data included
- [ ] User-facing methodology/report changes documented

## Scientific-impact note

State whether the change modifies equations, default coefficients, stochastic behavior, output schema, or only software/UX behavior. If numerical outputs intentionally change, explain the expected benchmark drift.
