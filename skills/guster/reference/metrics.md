# Guster Metrics

## Core metrics

| ID | Metric | Target |
|---|---|---:|
| SSR | single-source rate | ≥95% |
| RBR | resident budget ratio | ≤100% |
| PCR | placement compliance rate | ≥90% |
| ICR | index coverage rate | knowledge 100%, `.agents` ≥90% |
| FRS | state freshness rate | ≥90% |
| PHR | pointer health rate | 100% |
| SIR | secret isolation rate | ≥95% |
| GCR | governance complexity ratio | ≤0.5 |

## Targets

- Resident: ≤20 KB per end; skills ≤6,000 characters total, ≤500 per item.
- State: active project 30 days, handoff 7 days, environment 90 days.
- Knowledge: index every durable file; review every 90–180 days.
- Secrets: 0 in git; 1 canonical root; 0 inline tokens.

## CHI

The Context Health Index is a dashboard, not a KPI:

```text
CHI = 0.20 SSR + 0.15 RBR + 0.15 PCR + 0.15 ICR
    + 0.15 FRS + 0.10 PHR + 0.10 SIR
```

Red-line failures override the score: credential in git, broken resident
pointer, duplicate canonical source, resident hard-cap breach, or a governance
entry pointing at an archived asset.
