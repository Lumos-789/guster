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

- Resident: one ≤20 KB budget for the user and hub instruction files together
  (they are summed, not budgeted per end); soft line budgets are 150 user / 50 hub.
- Skills: ≤6,000 characters of description in total, ≤500 per skill.
- State: one 90-day SLA for every state document — hub `projects/`, `handoff/`,
  `provision/` and `.agents/plans/`. There is no separate 7- or 30-day tier.
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
