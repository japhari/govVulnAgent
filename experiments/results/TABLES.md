# Experiment Tables

## Main Results

| Model | Precision | Recall | F1 | FPR | MTTS (s/KLOC) |
|---|---:|---:|---:|---:|---:|
| Semgrep | 1.000 | 0.518 | 0.683 | 0.000 | 868.56 |
| GovVulnAgent | 0.778 | 0.778 | 0.778 | 0.222 | 2405.01 |

## Ablation

| Configuration | F1 | ΔF1 | MTTS (s/KLOC) |
|---|---:|---:|---:|
| full | 0.778 | +0.000 | 2423.83 |
| no_static | 0.778 | +0.000 | 823.54 |
| no_rag | 0.778 | +0.000 | 2431.56 |
| no_cot | 0.000 | -0.778 | 3314.34 |
| single_agent | 0.000 | -0.778 | 1661.66 |
