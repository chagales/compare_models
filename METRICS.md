# Metrics Reference

## Detection Metrics

Standard precision/recall metrics for CVE and CWE code extraction:

- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1-Score** = 2 × (Precision × Recall) / (Precision + Recall)

Where:
- **TP (True Positives)**: Correctly identified vulnerability codes
- **FP (False Positives)**: Incorrectly identified codes
- **FN (False Negatives)**: Missed vulnerability codes

## REIN Metrics (Relevant Information)

Metrics that evaluate response quality beyond exact code matching:

### Response Classification

- **Ui (Useful Information)**: Responses containing at least one correct code
- **Ni (Irrelevant Information)**: Responses with codes but all incorrect
- **Mi (Missing Information)**: Responses without any vulnerability codes

### Calculated Metrics

- **REINP (Precision)** = Ui / (Ui + Ni)
  - Proportion of useful responses among all responses with codes

- **REINR (Recall)** = Ui / (Ui + Mi)
  - Proportion of useful responses among all potential useful responses

- **REINF1** = 2 × (REINP × REINR) / (REINP + REINR)
  - Harmonic mean of REINP and REINR

- **REIN Rate** = Ni / (Ui + Ni)
  - Proportion of irrelevant information (lower is better)

- **REIN FN Rate** = Mi / (Ui + Mi)
  - Proportion of missing information (lower is better)

## Interpretation

| Metric | Good Value | Bad Value | Meaning |
|--------|------------|-----------|---------|
| F1-Score | >20% | <5% | Detection accuracy |
| REINF1 | >50% | <20% | Information quality |
| REINR | 100% | <80% | Response completeness |
| REIN Rate | <30% | >80% | Error rate |
| REIN FN Rate | 0% | >50% | Missing response rate |

## Example

For a model generating 100 CWE responses:
- 49 responses with correct codes (Ui = 49)
- 51 responses with incorrect codes (Ni = 51)
- 0 responses without codes (Mi = 0)

Results:
- REINP = 49/(49+51) = 49%
- REINR = 49/(49+0) = 100%
- REINF1 = 2×0.49×1.0/(0.49+1.0) = 65.77%
- REIN Rate = 51/(49+51) = 51%
- REIN FN Rate = 0/(49+0) = 0%

**Interpretation:** Model always provides a response (REINR=100%), but half contain incorrect information (REIN Rate=51%).
