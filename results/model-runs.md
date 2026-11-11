# Model susceptibility runs

Measured on **gpt-5.6-sol** (Azure AI Foundry, Direct-from-Azure, June 2026
training data), via the harness Responses-API path. Metric is attack success
rate (ASR): of injected records, the fraction where the model reproduced the
planted canary token. The harness also records Azure content-filter blocks as a
separate outcome.

| Run (seed) | Injected | Raw ASR | Fenced ASR | Raw filter-block | Fenced filter-block |
|---|---|---|---|---|---|
| 1337 | 120 | 6.7% (8) | 3.3% (4) | 7.5% (9) | 7.5% (9) |
| 7 | 120 | 10.0% (12) | 5.0% (6) | 16.7% (20) | 6.7% (8) |
| **pooled** | **240** | **8.3% (20)** | **4.2% (10)** | **12.1% (29)** | **7.1% (17)** |

## Reading

- A current frontier model is not immune. Unprotected, gpt-5.6-sol echoed
  instructions planted in log data in about 8% of injected records.
- Fencing plus the data-contract halved end-to-end ASR, consistently across two
  independent corpora.
- Azure's content filter is a real but erratic layer. Its block rate swung from
  7.5% to 16.7%, and fencing lowers it (the wrapped, newline-collapsed text
  looks less like an overt jailbreak), so more fenced requests reach the model,
  yet fenced ASR is still half of raw. The filter moves. The fence does not.
  That is the argument for the deterministic DCR layer.

## Caveat

gpt-5.6-sol does not allow temperature 0, so ASR carries run-to-run variance.
The two runs above are independent corpora (different seeds). Rerun to confirm
on your own deployment:

```powershell
python harness\measure.py --provider azure --n 200 --seed 1337
python harness\measure.py --provider azure --n 200 --seed 7
```
