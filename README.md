# LogFence

Ingestion-time containment for log-substrate prompt injection, inside the Microsoft Sentinel data path.

LogFence is a Data Collection Rule (DCR) `transformKql` control that fences the
log fields an attacker can write, before any AI SOC agent (Security Copilot, a
custom MCP agent, an LLM summariser) ever reads them. It runs in Azure Monitor
at ingestion, deterministically, on every row.

It does not try to detect an attack. It makes "this is untrusted data"
explicit and un-forgeable in the bytes, so the agent can be told once, in its
system prompt, that anything inside the fence markers is evidence and never
instructions.

![architecture](results/architecture.svg)

## Why this exists

The attack is well studied and the defence is agreed in principle (treat raw log
content as adversarial, sanitise at the ingestion edge). But every published
defence is academic, a platform-agnostic library, or guidance. Nobody had
written the concrete Sentinel implementation: the actual DCR transform, ASIM
aware, deployable today, measured through the Microsoft pipeline. That is this
repo. See [ARTICLE.md](ARTICLE.md) for the full writeup and references.

## What is in here

```
dcr/
  transform-fencing.kql        core transform (custom table: user_agent_s, url_s, message_s)
  transform-fencing-asim.kql   ASIM Web Session variant (Url, UrlOriginal, HttpUserAgent, HttpReferrer)
  logfence-dcr.arm.json        deployable ARM: custom table + direct-ingestion DCR with the fence
  logfence-dcr.parameters.json parameters for the above
  logfence-dcr-ama.arm.json    deployable ARM: AMA custom-text-log DCR + VM association (live-test path)
  deploy-notes.md              portal + ARM deployment, transformKql constraints, cost, the downstream contract
  ama-test-notes.md            end-to-end live test on a VM with the Azure Monitor Agent
harness/
  fence.py                     byte-faithful Python mirror of the KQL transform
  corpus.py                    reproducible corpus, S1-S4 payload taxonomy, canary-based ASR, 60/40 mix
  analyst.py                   pluggable LLM analyst (azure / openai / anthropic), Chat + Responses APIs
  measure.py                   before/after measurement (deterministic coverage + model susceptibility)
  selftest.py                  invariant guard, no model or network needed
  requirements.txt             optional deps for the model layer and the chart
results/
  coverage.json                deterministic result (committed)
  coverage.png                 before/after chart
  model-runs.md                measured ASR on gpt-5.6-sol, two runs
  plot.py                      regenerate the chart
  architecture.svg             the diagram above
ARTICLE.md                     the deep-dive
```

## The control, in three steps

For each attacker-controllable free-text field:

1. **Forgery prevention** - neutralise the fence bracket characters already in the value, so an attacker cannot inject a closing marker and break out.
2. **Structure collapse** - fold CR / LF / TAB into single spaces, removing the fake-new-line trick.
3. **Fence** - wrap in rare untrusted-data markers (`⟦U⟧ ... ⟦/U⟧`).

Structured fields (addresses, ports, timestamps) are left byte-for-byte intact.
transformKql blocks `replace_string`, `replace_regex` and `column_ifexists`; the
transform uses the one supported replacement function, `replace(pattern, rewrite, source)`.

## Run it

Layer A, deterministic coverage, needs only the standard library:

```powershell
python harness\measure.py --n 200 --seed 1337
python harness\selftest.py
```

Layer B, model susceptibility. Measure against the model your SOC actually runs
(current GPT-5.x or your Security Copilot deployment), not a 2024-era model:

```powershell
python -m pip install -r harness\requirements.txt
$env:AZURE_OPENAI_ENDPOINT   = "https://<your-resource>.openai.azure.com"
$env:AZURE_OPENAI_API_KEY    = "<key>"
$env:AZURE_OPENAI_DEPLOYMENT = "<your-gpt-5.x-or-copilot-deployment>"
python harness\measure.py --provider azure

# side-by-side sweep; gpt-4o-mini only as a historical reference line
python harness\measure.py --provider azure --models "gpt-5.5,gpt-5,gpt-4o-mini"
```

Defaults target current models (openai -> gpt-5.5, anthropic -> claude-sonnet-5-5).

Regenerate the chart:

```powershell
python results\plot.py
```

## Measured coverage (committed result, n=200, seed 1337)

| Measure | Stock pipeline | LogFence |
|---|---|---|
| Injected payloads reaching the agent unfenced | 100% | 0% |
| Breakout attempts (forged marker or CR/LF) reaching the agent | 100% | 0% |
| Structured fields corrupted | 0% | 0% |

36 of 120 injected records attempted a forgery or CR/LF breakout, all contained.
Stable across seeds (seed 7: 34 attempts, all contained, same 100-to-0 exposure).

## Measured model susceptibility (gpt-5.6-sol, Azure AI Foundry)

Attack success rate = fraction of injected records where the model echoed the
planted canary. Pooled across two runs (240 injected records per condition):

| | Raw ASR | Fenced ASR |
|---|---|---|
| gpt-5.6-sol | 8.3% | 4.2% |

Fencing halved end-to-end ASR on a current frontier model. Azure's content
filter blocked a further 7 to 12%, but erratically, which is the argument for a
deterministic layer. Full per-run detail in `results/model-runs.md`.

## Deploy to Sentinel

Two deployable ARM templates in `dcr/`:

- `logfence-dcr.arm.json` - a direct-ingestion DCR (Logs Ingestion API) plus the
  custom table. Fastest to stand up and test with synthetic POSTs.
- `logfence-dcr-ama.arm.json` - an AMA custom-text-log DCR plus the VM
  association, for testing on real agent-collected telemetry. See
  `dcr/ama-test-notes.md` for the end-to-end VM walkthrough.

```powershell
az deployment group create -g <rg> `
  --template-file dcr/logfence-dcr.arm.json `
  --parameters @dcr/logfence-dcr.parameters.json
```

`dcr/deploy-notes.md` covers the transformKql function constraints, cost, and the
one-line system-prompt contract the downstream agent needs.

## Honest limits

Fencing is a structural control. It guarantees the agent can tell data from
instructions. It does not guarantee the agent will not be persuaded by text that
sits honestly inside the fence. Published evaluations show structured separation
reduces, it does not eliminate, susceptibility. Pair LogFence with
least-privilege on agent tools, output validation, and a human on irreversible
actions. The fence is the deterministic floor the rest of your controls stand on.

## License

MIT.
