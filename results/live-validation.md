# Live validation on AMA-collected telemetry

LogFence was validated end to end on real agent-collected telemetry, not only in
the harness. A Windows VM running the Azure Monitor Agent tailed a proxy access
log at `C:\logfence\access.log`. The AMA custom-text-log DCR
(`dcr/logfence-dcr-ama.arm.json`) parsed each line and applied the fence in its
`transformKql` at ingestion, writing to `ProxyLogsAma_CL`.

## What was sent

Timestamped access-log lines carrying all four payload classes plus two edge
cases: a full forged fence wrapper buried in the URL
(`/x?q=⟦⟦U⟧-BREAKOUT-⟦/U⟧-⟧`) and a tab-based structure attack in the user agent.

## What landed

- Every free-text field (`url_s`, `user_agent_s`, `message_s`) arrived wrapped in
  the fence markers `⟦U⟧ ... ⟦/U⟧`.
- The forged-wrapper URL came through as `⟦U⟧/x?q=[[U]-BREAKOUT-[/U]-]⟦/U⟧`: every
  attacker-written bracket downgraded to `[` / `]`, only the platform fence intact.
- The tab attack collapsed to single spaces.
- Structured fields (`src_ip_s`, `dst_port_s`) were byte-identical to what was sent.

Note: the Logs grid renders `⟦` / `⟧` (U+27E6 / U+27E7) as plain `[` / `]`. The
stored bytes are the Unicode markers, which is why forged inner brackets are
distinguishable from the outer fence.

## Verification query and result

```kusto
ProxyLogsAma_CL
| where TimeGenerated > ago(1h)
| extend open_markers = countof(url_s, "⟦U⟧"), close_markers = countof(url_s, "⟦/U⟧")
| extend pass = url_s startswith "⟦U⟧" and url_s endswith "⟦/U⟧" and open_markers == 1 and close_markers == 1
| summarize total = count(), passed = countif(pass)
```

Result: **total 90, passed 90.** Every ingested record was properly fenced with
exactly one genuine marker pair, so no forged marker survived ingestion.
