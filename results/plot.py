"""Render the deterministic coverage result as a simple before/after chart."""
import json
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "coverage.json"), encoding="utf-8") as fh:
    cov = json.load(fh)["deterministic_coverage"]

labels = ["Payload exposure\nto the agent",
          "Breakout attempts\nreaching the agent",
          "Structured-field\ncorruption"]
raw = [cov["exposure_raw_pct"], 100.0, 0.0]
fenced = [cov["exposure_fenced_pct"], 100.0 - cov["breakout_neutralised_pct"], 0.0]

x = range(len(labels))
w = 0.38
fig, ax = plt.subplots(figsize=(8.6, 4.4))
b1 = ax.bar([i - w / 2 for i in x], raw, w, label="Stock pipeline", color="#c0392b")
b2 = ax.bar([i + w / 2 for i in x], fenced, w, label="LogFence at the DCR", color="#1f6f54")
ax.set_ylabel("percent")
ax.set_ylim(0, 108)
ax.set_xticks(list(x))
ax.set_xticklabels(labels, fontsize=9)
ax.set_title("LogFence deterministic coverage  (n=%d, %d injected records)"
             % (cov["records_total"], cov["records_malicious"]), fontsize=11)
ax.legend(frameon=False)
for bars in (b1, b2):
    for b in bars:
        ax.annotate(f"{b.get_height():.0f}%", (b.get_x() + b.get_width() / 2, b.get_height() + 1.5),
                    ha="center", fontsize=9)
ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
out = os.path.join(HERE, "coverage.png")
fig.savefig(out, dpi=140)
print("written:", out)
