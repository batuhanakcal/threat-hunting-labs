# PEAK Threat Hunting Framework — Reference Notes

Source: Splunk SURGe team (David Bianco, Ryan Fetterman) blog series.
PEAK = **P**repare, **E**xecute, **A**ct with Knowledge. The "K" = Knowledge.

Three hunt types: **Hypothesis-Driven**, **Baseline**, **Model-Assisted (M-ATH)**.
All three share the same three phases (Prepare / Execute / Act).

---

## The 3 phases (common to every hunt)

- **Prepare** — pick topic, research it, form the plan, scope it (systems, data, timeframe). Set a max hunt duration ("3 days, if nothing found, it's probably not happening").
- **Execute** — gather data, pre-process/clean it, analyze (find patterns/anomalies/evidence), refine as you learn, escalate anything malicious to IR immediately.
- **Act** — preserve the hunt (archive data + method), document findings (the "so what?"), create detections, re-add new ideas to the backlog, communicate to stakeholders.

Key mindset: a hunt with no threat found is NOT a failed hunt. Output is always one of: threat → IR, pattern learned → detection, or visibility gap → logging improvement.

---

## Type 1: Hypothesis-Driven Hunting

The classic approach: form a supposition about attacker activity, then use data to confirm or deny it.

**Building a hypothesis — 3 steps:**
1. **Topic** — an area of concern (not yet a hypothesis). E.g. "data exfiltration."
2. **Make it testable** — something you can prove/disprove. "An actor may be exfiltrating data via DNS tunneling."
3. **Refine** — narrow until huntable. "An actor may be exfiltrating *sensitive financial* data via DNS tunneling."

**ABLE framework — turns a hypothesis into an actionable plan:**
- **A — Actor**: which threat actor/type (optional; adds context like known C2 domains/tools).
- **B — Behavior**: the specific activity / TTP. Hunt one or two pieces, not a whole kill chain.
- **L — Location**: where in the network you'd expect it (desktops, internet-facing servers). Narrows scope.
- **E — Evidence**: which data source(s) to check + what the activity would look like if present.

Example (DNS exfil): Actor = none specific; Behavior = DNS tunneling exfil; Location = finance dept; Evidence = DNS query logs → unusually large/frequent queries, odd record types.

---

## Type 2: Baseline Hunting (aka Exploratory Data Analysis / EDA)

Establish a snapshot of "normal," then hunt deviations. Best for **getting to know a new data source or environment** — a precursor to focused hunts.

**Prepare:** select data source (start with most critical/security-relevant), research it (key fields + how to read values), scope (group similar systems — "desktops", "app servers" — and baseline each group; pick a timeframe, usually 30–90 days).

**Execute:**
- **Data dictionary** — document key fields: name, description, data type, how to interpret values.
  - Data types: Numerical (continuous/discrete), Categorical (nominal/ordinal), Textual, Date/Time (mind the timezone!), Boolean.
- **Review distributions** — descriptive stats per key field: avg/median, top common values, cardinality (# of unique values). This IS your baseline of "normal."
- **Investigate outliers** — techniques:
  - **Stack counting (LFO)** — count each unique value, sort ascending; lowest counts = outliers (occasionally reversed).
  - **Z-scores** — for numeric fields; flag values ± a threshold of standard deviations from the mean. Threshold usually 2 or 3.
  - **Machine learning** — isolation forests, density functions (advanced).
- **Gap analysis** — note data/tool problems (missing systems, unparsed fields).
- **Identify relationships** — links between fields (e.g. login count vs time-of-day). More context than single points.

**Act:** preserve hunt, document baseline, **list known-benign outliers** (saves time later!), create detections where thresholds signal malice, communicate.

Note: abnormal ≠ malicious. Alerting on all anomalies floods low-quality alerts. Trick = pick outliers most likely to be malicious.

---

## Type 3: Model-Assisted Threat Hunting (M-ATH)

Uses algorithms/ML (clustering, classification, anomaly detection, time-series) to generate hunting leads. Can feed either baseline or hypothesis hunts.

**When to use — must meet at least criterion #1:**
1. **Simpler methods aren't accurate enough** (ALWAYS try search/filter/sort/stack first).
2. Benign/malicious classes are easily labeled (enables supervised classification).
3. Data is high-volume / hard to summarize (good for clustering, dimensionality reduction).
4. Events easy to identify but hard to classify → analyst-in-the-loop.

**Invest wisely:** M-ATH costs more expertise + resources. Start simple. The more criteria fit, the better the fit.

**Algorithm families:** Classification (supervised), Clustering (unsupervised grouping), Time Series/forecasting, Anomaly detection. Tools: Splunk MLTK, or DSDL for Python.

**Phases** mirror the others (Prepare: pick topic, research, identify datasets, select algorithm → Execute: gather, pre-process, develop model, refine/tune, apply, analyze with traditional tools on the reduced set → Act: preserve, document, create detections/notables/playbooks, backlog, communicate).

---

## How this maps to my own work (BOTS v3, Hunt #1)

- I did a **hypothesis-driven hunt** without knowing the name: "is something non-human talking to the web server?" → ABLE: Actor=unknown, Behavior=web enumeration, Location=internet-facing web server (access_combined), Evidence=web logs (non-browser UA, high-variety requests).
- My baseline work (median/stdev/MAD/percentile) = the **"Review distributions" + "Investigate outliers"** steps of a baseline hunt. My `avg ± 2*stdev` band = a **z-score** test (the formal name).
- My detection v1→v4 = the **"Create detections"** step of the Act phase.
- Noting ELB health-checker as noise = documenting a **known-benign outlier**.

## Two terms to remember
- **Z-score** = the formal name for "how many standard deviations from the mean" (what my ±2σ band does).
- **Data dictionary** = structured doc of each field's name/description/type/values. My spl-notes.md is a primitive version.

---

## ABLE — how to actually fill it in

Not every letter comes from the same place. Some you decide with logic/knowledge, some you must discover from the data.

| Letter | Where it comes from |
|--------|--------------------|
| **Actor** | Logic / decision. Often "unspecified" (any attacker). |
| **Behavior** | Attack knowledge — research the topic. Describe the technique's signature. |
| **Location** | Logic + confirm with data. "It's web → web logs" then verify the sourcetype. |
| **Evidence** | Mostly DISCOVER from data. What does the activity actually look like in the logs? Which fields, which values mean success/failure? |

**Practical order:** you can write A and B from your head. But for L and especially E, do a small recon pass FIRST — look at how the activity appears in the data — THEN finalize ABLE. Don't invent the Evidence; ask the data.
