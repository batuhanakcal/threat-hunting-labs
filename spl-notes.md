# SPL Notes

Personal SPL reference — every query I learn goes here.
Format: the query, what it does, and when it should come to mind.

---

## Data discovery

### Count events by sourcetype

```
index=botsv3 | stats count by sourcetype
```

**What:** Shows which data sources exist in an index and how noisy each one is.
**When:** First thing to run in any new/unfamiliar environment.

### Count events by host

```
index=botsv3 | stats count by host | sort - count
```

**What:** Lists all machines sending logs, in loudest-first order.
**When:** Mapping out an environment — how many systems, which ones matter.

### Verify data exists (ignores time range)

```
| eventcount summarize=false index=botsv3
```

**What:** Asks the index metadata for the total event count — not affected by the time picker.
**When:** Search returns 0, and I need to know whether the data is missing or my search is wrong.

---

## Gotchas

- BOTS data is from 2018 → **always set time range to All time**, or searches return 0.
