# Report layout spec: one fixed look for every report

Implemented in `src/edgeconnect_mcp/layout.py`; every report renders through it.

## Sources

- **IBCS / ISO 24896, the notation standard for business reporting.** Its SUCCESS rules include: what means the same must look the same (UNIFY); no decoration (SIMPLIFY); the same scale for the same unit (CHECK); a message title on every page (SAY); and a fixed, logical structure (STRUCTURE).
- **Stephen Few, *Information Dashboard Design*:**
  - bullet graphs instead of gauges
  - sparklines for trends in tiles
  - one distinct colour reserved for alerts
  - most important item at top left
  - high data-ink ratio
- **The dataviz method used here:**
  - a fixed, colour-blind-validated palette
  - status colours never reused for data
  - every status shown with an icon and a word, never colour alone
  - one y axis per chart, thin marks
  - a table view for every chart
- **Our renderer's existing constraints:** one self-contained HTML file, no scripts, no external links, A4 print.

## 1. Page frame (identical on every report)

| Order | Block | Content |
|---|---|---|
| 1 | **Header** | Report kind ("EdgeConnect · Executive report"); a **message title** written as a statement, built by code from the verdict (for example "October 2026: network healthy, one link near capacity"); overall status pill. |
| 2 | **Run facts** | Four fixed fields: Orchestrator (name and version), Appliances (all or the list, with hub and branch counts), Period (dates, time zone, data granularity), Generated (UTC). The options the user chose are listed underneath. |
| 3 | **Verdict bar** | One status pill and one sentence: what needs attention, or "everything within target". The left border colour is the worst status. |
| 4 | **Section index** | One link per section with its status dot, so the reader can jump straight to what's red. |
| 5 | **KPI tiles** | At most 6, in one row, always in the same order for a given report. Each tile has: label, value and unit, change against the previous period (arrow, coloured for good or bad), a sparkline, and a status pill. |
| 6 | **Sections** | Numbered and in a fixed order per report (see 2). |
| 7 | **Footer** | Data gaps; thresholds used and where they come from; sources (APIs); units; "code computes every number". |

Width is at most 1080 px, centred. Below 1000 px the tiles go to 3 per row, below 720 px to 2 per row and one column of text.

## 2. Section anatomy (identical in every section)

1. **Number, title, status pill.** The title names the subject; it is not a question.
2. **One-sentence summary** (the agent's text, validated).
3. **Exactly one figure,** from the six allowed forms in 3.
4. **"Table view"**, folded on screen and always printed: all rows, worst first. Tables over 50 rows move in full to the appendix (see 5b).
5. **Three columns,** always in this order: **Findings** (computed by code), **Possible causes** (only eligible card causes), **Recommended actions** (only eligible card actions). An empty column says "None".
6. **Next:** up to three links to follow-up reports or narrower scopes.

## 3. The only six chart forms

| Data's job | Form | Rules |
|---|---|---|
| One headline number with its trend | **KPI tile** with sparkline | value plus a delta against the previous period; the sparkline has no axis, and its last point is marked |
| A value against a target | **Bullet graph** (Few) | grey bands for bad, ok and good; dark bar for the actual value; a thin line for the target. Replaces every gauge or meter |
| Ranking or share (apps, talkers, links) | **Ranked horizontal bars**, one hue, largest first | value and share printed at the bar's end; at most 10 bars, then "Other" |
| Change over time | **Line chart**, one y axis | current period in the series colour, previous period grey, threshold as a thin red line labelled at its end; axis ticks on round numbers |
| Status across items × categories (health map, tunnel per hour) | **Status grid** | each cell has a status colour **and** an icon (✓ ! !! ✕ –); rows sorted worst first |
| Detail | **Table** | numbers right-aligned in tabular figures; units in the header |

**Never:** pie or donut charts, gauges, dual y axes, 3-D, more than 3 coloured series in one chart, a number on every point, or decoration.

## 4. Notation (what means the same looks the same)

- **Status:** exactly five states. These are the only status colours, and they are never used for data. Today's reports grade in four (green, amber, red, grey shown as Good, Warning, Critical, No data); Serious is reserved for when a report grades a fourth level.

| State | Icon | Colour |
|---|---|---|
| Good | ✓ | #0ca30c |
| Warning | ! | #fab219 |
| Serious | !! | #ec835a |
| Critical | ✕ | #d03b3b |
| No data | – | grey |

- **Series:** a single series is always blue (`#2a78d6`). The previous period is always grey, and a target or threshold is always a thin line. A second or third series takes palette slots 2 and 3 (orange `#eb6834`, aqua `#1baf7a`). That palette has been validated for colour blindness.
- **Deltas:** ▲ or ▼ plus the value. Green when the change is good and red when it is bad, decided by the metric (for example, down is good for loss).
- **Units and formats:**

| Measure | Format |
|---|---|
| Volume | decimal bytes (GB, TB) |
| Rates | Mbps |
| Availability | % to 3 decimals |
| Other percentages | 1 decimal |
| Latency and jitter | ms, whole numbers |
| Loss | % to 2 decimals |
| MOS | 2 decimals |
| Times | UTC, ISO dates |
| Thousands | comma separator |

- **Scales:** the same unit uses the same axis range in every chart of one report (for example, every utilisation chart runs 0 to 100%).
- **Wording:** a fixed glossary for terms such as "transport (underlay)", "overlay", "path", "P95" and "pre-FEC / post-FEC loss". It is printed in the appendix of composite reports.

## 5. Behaviour

- **No scripts.** Hover detail uses native SVG `<title>` tooltips, the section index uses plain anchors, and the table view uses `<details>`. The file opens offline, from email or in a ticket.
- **Light by default, dark when the reader's system is dark,** each with its own validated colours. Print is always light.
- **Print:** A4 portrait, 12 mm margins, sections never split across pages, table views expanded, and the index and sample banner hidden.
- **Accessibility:**
  - Real headings are used.
  - Every SVG has a `role="img"` label.
  - Status is never shown by colour alone.
  - Text contrast passes AA.
  - The table view gives the data to screen readers.
- **Composite reports (C1 to C4):** one file, with a cover (header, verdict, tiles), then each included report as a numbered part with the same frame. The section index lists the parts, and links between the separate full reports are relative file links.

## 5b. Complete results (approved 2026-11-09)

- **Reports are as long as the data needs.** Several pages is normal. The page frame stays the same; only the number of rows and parts grows.
- **Collection must be complete for the scope the user picked.** All appliances means every appliance, and every tunnel, application, alarm and link. The engine sets the API options for completeness:
  - fleet-wide calls (`groupPk=0.Network`) where they exist, otherwise one call per appliance
  - `top` raised to the full count, where the API honours it
  - `maxAlarms` raised and windows split when a page is full
  - every overlay
  - the finest granularity the period's retention allows
- **When an API caps a result,** the report says so in the data gaps, with the cap, instead of hiding it. Example: top talkers stop at 100 per appliance.
- **Sections stay readable:** the figure shows the worst or largest items; the **table view lists every row**, sorted worst first. Very long tables (over 50 rows) move in full to an appendix at the end of the report, and the section links to it. No row is ever dropped.

## 6. How we keep it identical every time

1. **One renderer in code.** Each block above is one Python function: tile, bullet, bars, line, grid, table, section, frame. Reports only supply data to these functions; no report writes HTML.
2. **The agent never writes HTML.** Its text is escaped and length-limited, and it can only fill the summary, cause and action slots.
3. **Fixed order:** the section order, tile order and table columns are defined per report in code.
4. **Snapshot test:** each report type is rendered from recorded data and compared with a stored golden HTML. Any layout change fails the test until the golden file is updated on purpose.
5. **Self-checks at render time:**
   - no `<script>`
   - no external URL
   - every status has an icon
   - at most 6 tiles
   - at most 3 series per chart
