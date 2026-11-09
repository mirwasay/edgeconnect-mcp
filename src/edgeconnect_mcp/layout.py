"""The one page layout every report uses (docs/report-layout.md): header with a message title, run facts, verdict, section
index, KPI tiles, numbered sections of identical anatomy, appendix, footer. Presentation only: report.py decides every
number and status; this module never computes one. All text is escaped here, so callers pass plain strings."""
import html
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

# Report statuses (green/amber/red/grey) -> the fixed notation: class, icon, word. Status is never shown by colour alone.
STATUS = {"green": ("good", "✓", "Good"), "amber": ("warning", "!", "Warning"), "red": ("critical", "✕", "Critical"), "grey": ("nodata", "–", "No data")}
APPENDIX_ROWS = 50  # longer tables move, whole, to the appendix; no row is ever dropped
MAX_TILES = 6

CSS = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#6b6a65;--grid:#e1e0d9;--base:#c3c2b7;--ring:rgba(11,11,11,.10);
--series:#2a78d6;--good:#0ca30c;--warning:#fab219;--critical:#d03b3b;--nodata:#c3c2b7;--goodtext:#006300;--warntext:#8a5a00;--crittext:#b42318}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#9a9890;
--grid:#2c2c2a;--base:#383835;--ring:rgba(255,255,255,.10);--series:#3987e5;--goodtext:#0ca30c;--warntext:#fab219;--crittext:#f07a7a}}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 48px}
.rpt-head{border-bottom:2px solid var(--ink);padding-bottom:12px}.kind{color:var(--ink2);font-size:13px;text-transform:uppercase;letter-spacing:.06em}
.rpt-head h1{margin:2px 0 0;font-size:24px;line-height:1.25}
dl.facts{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:2px 16px;margin:12px 0 4px;font-size:12.5px}dl.facts div{min-width:0}dl.facts dt{color:var(--muted)}dl.facts dd{margin:0;overflow-wrap:anywhere}
.options{color:var(--ink2);font-size:12.5px;margin:4px 0 0}
.verdict{display:flex;gap:12px;align-items:center;background:var(--surface);border:1px solid var(--ring);border-left:6px solid var(--nodata);padding:12px 16px;border-radius:8px;margin:16px 0}
.verdict.good{border-left-color:var(--good)}.verdict.warning{border-left-color:var(--warning)}.verdict.critical{border-left-color:var(--critical)}.verdict p{margin:0;font-size:15px}
.banner{border:2px solid var(--critical);background:var(--surface);padding:12px 16px;border-radius:8px;margin:16px 0}
nav.toc{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px;margin:8px 0 16px}nav.toc a{color:var(--ink2);text-decoration:none}nav.toc a:hover{text-decoration:underline}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:var(--nodata)}.dot.good{background:var(--good)}.dot.warning{background:var(--warning)}.dot.critical{background:var(--critical)}
.tiles{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-bottom:8px}
.tile{background:var(--surface);border:1px solid var(--ring);border-radius:8px;padding:12px;display:flex;flex-direction:column;gap:4px;min-width:0}
.tile-label{color:var(--ink2);font-size:12.5px}.tile-value{font-size:24px;font-weight:600;line-height:1.15;overflow-wrap:anywhere}
.stats{display:flex;flex-wrap:wrap;gap:8px 24px;margin:8px 0}.stat b{display:block;font-size:17px}.stat span{color:var(--ink2);font-size:12px}
.pill{display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:600;padding:1px 8px;border-radius:999px;border:1px solid currentColor;width:fit-content;white-space:nowrap}
.pill.good{color:var(--goodtext)}.pill.warning{color:var(--warntext)}.pill.critical{color:var(--crittext)}.pill.nodata{color:var(--muted)}
section{background:var(--surface);border:1px solid var(--ring);border-radius:8px;padding:16px 20px;margin:16px 0;break-inside:avoid}
.sec-head{display:flex;align-items:center;gap:10px}.sec-head h2{font-size:17px;margin:0;flex:1}.num{color:var(--muted);font-variant-numeric:tabular-nums;font-size:13px}
.summary{font-size:15px;margin:8px 0 4px}
figure{margin:8px 0}svg.chart{width:100%;height:auto;display:block}
svg text{font-family:inherit}svg .lbl{fill:var(--ink);font-size:12px}svg .val,svg .axis{fill:var(--ink2);font-size:11px;font-variant-numeric:tabular-nums}
svg .bar{fill:var(--series)}svg .base{stroke:var(--base);stroke-width:1}svg .grid{stroke:var(--grid);stroke-width:1}svg .threshold{stroke:var(--critical);stroke-width:1}
svg .band1{fill:#c3c2b7}svg .band2{fill:#d4d3cb}svg .band3{fill:#e6e5df}svg .actual{fill:var(--ink)}svg .target{stroke:var(--ink);stroke-width:2}
.legend{display:flex;flex-wrap:wrap;gap:16px;font-size:12px;color:var(--ink2);margin-top:4px}.legend i{display:inline-block;width:14px;height:3px;vertical-align:middle;margin-right:6px}
nav.next{font-size:13px;color:var(--ink2);border-top:1px solid var(--grid);padding-top:8px;margin-top:10px}
svg .cell.good{fill:var(--good)}svg .cell.warning{fill:var(--warning)}svg .cell.critical{fill:var(--critical)}svg .cell.nodata{fill:var(--nodata)}
svg .icon{fill:#fff;font-size:12px;font-weight:700}svg .icon.warning,svg .icon.nodata{fill:#0b0b0b}
details.tbl summary{cursor:pointer;color:var(--ink2);font-size:13px;margin-top:6px}
.tablewrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:12.5px;margin:6px 0}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
th{color:var(--ink2);font-weight:600}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.notes h3,.appendix h3,footer h3{font-size:12.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2);margin:10px 0 4px}.notes ul{margin:0;padding-left:18px}
.appendix h2,footer h2{font-size:17px}
footer{font-size:12.5px;color:var(--ink2);border-top:2px solid var(--ink);margin-top:24px;padding-top:12px}footer p{margin:4px 0}
@media (max-width:1000px){.tiles{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:720px){.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}dl.facts{grid-template-columns:repeat(2,minmax(0,1fr))}section{padding:12px}}
@media print{@page{size:A4;margin:12mm}:root{color-scheme:light}body{background:#fff}main{max-width:none;padding:0}nav.toc{display:none}
details.tbl>summary{display:none}section{border-color:#ccc}}
"""


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def status_of(status: Optional[str]) -> Tuple[str, str, str]:
    return STATUS.get(status or "grey", STATUS["grey"])


def pill(status: Optional[str]) -> str:
    cls, icon, word = status_of(status)
    return '<span class="pill {}"><span aria-hidden="true">{}</span> {}</span>'.format(cls, icon, word)


def tiles(items: Sequence[Tuple[str, str, Optional[str]]]) -> str:
    """KPI tiles: (label, value text, status). At most six, in the order given."""
    cells = ['<div class="tile"><div class="tile-label">{}</div><div class="tile-value">{}</div>{}</div>'.format(esc(label), esc(value), pill(status) if status else "")
             for label, value, status in list(items)[:MAX_TILES]]
    return '<div class="tiles" data-section-id="kpi-strip">{}</div>'.format("".join(cells)) if cells else ""


def stats(items: Sequence[Tuple[str, str, Optional[str]]]) -> str:
    """A section's own figures, small: value over label."""
    cells = ['<div class="stat"><b>{}</b><span>{}</span></div>'.format(esc(value), esc(label)) for label, value, _ in items]
    return '<div class="stats">{}</div>'.format("".join(cells)) if cells else ""


def bars(title: str, points: Sequence[Tuple[str, float]], zoom: bool) -> str:
    """Ranked horizontal bars, one hue, in the order given, value printed at the end. Availability zooms so 99.9 and 100 differ."""
    if not points:
        return ""
    values = [p[1] for p in points]
    floor, ceiling = (min(90.0, min(values)), 100.0) if zoom else (0.0, max(100.0, max(values)))
    width, row, x0, x1, top = 760, 22, 230, 680, 20
    parts = ['<text class="axis" x="{}" y="12">Scale {:g}% to {:g}%{}</text>'.format(x0, floor, ceiling, " (zoomed)" if floor > 0 else "")]
    for i, (label, value) in enumerate(points):
        y = top + i * row
        length = 0 if value <= floor else (value - floor) / (ceiling - floor) * (x1 - x0)
        parts.append('<g><title>{0}: {1:.2f}%</title><text class="lbl" x="{2}" y="{3}" text-anchor="end">{4}</text>'
                     '<rect class="bar" x="{5}" y="{6}" width="{7:.1f}" height="12" rx="3"/><text class="val" x="{8:.1f}" y="{3}">{1:.2f}%</text></g>'.format(
                         esc(label), value, x0 - 8, y + 11, esc(str(label)[:34]), x0, y + 1, max(length, 1.5), x0 + max(length, 1.5) + 6))
    parts.append('<line class="base" x1="{0}" x2="{0}" y1="{1}" y2="{2}"/>'.format(x0, top - 2, top + len(points) * row))
    return '<figure><svg class="chart" viewBox="0 0 {} {}" role="img" aria-label="{}"><title>{}</title>{}</svg></figure>'.format(
        width, top + len(points) * row + 4, esc(title), esc(title), "".join(parts))


def grid(title: str, rows: Sequence[Tuple[str, Sequence[Tuple[str, Optional[str], str]]]], columns: Sequence[str]) -> str:
    """Status grid: rows of (name, cells); each cell (text, status, tooltip) gets a colour and an icon."""
    if not rows:
        return ""
    cw, rh, x0 = 96, 26, 220
    parts = ['<text class="axis" x="{:.1f}" y="14" text-anchor="middle">{}</text>'.format(x0 + i * cw + cw / 2, esc(c)) for i, c in enumerate(columns)]
    for r, (name, cells) in enumerate(rows):
        y = 22 + r * rh
        parts.append('<text class="lbl" x="{}" y="{}" text-anchor="end">{}</text>'.format(x0 - 8, y + 16, esc(str(name)[:30])))
        for i, (text, status, tip) in enumerate(cells):
            cls, icon, word = status_of(status)
            parts.append('<g><title>{} · {}: {} ({})</title><rect class="cell {}" x="{}" y="{}" width="{}" height="{}" rx="3"/>'
                         '<text class="icon {}" x="{:.1f}" y="{}" text-anchor="middle">{} {}</text></g>'.format(
                             esc(name), esc(columns[i]), esc(text), word, cls, x0 + i * cw + 2, y + 2, cw - 4, rh - 4, cls, x0 + i * cw + cw / 2, y + 17, icon, esc(text)))
    return '<figure><svg class="chart" viewBox="0 0 {} {}" role="img" aria-label="{}"><title>{}</title>{}</svg></figure>'.format(
        x0 + len(columns) * cw + 4, 26 + len(rows) * rh, esc(title), esc(title), "".join(parts))


SERIES = ("var(--series)", "#eb6834", "#1baf7a")  # validated categorical slots 1-3; never more than three series in one chart


def bullets(title: str, items: Sequence[Tuple[str, Optional[float], float, Tuple[float, float]]], low: float, high: float) -> str:
    """Bullet graphs (Stephen Few): grey bands below / between / above the two limits, a dark bar for the value, a line for the target."""
    width, row, x0, x1 = 760, 30, 230, 700
    sx = lambda v: x0 + (min(max(v, low), high) - low) / (high - low) * (x1 - x0)
    parts = []
    for i, (label, value, target, limits) in enumerate(items):
        y = 6 + i * row
        a, b = sorted(limits)
        bands = "".join('<rect class="band{}" x="{:.1f}" y="{}" width="{:.1f}" height="20"/>'.format(k, sx(f), y, max(0.0, sx(t) - sx(f)))
                        for k, (f, t) in enumerate(((low, a), (a, b), (b, high)), 1))
        bar = '<rect class="actual" x="{}" y="{}" width="{:.1f}" height="8" rx="2"/>'.format(x0, y + 6, sx(value) - x0) if value is not None else ""
        shown = "no data" if value is None else "{:.3f}%".format(value)
        parts.append('<g><title>{0}: {1} (target {2:.3f}%)</title><text class="lbl" x="{3}" y="{4}" text-anchor="end">{0}</text>{5}{6}'
                     '<line class="target" x1="{7:.1f}" x2="{7:.1f}" y1="{8}" y2="{9}"/><text class="val" x="{10}" y="{4}">{1}</text></g>'.format(
                         esc(label), shown, target, x0 - 8, y + 14, bands, bar, sx(target), y + 2, y + 18, x1 + 6))
    return ('<figure><svg class="chart" viewBox="0 0 {0} {1}" role="img" aria-label="{2}"><title>{2}</title>{3}</svg>'
            '<figcaption class="legend">Dark bar: actual. Line: target. Bands: below {4:g}%, {4:g} to {5:g}%, above {5:g}%.</figcaption></figure>').format(
        width + 60, 12 + len(items) * row, esc(title), "".join(parts), *sorted(items[0][3])) if items else ""


def line(title: str, series: Sequence[Tuple[str, Sequence[Tuple[str, float]]]], unit: str, threshold: Optional[float] = None) -> str:
    """Time series on one y axis: up to three series in fixed colours, a labelled threshold line, round axis ticks, a legend."""
    if len(series) > len(SERIES):
        raise ValueError("a line chart takes at most {} series".format(len(SERIES)))
    if not series or not series[0][1]:
        return ""
    width, height, x0, x1, y0, y1 = 760, 220, 72, 740, 190, 14
    labels = [p[0] for p in series[0][1]]
    peak = max([v for _, pts in series for _, v in pts] + ([threshold] if threshold is not None else []) + [0.0])
    step = 10 ** max(0, len("{:.0f}".format(peak)) - 1) / 2 or 1.0
    top = max(step, -(-peak * 1.1 // step) * step)
    sx = lambda i: x0 + (i * (x1 - x0) / (len(labels) - 1) if len(labels) > 1 else (x1 - x0) / 2)
    sy = lambda v: y0 - v / top * (y0 - y1)
    parts = []
    for k in range(5):
        v = top * k / 4
        tick = human_bytes(v) if unit == "bytes" else "{:g}".format(round(v, 2))
        parts.append('<line class="grid" x1="{0}" x2="{1}" y1="{2:.1f}" y2="{2:.1f}"/><text class="axis" x="{3}" y="{4:.1f}" text-anchor="end">{5}</text>'.format(
            x0, x1, sy(v), x0 - 6, sy(v) + 4, tick))
    every = max(1, len(labels) // 8)
    parts += ['<text class="axis" x="{:.1f}" y="{}" text-anchor="middle">{}</text>'.format(sx(i), y0 + 18, esc(l)) for i, l in enumerate(labels) if i % every == 0]
    if threshold is not None:
        parts.append('<line class="threshold" x1="{0}" x2="{1}" y1="{2:.1f}" y2="{2:.1f}"/><text class="axis" x="{1}" y="{3:.1f}" text-anchor="end">threshold {4:g}{5}</text>'.format(
            x0, x1, sy(threshold), sy(threshold) - 5, threshold, esc(unit)))
    for k, (name, pts) in enumerate(series):
        coords = " ".join("{:.1f},{:.1f}".format(sx(i), sy(v)) for i, (_, v) in enumerate(pts))
        parts.append('<polyline fill="none" stroke="{}" stroke-width="2" points="{}"><title>{}</title></polyline>'.format(SERIES[k], coords, esc(name)))
    legend = "".join('<span><i style="background:{}"></i>{}</span>'.format(SERIES[k], esc(name)) for k, (name, _) in enumerate(series))
    return ('<figure><svg class="chart" viewBox="0 0 {} {}" role="img" aria-label="{}"><title>{}</title>{}</svg><figcaption class="legend">{}</figcaption></figure>').format(
        width, height + 10, esc(title), esc(title), "".join(parts), legend)


def human_bytes(n: float) -> str:
    """Decimal units (1 GB = 10^9 bytes)."""
    for unit, size in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if abs(n) >= size:
            return "{:.2f} {}".format(n / size, unit)
    return "{:.0f} bytes".format(n)


def number(column: str, value: float) -> str:
    """Fixed formats: availability and reachability to 3 decimals, other percentages to 1, everything else 2."""
    if any(k in column for k in ("avail", "reach")):
        return "{:,.3f}".format(value)
    return "{:,.1f}".format(value) if column.endswith("_pct") else "{:,.2f}".format(value)


def cell(value: Any) -> Tuple[str, bool]:
    if value is None:
        return "no data", False
    if isinstance(value, bool):
        return ("yes" if value else "no"), False
    if isinstance(value, float):
        return "{:,.2f}".format(value), True
    if isinstance(value, int):
        return "{:,}".format(value), True
    return str(value), False


def table(rows: Sequence[Mapping[str, Any]]) -> str:
    """Every row, every column, in the order given; numbers right-aligned; a `status` column shown as a pill."""
    if not rows:
        return ""
    columns = list(rows[0].keys())
    numeric = {c for c in columns if all(isinstance(r.get(c), (int, float)) and not isinstance(r.get(c), bool) for r in rows if r.get(c) is not None)
               and any(r.get(c) is not None for r in rows)}
    head = "".join('<th class="{}">{}</th>'.format("n" if c in numeric else "", esc(c.replace("_", " "))) for c in columns)
    body = []
    for r in rows:
        tds = []
        for c in columns:
            if c == "status":
                tds.append("<td>{}</td>".format(pill(r.get(c))))
                continue
            v = r.get(c)
            text = human_bytes(v) if c.endswith("bytes") and c in numeric and v is not None else number(c, v) if isinstance(v, float) else cell(v)[0]
            tds.append('<td class="{}">{}</td>'.format("n" if c in numeric else "", esc(text)))
        body.append("<tr>{}</tr>".format("".join(tds)))
    return '<div class="tablewrap"><table><thead><tr>{}</tr></thead><tbody>{}</tbody></table></div>'.format(head, "".join(body))


def section(sid: str, number: int, title: str, status: str, summary: str, figure: str, stat_html: str, rows: Sequence[Mapping[str, Any]],
            notes: Sequence[str], appendix: List[str], causes: Sequence[str] = (), actions: Sequence[str] = (), follow: Sequence[str] = ()) -> str:
    """One section, always the same anatomy: number, title, status; summary; figures; table view; notes; possible causes; actions."""
    view = ""
    if rows:
        if len(rows) > APPENDIX_ROWS:
            appendix.append('<section class="appendix" id="appendix-{0}" data-section-id="appendix-{0}"><h2>Appendix: {1}</h2><p>All {2:,} rows.</p>{3}</section>'.format(
                esc(sid), esc(title), len(rows), table(rows)))
            view = '<p class="options">{:,} rows: <a href="#appendix-{}">full table in the appendix</a>.</p>'.format(len(rows), esc(sid))
        else:
            view = '<details class="tbl" open><summary>Table ({} row{})</summary>{}</details>'.format(len(rows), "" if len(rows) == 1 else "s", table(rows))
    lists = (("Notes", notes), ("Possible causes", causes), ("Recommended actions", actions))
    note_html = "".join('<div class="notes"><h3>{}</h3><ul>{}</ul></div>'.format(h, "".join("<li>{}</li>".format(esc(i)) for i in items)) for h, items in lists if items)
    return ('<section id="{0}" data-section-id="{0}" aria-labelledby="{0}-h"><header class="sec-head"><span class="num">{1}</span><h2 id="{0}-h">{2}</h2>{3}</header>'
            '{4}{5}{6}{7}{8}{9}</section>').format(esc(sid), number, esc(title), pill(status), summary, stat_html, figure, view, note_html,
                                                   '<nav class="next" aria-label="Follow-up reports">Next: {}</nav>'.format(" \u00b7 ".join(esc(f) for f in follow)) if follow else "")


def page(title: str, kind: str, facts: Sequence[Tuple[str, str]], options: str, verdict_status: str, verdict_text: str, banner: str,
         index: Sequence[Tuple[str, str, str]], tile_html: str, sections_html: str, appendix: Sequence[str], footer: Sequence[Tuple[str, str]]) -> str:
    fact_html = "".join("<div><dt>{}</dt><dd>{}</dd></div>".format(esc(k), esc(v)) for k, v in facts)
    toc = "".join('<a href="#{}"><span class="dot {}"></span>{}</a>'.format(esc(sid), status_of(st)[0], esc(label)) for sid, label, st in index)
    if appendix:
        toc += '<a href="#appendix">Appendix</a>'
    foot = "".join("<h3>{}</h3><p>{}</p>".format(esc(h), esc(t)) for h, t in footer)
    cls = status_of(verdict_status)[0]
    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>{title}</title><style>{css}</style></head><body><main>'
            '<header class="rpt-head"><div class="kind">{kind}</div><h1>{title}</h1><dl class="facts">{facts}</dl>'
            '<p class="options" data-section-id="report-options">{options}</p></header>'
            '<div class="verdict {cls}" role="status" data-section-id="verdict">{pill}<p>{verdict}</p></div>{banner}'
            '<nav class="toc" aria-label="Sections">{toc}</nav>{tiles}{sections}{appendix}'
            '<footer><h2>About this report</h2>{foot}</footer></main></body></html>\n').format(
        title=esc(title), css=CSS, kind=esc(kind), facts=fact_html, options=esc(options), cls=cls, pill=pill(verdict_status), verdict=esc(verdict_text),
        banner=banner, toc=toc, tiles=tile_html, sections=sections_html,
        appendix='<div id="appendix">{}</div>'.format("".join(appendix)) if appendix else "", foot=foot)
