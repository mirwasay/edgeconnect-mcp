"""Orchestrator reports: collect -> compute -> (the agent writes narrative.json) -> validate -> render. Standard library only.

collect  runs a fixed recipe of reads through the MCP server in-process (same .env, spec allowlist, redaction, audit log
         and get_only rule) and writes bundle.json with every call's provenance.
compute  turns the bundle into metrics.json: every number and every green/amber/red/grey status the report shows.
template prints the narrative skeleton: section ids, computed status and the metric ids the prose may cite.
validate checks narrative.json: numbers only as {{m:<metric id>}} tokens, known sections, no status that contradicts compute.
render   writes one self-contained HTML5 file (inline CSS and SVG, no JavaScript).
"""
import argparse
import bisect
import calendar
import hashlib
import html
import json
import math
import statistics
import os
import re
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from . import __version__
from .advisories import ADVISORIES, AS_OF as ADVISORIES_AS_OF
from . import layout
from .history import DEFAULT_ROOT as HISTORY_ROOT, History, missing as history_missing, pull, read_alarms
from .errors import EdgeConnectError
from .server import HOME_DOTENV, Server, ToolError

STATUSES = ("green", "amber", "red", "grey")
REPORTS = ("availability", "noc", "capacity", "lifecycle", "incident", "executive", "traffic", "paths", "operations", "optimisation", "security", "activity")
SECTIONS = {
    "availability": (("avail-summary", "Availability summary"), ("avail-appliances", "Appliance reachability"),
                     ("avail-roles", "Hubs and branches"), ("avail-tunnels", "Tunnel availability"), ("avail-interfaces", "Interface availability"),
                     ("avail-paths", "Path quality"), ("avail-alarms", "Alarms in the period"), ("data-gaps", "Data gaps")),
    "noc": (("noc-summary", "NOC summary"), ("noc-appliances", "Appliance state"), ("noc-alarms", "Active alarms"), ("noc-health", "Health"),
            ("noc-tunnels", "Tunnels down"), ("noc-worst", "Sites needing attention"), ("data-gaps", "Data gaps")),
    "capacity": (("cap-summary", "WAN capacity summary"), ("cap-links", "WAN links by P95 utilisation"), ("data-gaps", "Data gaps")),
    "lifecycle": (("life-summary", "Lifecycle summary"), ("life-inventory", "Inventory and software"), ("life-licences", "Licences"),
                  ("life-backups", "Backups"), ("life-advisories", "Security advisories"), ("life-eol", "Hardware end of life"), ("data-gaps", "Data gaps")),
    "executive": (("exec-fleet", "Fleet"), ("exec-availability", "Availability"), ("exec-alarms", "Active alarms"),
                  ("exec-licensing", "Licensing"), ("exec-software", "Software versions"), ("exec-capacity", "WAN capacity"),
                  ("exec-noc", "NOC digest"), ("exec-paths", "Path quality"), ("exec-traffic", "WAN traffic"), ("exec-lifecycle", "Lifecycle and vulnerabilities"),
                  ("exec-actions", "Recommended actions"), ("data-gaps", "Data gaps")),
    "operations": (("ops-state", "Appliance state"), ("ops-alarms", "Active alarms"), ("ops-health", "Health by category"), ("ops-tunnels", "Tunnels down"),
                   ("ops-paths", "Worst paths"), ("ops-capacity", "Busiest WAN links"), ("ops-actions", "Recommended actions"), ("data-gaps", "Data gaps")),
    "traffic": (("traffic-summary", "Traffic summary"), ("traffic-apps", "Applications"), ("traffic-talkers", "Top talkers"), ("traffic-domains", "Domains"),
                ("traffic-countries", "Countries"), ("traffic-ports", "Ports"), ("traffic-classes", "Traffic classes"), ("data-gaps", "Data gaps")),
    "paths": (("paths-summary", "Path quality summary"), ("paths-ranked", "Every active path, worst first"), ("paths-fec", "Loss hidden by FEC"),
              ("paths-transport", "Transports compared"), ("data-gaps", "Data gaps")),
    "optimisation": (("opt-summary", "WAN optimisation summary"), ("opt-appliances", "Reduction by appliance"), ("data-gaps", "Data gaps")),
    "security": (("sec-summary", "Firewall summary"), ("sec-pairs", "Zone pairs"), ("data-gaps", "Data gaps")),
    "activity": (("act-summary", "Change and alarm summary"), ("act-changes", "Changes"), ("act-alarms", "Alarms by type"), ("act-repeat", "Repeating alarms"),
                 ("act-after-change", "Alarms within an hour of a change"), ("data-gaps", "Data gaps")),
    "incident": (("inc-summary", "Incident summary"), ("inc-timeline", "Alarm timeline"), ("inc-appliances", "Affected appliances"),
                 ("inc-paths", "Path quality in the window"), ("inc-changes", "Changes in the window and the 24 hours before"), ("data-gaps", "Data gaps")),
}
ALWAYS_DOWN = 0.99  # a tunnel group up less than 1% of the period counts as down for the whole period: listed apart, not averaged in
TITLES = {"availability": "Availability report", "noc": "NOC digest", "capacity": "WAN capacity report",
          "lifecycle": "Lifecycle, licence and vulnerability report", "incident": "Major incident report",
          "executive": "Executive summary", "traffic": "Traffic and applications report",
          "paths": "Path quality report", "operations": "Operations summary", "optimisation": "WAN optimisation report",
          "security": "Firewall report", "activity": "Change and alarm activity report"}
INCIDENT_LOOKBACK_MS = 24 * 3600000  # changes in the 24 hours before an incident are shown next to it
INCIDENT_MAX_APPLIANCES = 20
INCIDENT_MAX_MS = 7 * 86400000  # longer windows are periods, not incidents (and the minute reachability is read per day)
AUDIT_PAGE = 10000  # GET /action returns at most this many entries, newest first
AUDIT_MAX_PAGES = 100  # activity report: at most this many pages (1,000,000 changes) before the rest is a named gap
# The executive page's KPI strip: availability, overlays, sites below target, critical alarms, licence, capacity, NOC, advisories.
EXEC_KPIS = ("fleet_reach_pct", "paths_ok_pct", "wan_bytes_total", "worst_p95_pct", "active_critical", "license_days_left")
PARTS = {"executive": ("availability", "noc", "capacity", "lifecycle", "traffic", "paths"), "operations": ("noc", "paths", "capacity")}  # reports that combine others; the rest are themselves
ROLE_NAMES = {"0": "branch", "1": "hub", "2": "mesh"}  # GET /appliance `networkRole`
STATE_NAMES = {1: "normal", 2: "unreachable", 3: "unsupported", 4: "out of sync", 5: "syncing"}  # GET /appliance `state`
GOOD_HEALTH = ("HEALTHY",)  # POST /health hourly `status` that counts as good; the spec enum is HEALTHY, WARNING, MINOR, MAJOR, CRITICAL
WAN_INTERFACE = re.compile(r"^b?wan\d", re.I)  # WAN ports and their VLANs (wan0, wan1.20, bwan0) in POST /stats/aggregate/interface
HEALTH_VERTICALS = ["ALARM", "LOSS", "LATENCY", "JITTER", "MOS", "BW_UTILIZATION"]
HOURLY_RETENTION = 14 * 86400  # fallback when GET /gms/stats/retention cannot be read: hourly interface stats kept 14 days by default
# Report options: the only choices a user (or the agent asking them) can make; argparse enforces them and the report prints them.
OPTIONS = {"period": ("last-month", "month-to-date", "last-7-days", "last-24-hours"), "target": ("orchestrator", "99.5", "99.9", "99.99"), "down_tunnels": ("include", "separate")}
DEFAULT_OPTIONS = {"period": "last-month", "scope": "all", "target": "orchestrator", "down_tunnels": "separate"}  # separate: approved 2026-11-09, idle paths drowned the figures
SEVERITY_ORDER = {"critical": 0, "major": 1, "minor": 2, "warning": 3}
MAX_ALARMS = 10000
WINDOW_PERIODS = {"last-24-hours": 86400, "last-7-days": 7 * 86400}  # rolling windows ending now, for reports that read stats aggregates
DEFAULT_PERIOD = {r: "last-7-days" for r in ("traffic", "paths", "operations", "optimisation", "security", "activity")}  # every other report defaults to DEFAULT_OPTIONS["period"]
TRAFFIC_TOP = 100000  # `top` sent so the Orchestrator returns every application, domain and port, not its default ten
TALKERS_CAP = 100  # GET /stats/aggregate/topTalkers returns at most 100 per appliance whatever `top` asks (seteam, 10.0, 2026-11-08)
TRAFFIC_PATHS = ("/stats/aggregate/application2", "/stats/aggregate/topTalkers", "/stats/aggregate/dns", "/stats/aggregate/ports", "/stats/aggregate/trafficClass")
PROTOCOLS = {6: "tcp", 17: "udp", 1: "icmp"}  # maxAlarms sent; a list this long may be cut, so it is reported as a gap
# Loss % is lost / (received + lost) packets. Below this many received packets in the period a loss % means little (the loss
# counters also count probe packets), so a tunnel that lost probes there is "no traffic, probes lost" and red. Seen on 10.0: idle
# SSE and guest overlays with 0 packets received and thousands lost.
MIN_LOSS_PACKETS = 10000
# Used, and listed as a gap, when GET /health/healthThresholdConfig returns nothing (the values a 9.7.1 Orchestrator ships with;
# capacity's 80/95 % link load is the report's own rule). goodLimit / okLimit as the Orchestrator names them.
DEFAULT_HEALTH = {"packetLoss": (0.1, 1.0), "latency": (20.0, 50.0), "jitter": (10.0, 20.0), "mos": (1.0, 4.0), "bwUtilization": (80.0, 95.0)}
DEFAULT_AVAILABILITY = (99.0, 99.5)  # used, and flagged, when GET /stats/config/availabilityThreshold returns nothing
# Keys never copied into a bundle, whatever the server's redaction does.
_DROP_KEYS = re.compile(r"licen[cs]e[-_]?key|serial|account[-_]?key|password|secret|token", re.I)  # serial: GET /appliance says plain `serial`
_TOKEN = re.compile(r"\{\{m:([A-Za-z0-9_.\-]+)\}\}")
_STATUS_WORDS = {"green": ("healthy", "on target", "meets target", "met target", "no issues"),
                 "amber": ("degraded", "at risk", "needs attention"),
                 "red": ("failing", "below target", "missed target", "outage"),  # not critical / warning: those name alarm severities
                 "grey": ("no data", "not available", "unknown")}
MAX_TEXT = 1200
CARDS: Dict[str, Any] = json.loads((Path(__file__).with_name("cards.json")).read_text(encoding="utf-8"))["sections"]
# Executive blocks show the actions of the sections they summarise.
EXEC_SOURCES = {"exec-availability": ("avail-appliances", "avail-tunnels", "avail-paths"), "exec-alarms": ("noc-alarms",), "exec-licensing": ("life-licences",),
                "exec-software": ("life-inventory",), "exec-capacity": ("cap-links",), "exec-noc": ("noc-appliances", "noc-health", "noc-tunnels"),
                "exec-lifecycle": ("life-backups", "life-advisories"),
                "paths-ranked": ("avail-paths",), "paths-summary": ("avail-paths",), "exec-paths": ("avail-paths", "paths-fec"),
                "ops-state": ("noc-appliances",), "ops-alarms": ("noc-alarms",), "ops-health": ("noc-health",), "ops-tunnels": ("noc-tunnels",),
                "ops-paths": ("avail-paths",), "ops-capacity": ("cap-links",)}
_OPS = {"<": lambda a, b: a < b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}
# Figures written as words are figures too.
_NUMBER_WORDS = re.compile(r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|"
                           r"eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundreds?|thousands?|millions?|dozens?|half|halves|twice|doubled?|tripled?|"
                           r"percent)\b", re.I)
# Digits that are names, not figures: P95, the 24-hour and 7-day windows, software releases.
_FIXED_TERMS = re.compile(r"\bP\d{2}\b|\blast (?:24 hours|7 days)\b|\b(?:ECOS|release|version|Orchestrator)\s+\d+(?:\.\d+)+\b", re.I)


# --- collect -----------------------------------------------------------------

class Collector:
    def __init__(self, server: Any, orchestrator: str) -> None:
        self.server, self.orchestrator = server, orchestrator.strip().lower()  # the server lowercases nicknames
        self.calls: List[Dict[str, Any]] = []
        self.data: Dict[str, Any] = {}
        known = {o["name"]: o for o in self._tool("list_orchestrators", {})[1]}
        if self.orchestrator not in known:
            raise ValueError("unknown Orchestrator {!r}; configured: {}".format(orchestrator, ", ".join(known)))
        self.read_posts = known[self.orchestrator]["read_posts_enabled"]

    def _tool(self, name: str, arguments: Mapping[str, Any]) -> Tuple[bool, Any]:
        response = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": dict(arguments, max_chars=10 ** 9)}})
        text = response["result"]["content"][0]["text"]
        if response["result"]["isError"]:
            return False, text.split("\n", 1)[0][len("Error: "):] if text.startswith("Error: ") else text
        value = json.loads(text)
        return True, value.get("result") if isinstance(value, dict) and "result" in value else value

    def call(self, cid: str, path: str, query: Optional[Dict[str, Any]] = None, body: Any = None, keep: bool = True) -> Any:
        method = "GET" if body is None else "POST"
        record: Dict[str, Any] = {"id": cid, "method": method, "path": path, "query": query or {}, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        if body is not None:
            record["body"] = body
        if method == "POST" and not self.read_posts:
            record.update(outcome="skipped", error="read-only POSTs are off for this Orchestrator (get_only); GET alternatives used where one exists")
            self.calls.append(record)
            return None
        started = time.monotonic()
        arguments: Dict[str, Any] = {"orchestrator": self.orchestrator, "path": path, "query": query or {}}
        ok, value = self._tool("api_get" if body is None else "api_read_post", dict(arguments, **({"body": body} if body is not None else {})))
        record["seconds"] = round(time.monotonic() - started, 2)
        if not ok:
            status = re.search(r"HTTP (\d{3})", str(value))
            record.update(outcome="error", error=str(value)[:300], http_status=int(status.group(1)) if status else None)
            self.calls.append(record)
            return None
        value = _scrub(value)
        record["outcome"] = "empty" if value in (None, [], {}, "") or value == {"data": []} else "ok"
        self.calls.append(record)
        if keep:
            self.data[cid] = value
        return value

    def pager(self) -> Any:
        """(path, query, body) -> rows, for history paging: recorded as calls, not kept as data (the pages go to the store)."""
        return lambda path, query, body: self.call("history", path, query, body, keep=False)


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items() if not _DROP_KEYS.search(str(k))}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def month_window(month: str, now: Optional[datetime] = None) -> Tuple[date, int, int]:
    """First day, start and end (epoch ms) of YYYY-MM; the current month ends now."""
    if not re.fullmatch(r"\d{4}-\d{2}", month):
        raise ValueError("--month must be YYYY-MM")
    year, number = int(month[:4]), int(month[5:])
    first = date(year, number, 1)
    start = datetime(year, number, 1, tzinfo=timezone.utc)
    end = datetime(year, number, calendar.monthrange(year, number)[1], 23, 59, 59, tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    if start > now:
        raise ValueError("--month {} is in the future".format(month))
    return first, int(start.timestamp() * 1000), int(min(end, now).timestamp() * 1000)


def resolve_month(period: str, now: datetime) -> str:
    """last-month is the previous calendar month; month-to-date is this one."""
    if period not in OPTIONS["period"]:
        raise ValueError("--period must be one of {}".format(", ".join(OPTIONS["period"])))
    year, month = (now.year, now.month) if period == "month-to-date" else (now.year - (now.month == 1), now.month - 1 or 12)
    return "{:04d}-{:02d}".format(year, month)


def collect(server: Any, orchestrator: str, report: str, month: Optional[str] = None, appliances: Optional[List[str]] = None, top: Optional[int] = None,
            now: Optional[datetime] = None, period: Optional[str] = None, target: str = "orchestrator", down_tunnels: str = DEFAULT_OPTIONS["down_tunnels"],
            window: Optional[Tuple[datetime, datetime]] = None, alarm_id: Optional[str] = None, history_root: Path = HISTORY_ROOT) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    if report == "incident" and not window and not alarm_id:
        raise ValueError("the incident report needs --from and --to, or --alarm-id")
    for name, value in (("target", target), ("down_tunnels", down_tunnels)):
        if value not in OPTIONS[name]:
            raise ValueError("{} must be one of {}".format(name, ", ".join(OPTIONS[name])))
    period = period or DEFAULT_PERIOD.get(report, DEFAULT_OPTIONS["period"])
    options = {"period": "month" if month else period, "scope": "all", "target": target, "down_tunnels": down_tunnels}
    if period in WINDOW_PERIODS and not month:
        if report not in tuple(DEFAULT_PERIOD) + ("noc", "lifecycle"):
            raise ValueError("--period {} is for the traffic report; {} takes a month (last-month, month-to-date or --month)".format(period, report))
        end_ms = int(now.timestamp()) // 3600 * 3600 * 1000  # whole hours, so the previous window lines up
        start_ms, first = end_ms - WINDOW_PERIODS[period] * 1000, None
        month = period
    else:
        month = month or resolve_month(period, now)
        first, start_ms, end_ms = month_window(month, now)
    options["month"] = month
    c = Collector(server, orchestrator)
    c.call("versions", "/gms/versions")
    inventory = c.call("appliances", "/appliance") or []
    if appliances:
        known = {a.get("nePk") for a in inventory} | {a.get("hostName") for a in inventory}
        unknown = [a for a in appliances if a not in known]
        if unknown:
            raise ValueError("--scope names appliances this Orchestrator does not have: {}".format(", ".join(unknown)))
        inventory = [a for a in inventory if a.get("nePk") in appliances or a.get("hostName") in appliances]
        c.data["appliances"] = inventory
        options["scope"] = list(appliances)
    nepks = [a["nePk"] for a in inventory if a.get("nePk")]
    parts = PARTS.get(report, (report,))
    if "availability" in parts:
        _collect_availability(c, nepks, first, start_ms, end_ms, int(now.timestamp() * 1000), history_root)
    if "noc" in parts:
        _collect_noc(c, nepks, int(now.timestamp()))
    if "capacity" in parts:
        _collect_capacity(c, nepks, start_ms // 1000, end_ms // 1000, top, int(now.timestamp()))
    if "lifecycle" in parts:
        _collect_lifecycle(c, nepks)
    if "traffic" in parts:
        _collect_traffic(c, nepks, start_ms // 1000, end_ms // 1000)
    span = {"startTime": start_ms // 1000, "endTime": end_ms // 1000, "granularity": "day"}
    if "optimisation" in parts:
        for ne in nepks:
            c.call("flows:" + ne, "/stats/aggregate/flow", dict(span, nePk=ne, trafficType="optimized_traffic"))
    if "security" in parts:
        c.call("zones", "/zones")
        for ne in nepks:
            c.call("security:" + ne, "/stats/aggregate/securityPolicy", dict(span, nePk=ne))
    if "activity" in parts:
        keep = ("id", "queuedTime", "user", "name", "nepk", "completionStatus")
        entries: Optional[List[Dict[str, Any]]] = []
        until, pages = end_ms, 0
        while True:  # GET /action pages newest first: a full page means older entries remain, so read again up to its oldest entry
            page = c.call("activity_audit_page", "/action", {"startTime": start_ms, "endTime": until, "limit": AUDIT_PAGE}, keep=False)
            if not isinstance(page, list):
                entries = None if not entries else entries
                break
            entries += [{k: r.get(k) for k in keep} for r in page if isinstance(r, dict)]
            pages += 1
            oldest = min((r.get("queuedTime") or until for r in page if isinstance(r, dict)), default=until)
            if len(page) < AUDIT_PAGE or oldest <= start_ms or pages >= AUDIT_MAX_PAGES:
                break
            until = oldest - 1
        c.data["activity_audit"] = _merge_by_id(entries) if entries is not None else None
        c.data["activity_audit_full"] = pages >= AUDIT_MAX_PAGES
        rows, failed, notes, source = read_alarms(c.pager(), nepks, c.read_posts, start_ms, end_ms)
        c.data["activity_alarms"] = _merge_by_id(rows, History(history_root, c.orchestrator).load("alarms", start_ms, end_ms))
        c.data["activity_alarm_notes"] = notes + (["alarms not read for {} windows".format(len(failed))] if failed else [])
    if "paths" in parts:
        c.call("health_threshold", "/health/healthThresholdConfig")
        # Hourly buckets are kept about 14 days (GET /gms/stats/retention); older windows use daily ones.
        granularity = "hour" if start_ms >= int(now.timestamp() * 1000) - 14 * 86400000 else "day"
        for ne in nepks:
            if "paths:" + ne not in c.data:  # the availability part already read the same window
                c.call("paths:" + ne, "/stats/aggregate/tunnel", {"nePk": ne, "startTime": start_ms // 1000, "endTime": end_ms // 1000, "granularity": granularity})
    now_ms = int(now.timestamp() * 1000)
    c.data["read_posts"] = c.read_posts
    if "incident" in parts:
        start_ms, end_ms = _collect_incident(c, inventory, bool(appliances), window, alarm_id, now_ms, history_root)
        options.update(period="incident", window=[start_ms, end_ms], alarm_id=alarm_id)
    return {"kind": "edgeconnect-report-bundle", "generator": __version__, "report": report, "orchestrator": c.orchestrator, "options": options,
            "period": {"month": month, "from_ms": start_ms, "to_ms": end_ms, "now_s": int(now.timestamp())},
            "collected_at": now.isoformat(timespec="seconds"), "read_posts_enabled": c.read_posts, "calls": c.calls, "data": c.data,
            "units": {"stats_time": "epoch seconds", "alarm_and_audit_time": "epoch milliseconds", "availability": "date YYYY-MM-DD; values are minute sample counts",
                      "bandwidth": "kbps", "interface_bytes": "bytes per bucket"}}


def _collect_availability(c: Collector, nepks: List[str], first: date, start_ms: int, end_ms: int, now_ms: int, root: Path) -> None:
    c.call("availability_threshold", "/stats/config/availabilityThreshold")
    c.call("health_threshold", "/health/healthThresholdConfig")
    c.call("retention", "/gms/stats/retention")
    for ne in nepks:
        # Availability takes a date, alarms take epoch milliseconds (stats aggregates would take seconds).
        c.call("reach:" + ne, "/stats/aggregate/availability/appliance", {"nePk": ne, "date": first.isoformat(), "granularity": "month"})
        c.call("overlay:" + ne, "/stats/aggregate/availability/tunnel", {"nePk": ne, "date": first.isoformat(), "granularity": "month", "overlayId": "all"})
        c.call("underlay:" + ne, "/stats/aggregate/availability/tunnel", {"nePk": ne, "date": first.isoformat(), "granularity": "month", "overlayId": "0"})
        c.call("ifavail:" + ne, "/stats/aggregate/availability/interface", {"nePk": ne, "date": first.isoformat(), "granularity": "month"})
        c.call("alarm_period:" + ne, "/health/alarmPeriodSummary", {"applianceId": ne, "from": start_ms, "to": end_ms})
        # Path quality per tunnel over the period: aggregate stats take epoch seconds, daily buckets are kept for months.
        c.call("paths:" + ne, "/stats/aggregate/tunnel", {"nePk": ne, "startTime": start_ms // 1000, "endTime": end_ms // 1000, "granularity": "day"})
    if nepks:
        c.call("appliance_alarms", "/alarm/appliance", {"view": "all", "from": start_ms, "to": end_ms, "maxAlarms": MAX_ALARMS, "orderBySeverity": True}, {"nePks": nepks})
    # The Orchestrator keeps 7 days of alarms: anything older in the period comes from the archive (`report store`), or is a gap.
    history = History(root, c.orchestrator)
    older_until = min(end_ms, now_ms - 7 * 86400000)
    listed = c.data.get("appliance_alarms")
    archived = history_missing(history.coverage().get("alarms", []), start_ms, older_until) == []
    # Only the alarm list can take archived alarms; the GET counts fallback cannot reach back past 7 days at all.
    c.data["period_alarms_covered"] = start_ms >= older_until or (isinstance(listed, list) and archived)
    if isinstance(listed, list):
        c.data["appliance_alarms_capped"] = len(listed) >= MAX_ALARMS
        c.data["appliance_alarms"] = _merge_by_id(listed, [a for a in history.load("alarms", start_ms, end_ms) if a.get("applianceId") in nepks])


def _collect_noc(c: Collector, nepks: List[str], now_s: int) -> None:
    c.call("alarm_summary", "/alarm/summary")
    c.call("alarm_counts", "/alarm/count/appliance")
    c.call("alarm_retention", "/gms/stats/nonStatsTable/retention")
    c.call("maintenance", "/maintenanceMode")
    # Network-wide in one call each; the boolean selectors keep only the fields named.
    c.call("tunnels_physical", "/tunnels2/physical", {"operStatus": "true", "srcNePk": "true", "alias": "true"})
    c.call("tunnels_bonded", "/tunnels2/bonded", {"operStatus": "true", "srcNePk": "true", "alias": "true", "tag": "true"})
    if nepks:
        c.call("active_alarms", "/alarm/appliance", {"view": "active", "maxAlarms": MAX_ALARMS, "orderBySeverity": True}, {"nePks": nepks})
        for vertical in HEALTH_VERTICALS:  # one read per category: the combined status hides which category is unhealthy
            c.call("health:" + vertical, "/health", {}, {"from": now_s - 7 * 86400, "to": now_s, "nePks": nepks, "overlayId": -1, "verticals": [vertical]})


def day_retention(retention: Any, kinds: Tuple[str, ...]) -> Optional[int]:
    """Seconds of daily stats kept for the shortest of `kinds` (each kind's longer DAY entry), from GET /gms/stats/retention."""
    kept = []
    for kind in kinds:
        entries = retention.get(kind) if isinstance(retention, dict) else None
        days = [e.get("retention") for e in entries or [] if isinstance(e, dict) and str(e.get("granularity")).upper() == "DAY" and isinstance(e.get("retention"), (int, float))]
        if days:
            kept.append(int(max(days)))
    return min(kept) if kept else None


def hour_retention(retention: Any) -> Optional[int]:
    """Seconds of hourly interface stats the Orchestrator keeps (the longer of the two HOUR entries GET /gms/stats/retention lists)."""
    entries = retention.get("interface") if isinstance(retention, dict) else None
    hours = [e.get("retention") for e in entries or [] if isinstance(e, dict) and str(e.get("granularity")).upper() == "HOUR" and isinstance(e.get("retention"), (int, float))]
    return int(max(hours)) if hours else None


def _collect_capacity(c: Collector, nepks: List[str], start_s: int, end_s: int, top: Optional[int], now_s: int) -> None:
    if not nepks:
        return
    for cid, path in (("retention", "/gms/stats/retention"), ("health_threshold", "/health/healthThresholdConfig")):
        if cid not in c.data:
            c.call(cid, path)
    kept = hour_retention(c.data.get("retention"))
    # Hourly data reaches back from now, not from the period's end: a period past it gets daily buckets instead.
    hourly_from = max(start_s, now_s - (kept or HOURLY_RETENTION))
    basis = {"granularity": "hour", "from": hourly_from, "to": end_s} if hourly_from < end_s else {"granularity": "day", "from": start_s, "to": end_s}
    c.data["capacity_basis"] = dict(basis, retention_known=kept is not None)
    totals = c.call("interface_totals", "/stats/aggregate/interface", {"startTime": start_s, "endTime": end_s, "granularity": "day", "trafficType": "all_traffic"}, {"nePks": nepks})
    if totals is not None:  # the same totals for the period before, for the change in average load
        c.call("interface_totals_previous", "/stats/aggregate/interface", {"startTime": 2 * start_s - end_s, "endTime": start_s, "granularity": "day", "trafficType": "all_traffic"},
               {"nePks": nepks})
    if totals is None:  # GET-only, or the POST was refused: the overlay transport stats mark WAN-side interfaces (last day only)
        for ne in nepks:
            c.call("wan_side:" + ne, "/stats/timeseries/interfaceOverlay", {"nePk": ne, "startTime": end_s - 86400, "endTime": end_s, "granularity": "day"})
    c.data["capacity_top"] = top
    links = wan_links(c.data, nepks)
    for ne in dict.fromkeys(link["nePk"] for link in links):  # what drives a busy link: its appliance's largest applications
        c.call("apps:" + ne, "/stats/aggregate/application2", {"nePk": ne, "startTime": start_s, "endTime": end_s, "top": 10})
    for link in links[:top or None]:  # every link unless --top limits it to the busiest
        c.call("hourly:{}:{}".format(link["nePk"], link["interface"]), "/stats/timeseries/interface",
               {"nePk": link["nePk"], "startTime": basis["from"], "endTime": basis["to"], "granularity": basis["granularity"], "trafficType": "all_traffic", "interfaceName": link["interface"]})


def _merge_by_id(*lists: Any) -> List[Dict[str, Any]]:
    """Records from several sources, one per id; the first source wins (live reads come first)."""
    seen: Dict[str, Dict[str, Any]] = {}
    for rows in lists:
        for row in rows or []:
            if isinstance(row, dict) and row.get("id") is not None:
                seen.setdefault(str(row["id"]), row)
    return list(seen.values())


def _collect_incident(c: Collector, inventory: List[Dict[str, Any]], scoped: bool, window: Optional[Tuple[datetime, datetime]], alarm_id: Optional[str],
                      now_ms: int, root: Path) -> Tuple[int, int]:
    history = History(root, c.orchestrator)
    nepks = [a["nePk"] for a in inventory if a.get("nePk")]
    if scoped and len(nepks) > INCIDENT_MAX_APPLIANCES:
        raise ValueError("--scope names {} appliances; an incident report takes at most {}".format(len(nepks), INCIDENT_MAX_APPLIANCES))
    pager = c.pager()

    def alarms(a: int, b: int) -> List[Dict[str, Any]]:
        """Live alarms raised in [a, b] plus every alarm open now, then the archive for [a, b]; live reads win."""
        rows, failed, notes, source = read_alarms(pager, nepks, c.read_posts, a, b)
        c.data["incident_alarm_source"] = source
        c.data.setdefault("incident_alarm_notes", []).extend(notes + (["alarms not read for {} windows".format(len(failed))] if failed else []))
        return _merge_by_id(rows, history.load("alarms", a, b))

    if window:
        start_ms, end_ms = int(window[0].timestamp() * 1000), int(window[1].timestamp() * 1000)
    else:  # the window around one alarm: an hour before it was raised to an hour after it cleared
        found = [a for a in alarms(now_ms - 7 * 86400000, now_ms) + history.load("alarms", 0, now_ms) if str(a.get("id")) == str(alarm_id)]
        if not found:
            raise ValueError("alarm {} is not in the Orchestrator's 7 days of alarms or the stored history".format(alarm_id))
        raised, cleared = found[0].get("timeOccurredInMills"), found[0].get("clearedTimeInMills")
        if found[0].get("closed") and not cleared:
            raise ValueError("alarm {} is closed but the Orchestrator gives no clear time (GET-only alarm list); give --from and --to".format(alarm_id))
        start_ms = int(raised) - 3600000
        end_ms = min(now_ms, int(cleared) + 3600000 if isinstance(cleared, (int, float)) and cleared > 0 else now_ms)
    if not 0 < start_ms < end_ms <= now_ms + 60000:
        raise ValueError("the incident window must start before it ends, and not in the future")
    if end_ms - start_ms > INCIDENT_MAX_MS:
        raise ValueError("an incident window is at most {} days; use the availability or NOC report for longer periods".format(INCIDENT_MAX_MS // 86400000))
    before = start_ms - INCIDENT_LOOKBACK_MS
    # Alarms raised up to 7 days before the window may still be open in it; older standing ones come from the open-now read.
    raised_from = start_ms - 7 * 86400000
    c.data["incident_alarms"] = alarms(raised_from, end_ms)
    # Only the part of the window (and the 24 hours before it) older than the Orchestrator's own 7 days depends on the archive.
    archive_until = min(end_ms, now_ms - 7 * 86400000)
    c.data["incident_alarms_stored"] = before >= archive_until or history_missing(history.coverage().get("alarms", []), before, archive_until) == []
    involved = [a.get("applianceId") for a in c.data["incident_alarms"] if start_ms <= (a.get("timeOccurredInMills") or 0) <= end_ms]
    ranked = nepks if scoped else sorted(set(involved) & set(nepks), key=lambda ne: -involved.count(ne))
    affected = ranked[:INCIDENT_MAX_APPLIANCES]
    c.data["incident_dropped"] = len(ranked) - len(affected)
    # Changes: the audit log is never stored, so one live page per scoped appliance (GET /action filters by appliance), or one
    # page for everything. Pages come newest first: a full page reaches back only to its oldest entry, which is recorded.
    audit, full_pages, read_ok = [], [], True
    for ne in affected if scoped else [None]:
        page = c.call("audit_page", "/action", dict({"startTime": before, "endTime": end_ms, "limit": AUDIT_PAGE}, **({"appliance": ne} if ne else {})), keep=False)
        if not isinstance(page, list):
            read_ok = False
            continue
        audit += page
        if len(page) >= AUDIT_PAGE:
            full_pages.append({"appliance": ne, "oldest": min((r.get("queuedTime") or 0) for r in page if isinstance(r, dict))})
    keep = ("id", "queuedTime", "user", "name", "nepk", "completionStatus")  # what the report shows; results and helper details stay out
    c.data["incident_audit"] = _merge_by_id([{k: r.get(k) for k in keep} for r in audit if isinstance(r, dict)])
    c.data["incident_audit_full"] = full_pages
    c.data["incident_audit_ok"] = read_ok
    c.call("health_threshold", "/health/healthThresholdConfig")
    c.call("availability_threshold", "/stats/config/availabilityThreshold")
    # Path stats: minute buckets are kept about a day, hourly about 14 days, daily for months (GET /gms/stats/retention).
    granularity = "minute" if start_ms >= now_ms - 86400000 else "hour" if start_ms >= now_ms - 14 * 86400000 else "day"
    days = sorted({datetime.fromtimestamp(t / 1000, timezone.utc).date().isoformat() for t in range(start_ms, end_ms + 1, 86400000)} |
                  {datetime.fromtimestamp(end_ms / 1000, timezone.utc).date().isoformat()})
    for ne in affected:
        for day in days:
            c.call("reach_minutes:{}:{}".format(ne, day), "/stats/timeseries/availability/appliance", {"nePk": ne, "date": day, "granularity": "day"})
        c.call("paths:" + ne, "/stats/aggregate/tunnel", {"nePk": ne, "startTime": start_ms // 1000, "endTime": end_ms // 1000, "granularity": granularity})
    c.data["incident"] = {"from_ms": start_ms, "to_ms": end_ms, "affected": affected, "granularity": granularity, "alarm_id": alarm_id}
    return start_ms, end_ms


def _collect_traffic(c: Collector, nepks: List[str], start_s: int, end_s: int) -> None:
    """Per appliance (the Orchestrator has no fleet total for these: groupPk returns a few appliances' rows), then the previous window."""
    span = end_s - start_s
    window = {"startTime": start_s, "endTime": end_s}
    for ne in nepks:
        c.call("apps:" + ne, "/stats/aggregate/application2", dict(window, nePk=ne, top=TRAFFIC_TOP))
        c.call("talkers:" + ne, "/stats/aggregate/topTalkers", dict(window, nePk=ne, top=TALKERS_CAP))
        c.call("dns:" + ne, "/stats/aggregate/dns", dict(window, nePk=ne, top=TRAFFIC_TOP, groupBy="country"))  # groupBy=dns is empty on 10.0
        c.call("ports:" + ne, "/stats/aggregate/ports", dict(window, nePk=ne, top=TRAFFIC_TOP))
        c.call("classes:" + ne, "/stats/aggregate/trafficClass", dict(window, nePk=ne, granularity="hour" if span <= 86400 else "day", trafficType="all_traffic"))
    for ne in nepks:
        c.call("apps_previous:" + ne, "/stats/aggregate/application2", {"startTime": start_s - span, "endTime": start_s, "nePk": ne, "top": TRAFFIC_TOP})


def _collect_lifecycle(c: Collector, nepks: List[str]) -> None:
    c.call("gms_license", "/gmsLicense")
    c.call("portal_appliances", "/license/portal/appliance")
    for ne in nepks:
        c.call("backup:" + ne, "/appliance/backup", {"nePk": ne, "runningConfig": "false"})  # without it each backup carries its whole config


# --- compute -----------------------------------------------------------------

def band(value: Optional[float], limits: Tuple[float, float], higher_is_better: bool = True) -> str:
    """green / amber / red against two limits; grey when there is no value. Limit order does not matter."""
    if value is None:
        return "grey"
    low, high = sorted(limits)
    if higher_is_better:
        return "green" if value >= high else "amber" if value >= low else "red"
    return "green" if value <= low else "amber" if value <= high else "red"


def worst(statuses: List[str]) -> str:
    known = [s for s in statuses if s != "grey"]
    return max(known, key=("green", "amber", "red").index) if known else "grey"


def _target_limits(ctx: Dict[str, Any], key: str) -> Tuple[float, float]:
    """Availability limits: a fixed --target is met (green) or missed (red); `orchestrator` uses its configured thresholds."""
    target = ctx["options"].get("target", "orchestrator")
    if target != "orchestrator":
        return float(target), float(target)
    limits, default_used = _limits(ctx["data"].get("availability_threshold") or {}, key)
    note = "No availability thresholds configured; default {} / {} % used.".format(*DEFAULT_AVAILABILITY)
    if default_used and note not in ctx["gaps"]:
        ctx["gaps"].append(note)
    return limits


def _limits(threshold: Any, key: str) -> Tuple[Tuple[float, float], bool]:
    item = threshold.get(key) if isinstance(threshold, dict) else None
    if isinstance(item, dict) and isinstance(item.get("goodLimit"), (int, float)) and isinstance(item.get("okLimit"), (int, float)):
        return (float(item["goodLimit"]), float(item["okLimit"])), False
    return DEFAULT_AVAILABILITY, True


def _pct(part: float, whole: float) -> Optional[float]:
    return round(100.0 * part / whole, 3) if whole else None


def _tunnel_totals(value: Any, separate: bool = False) -> Dict[str, Any]:
    """Seconds sampled, down and degraded, plus the groups down for the whole period (up under 1% of it), which `separate` leaves out of the totals.

    `count` is minute samples while tunnel_state, blackout and brownout are seconds (seen on 9.7.1 and 10.0: count 1441 for a
    day, downtime up to count x 60); tunnel_state and blackout overlap, so take the larger."""
    totals: Dict[str, Any] = {"seconds": 0.0, "down": 0.0, "brownout": 0.0, "always_down": []}
    groups = value.values() if isinstance(value, dict) else [value] if isinstance(value, list) else []
    for group in groups:
        for row in group if isinstance(group, list) else []:
            if isinstance(row, dict):
                seconds = 60.0 * float(row.get("count") or 0)
                down = min(seconds, max(float(row.get("tunnel_state") or 0), float(row.get("blackout") or 0)))
                if seconds and down >= ALWAYS_DOWN * seconds:
                    totals["always_down"].append(row)
                    if separate:
                        continue
                totals["seconds"] += seconds
                totals["down"] += down
                totals["brownout"] += min(seconds, float(row.get("brownout") or 0))
    return totals


def _p95(values: List[float]) -> Optional[float]:
    """Nearest-rank 95th percentile."""
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)], 2)


def _version(text: Any) -> Tuple[int, ...]:
    """9.6.2.1_107093 -> (9, 6, 2, 1); 9.7.1.42046 -> (9, 7, 1, 42046)."""
    match = re.match(r"\d+(?:\.\d+)*", str(text or ""))
    return tuple(int(part) for part in match.group(0).split(".")) if match else ()


def advisory_hit(version: Any, advisory: Mapping[str, Any]) -> Optional[str]:
    """Why `version` is affected by `advisory`, or None. Trains newer than every listed one are not affected."""
    v = _version(version)
    if len(v) < 2:
        return None
    fixed = {_version(train): _version(build) for train, build in advisory["fixed_in"].items()}
    train = v[:2]
    if train in fixed:
        return "below {}".format(".".join(map(str, fixed[train]))) if v < fixed[train] else None
    return "no fix in the {} train; upgrade".format(".".join(map(str, train))) if train < min(fixed) else None


def wan_links(data: Mapping[str, Any], nepks: Any) -> List[Dict[str, Any]]:
    """WAN interfaces with their average utilisation over the window, busiest first.

    From POST /stats/aggregate/interface when it ran (one row per interface; BW in kbps; daily buckets), else from the
    WAN-side rows of GET /stats/timeseries/interfaceOverlay for the last day (summed over overlays)."""
    links: Dict[Tuple[str, str], Dict[str, Any]] = {}
    rows = data.get("interface_totals")
    if isinstance(rows, list):
        for row in rows:
            name = str(row.get("INTERFACE") or "")
            if row.get("nePk") in nepks and WAN_INTERFACE.match(name) and row.get("TRAFFIC_TYPE") in (4, None):
                seconds = float(row.get("MAX_TIMESTAMP") or 0) - float(row.get("MIN_TIMESTAMP") or 0) + 86400
                links[(row["nePk"], name)] = {"nePk": row["nePk"], "interface": name, "label": "", "tx_bytes": float(row.get("SUM_TX_BYTES") or 0),
                                              "rx_bytes": float(row.get("SUM_RX_BYTES") or 0), "bw_tx": float(row.get("AVG_MAX_BW_TX") or 0),
                                              "bw_rx": float(row.get("AVG_MAX_BW_RX") or 0), "seconds": seconds, "source": "POST /stats/aggregate/interface"}
    else:
        for ne in nepks:
            for row in data.get("wan_side:" + str(ne)) or []:
                if not isinstance(row, dict) or not row.get("ISWANSIDE"):
                    continue
                link = links.setdefault((ne, str(row.get("INTERFACE"))), {"nePk": ne, "interface": str(row.get("INTERFACE")), "label": str(row.get("LABELNAME") or ""),
                                                                         "tx_bytes": 0.0, "rx_bytes": 0.0, "bw_tx": 0.0, "bw_rx": 0.0, "seconds": 86400.0,
                                                                         "source": "GET /stats/timeseries/interfaceOverlay (last day)"})
                link["tx_bytes"] += float(row.get("TX_BYTES") or 0)
                link["rx_bytes"] += float(row.get("RX_BYTES") or 0)
                link["bw_tx"] = max(link["bw_tx"], float(row.get("MAX_BW_TX") or 0))
                link["bw_rx"] = max(link["bw_rx"], float(row.get("MAX_BW_RX") or 0))
    for link in links.values():
        link["avg_tx_pct"] = _util(link["tx_bytes"], link["seconds"], link["bw_tx"])
        link["avg_rx_pct"] = _util(link["rx_bytes"], link["seconds"], link["bw_rx"])
    return sorted(links.values(), key=lambda link: -max(link["avg_tx_pct"] or 0, link["avg_rx_pct"] or 0))


def _expiry_status(days: int) -> str:
    """Licences: 30 days or less red, 90 days or less amber."""
    return "red" if days <= 30 else "amber" if days <= 90 else "green"


def _load_status(pct: Optional[float], limits: Tuple[float, float] = DEFAULT_HEALTH["bwUtilization"]) -> str:
    """Link load: at or above the lower limit amber, at or above the higher red."""
    low, high = sorted(limits)
    return "grey" if pct is None else "red" if pct >= high else "amber" if pct >= low else "green"


def health_limits(data: Mapping[str, Any], key: str, gaps: List[str]) -> Tuple[float, float]:
    """goodLimit / okLimit for one metric from GET /health/healthThresholdConfig, else the default (listed as a gap once)."""
    item = (data.get("health_threshold") or {}).get(key) if isinstance(data.get("health_threshold"), dict) else None
    if isinstance(item, dict) and isinstance(item.get("goodLimit"), (int, float)) and isinstance(item.get("okLimit"), (int, float)):
        return float(item["goodLimit"]), float(item["okLimit"])
    note = "No {} limits from GET /health/healthThresholdConfig; default {} / {} used.".format(key, *DEFAULT_HEALTH[key])
    if note not in gaps:
        gaps.append(note)
    return DEFAULT_HEALTH[key]


def _util(byte_count: float, seconds: float, kbps: float) -> Optional[float]:
    """Percent of the configured bandwidth: bytes x 8 / (seconds x kbps x 1000)."""
    return round(100.0 * byte_count * 8 / (seconds * kbps * 1000), 2) if seconds > 0 and kbps > 0 else None


def compute(bundle: Mapping[str, Any]) -> Dict[str, Any]:
    data, calls, report = bundle["data"], bundle["calls"], bundle["report"]
    metrics: Dict[str, Dict[str, Any]] = {}
    sections: Dict[str, Dict[str, Any]] = {}
    gaps: List[str] = []

    def metric(mid: str, value: Any, unit: str, label: str, status: Optional[str] = None) -> str:
        metrics[mid] = {"value": value, "unit": unit, "label": label, "status": status}
        return mid

    # Skipped (get_only) and refused (401/403) calls say nothing about the statistics store.
    stats_calls = [c for c in calls if c["path"].startswith("/stats/") and c.get("outcome") != "skipped" and c.get("http_status") not in (401, 403)]
    stats_down = bool(stats_calls) and all(c.get("outcome") == "error" and c.get("http_status") == 500 for c in stats_calls)
    for c in calls:
        if c.get("outcome") in ("error", "skipped") and not (stats_down and c["path"].startswith("/stats/")):
            gaps.append("{} {}: {}".format(c["method"], c["path"], c.get("error") or c["outcome"]))
    if stats_down:
        gaps.insert(0, "Every statistics call returned HTTP 500: the Orchestrator's statistics store is down, so statistics are not shown.")

    inventory = data.get("appliances") or []
    names = {a.get("nePk"): a.get("hostName") or a.get("nePk") for a in inventory}
    now_s = int(bundle["period"].get("now_s") or bundle["period"]["to_ms"] // 1000)
    parts = PARTS.get(report, (report,))
    options = dict(DEFAULT_OPTIONS, month=bundle["period"]["month"])
    options.update(bundle.get("options") or {})
    ctx = {"data": data, "inventory": inventory, "names": names, "metric": metric, "metrics": metrics, "gaps": gaps, "stats_down": stats_down, "now_s": now_s, "options": options,
           "period_from_s": bundle["period"]["from_ms"] // 1000,
           "period_s": max(1, (bundle["period"]["to_ms"] - bundle["period"]["from_ms"]) // 1000)}
    m_total = metric("appliances_total", len(inventory), "appliances", "Appliances in scope")
    if "availability" in parts:
        sections.update(_availability(ctx))
    if "noc" in parts:
        sections.update(_noc(ctx))
    if "capacity" in parts:
        sections.update(_capacity(ctx))
    if "lifecycle" in parts:
        sections.update(_lifecycle(ctx))
    if "incident" in parts:
        sections.update(_incident(ctx))
    if "traffic" in parts:
        sections.update(_traffic(ctx))
    if "paths" in parts:
        sections.update(_path_report(ctx))
    if "optimisation" in parts:
        sections.update(_optimisation(ctx))
    if "security" in parts:
        sections.update(_security(ctx))
    if "activity" in parts:
        sections.update(_activity(ctx))

    if report == "executive":
        reachable_now = [a for a in inventory if a.get("state") == 1]
        down_share = _pct(len(inventory) - len(reachable_now), len(inventory))
        fleet_status = "grey" if down_share is None else "green" if not down_share else "red" if down_share > 10 else "amber"
        m_now = metric("reachable_now_pct", _pct(len(reachable_now), len(inventory)), "%", "Appliances reachable at collection time", fleet_status)
        metric("reachable_now", len(reachable_now), "appliances", "Appliances reachable at collection time")
        sections["exec-fleet"] = {"status": fleet_status, "metrics": [m_total, "reachable_now", m_now],
                                  "notes": ["Rule: any appliance down is amber; more than 10% down is red. The appliance list is in the availability and NOC reports."]}
        sections["exec-availability"] = {"status": worst([sections[sid]["status"] for sid in ("avail-appliances", "avail-tunnels", "avail-paths")]),
                                         "metrics": ["fleet_reach_pct", "overlay_avail_pct", "underlay_avail_pct", "appliances_below_target", "paths_red"]}
        sections["exec-alarms"] = dict(sections["noc-alarms"], table=[])
        sections["exec-licensing"] = dict(sections["life-licences"], table=[])
        sections["exec-software"] = {"status": metrics["ecos_trains"]["status"], "metrics": ["ecos_versions", "ecos_trains", "orchestrator_version"],
                                     "notes": ["Rule: more than one ECOS train in use is amber."]}
        sections["exec-capacity"] = {"status": sections["cap-summary"]["status"], "metrics": sections["cap-summary"]["metrics"]}
        sections["exec-noc"] = {"status": sections["noc-summary"]["status"], "metrics": sections["noc-summary"]["metrics"]}
        sections["exec-lifecycle"] = {"status": sections["life-summary"]["status"], "metrics": sections["life-summary"]["metrics"]}
        sections["exec-paths"] = {"status": sections["paths-summary"]["status"], "metrics": ["paths_ok_pct", "paths_red", "paths_fec_masking"],
                                  "notes": ["Rule: at least 98% of paths within every health threshold is green, 90% amber."]}
        sections["exec-traffic"] = {"status": sections["traffic-summary"]["status"], "metrics": ["wan_bytes_total", "wan_bytes_change_pct", "top_app_share_pct"],
                                    "chart": sections["traffic-apps"].get("chart")}
    if report == "operations":
        for sid, source in (("ops-state", "noc-appliances"), ("ops-alarms", "noc-alarms"), ("ops-health", "noc-health"), ("ops-tunnels", "noc-tunnels"),
                            ("ops-paths", "paths-ranked"), ("ops-capacity", "cap-links")):
            sections[sid] = dict(sections[source])
    kept = day_retention(data.get("retention"), ("tunnel", "interface"))
    if kept and bundle["period"]["from_ms"] // 1000 < now_s - kept and report in ("availability", "capacity", "executive"):
        gaps.append("The period starts older than the {:g} days of daily statistics this Orchestrator keeps, so path quality and capacity cover only part of it, or none.".format(kept / 86400))
    for sid, sec in sections.items():  # possible causes and actions: only card entries whose conditions hold
        sources = EXEC_SOURCES.get(sid, (sid,))
        sec["causes"], sec["actions"] = _eligible(sources, metrics, "causes"), _eligible(sources, metrics, "actions")
    for sid in ("exec-actions", "ops-actions"):  # one list of every action the summary's sections show, in section order
        if sid in dict(SECTIONS[report]):
            listed = [a for other, _ in SECTIONS[report] if other in sections for a in sections[other].get("actions", [])]
            unique = list({a["id"]: a for a in listed}.values())
            sections[sid] = {"status": "amber" if unique else "green", "metrics": [], "actions": unique, "causes": [],
                             "notes": [] if unique else ["No action needed from this period's data."]}
    sections["data-gaps"] = {"status": "grey" if gaps else "green", "metrics": [], "notes": gaps or ["None: every call returned data."]}
    headline = None
    if report in ("executive", "operations"):
        areas = [sid for sid, _ in SECTIONS[report] if sid not in ("data-gaps", "exec-actions", "ops-actions")]
        overall = worst([sections[sid]["status"] for sid in areas])
        attention = [dict(SECTIONS[report])[sid] for sid in areas if sections[sid]["status"] in ("amber", "red")]
        kpis = EXEC_KPIS if report == "executive" else ("state_unreachable", "active_critical", "health_good_24h_pct", "tunnels_bonded_down", "paths_ok_pct", "worst_p95_pct")
        headline = {"status": overall, "kpis": [k for k in kpis if k in metrics],
                    "text": "Overall: {}. {}.".format(layout.STATUS[overall][2], "No area needs attention" if not attention else "Attention needed in " + ", ".join(attention))}

    # An appliance counts as covered when any per-appliance read returned something for it (keyed "<what>:<nePk>", or named inside a result).
    other = json.dumps({k: v for k, v in data.items() if k not in ("appliances", "versions") and ":" not in k})
    answered = sum(1 for ne in names if any(k.endswith(":" + str(ne)) and v for k, v in data.items()) or '"{}"'.format(ne) in other)
    return {"kind": "edgeconnect-report-metrics", "report": report, "orchestrator": bundle["orchestrator"],
            "orchestrator_version": (data.get("versions") or {}).get("current") if isinstance(data.get("versions"), dict) else None,
            "period": bundle["period"], "collected_at": bundle["collected_at"], "bundle_sha256": bundle.get("sha256"),
            "coverage": {"appliances": len(names), "with_data": answered}, "stats_store_down": stats_down,
            "options": dict(options, down_tunnels_count=metrics.get("tunnel_groups_down_all_period", {}).get("value"),
                            idle_paths_count=metrics.get("paths_idle_probe_loss", {}).get("value")),
            "headline": headline, "metrics": metrics, "sections": {sid: sections[sid] for sid, _ in SECTIONS[report]}}


def clause_holds(clause: List[Any], metrics: Mapping[str, Mapping[str, Any]]) -> bool:
    """[metric, op, value]: value may name another metric; a metric with no value only matches == None."""
    mid, op, want = clause
    if mid not in metrics:
        return False
    if op == "status":
        return metrics[mid].get("status") in want
    have = metrics[mid].get("value")
    if isinstance(want, str) and want in metrics:
        want = metrics[want].get("value")
    if op in ("==", "!="):
        return (have == want) == (op == "==")
    if not isinstance(have, (int, float)) or not isinstance(want, (int, float)):
        return False
    return _OPS[op](have, want)


def _eligible(sids: Tuple[str, ...], metrics: Mapping[str, Any], kind: str) -> List[Dict[str, str]]:
    seen: Dict[str, Dict[str, str]] = {}
    for sid in sids:
        for entry in (CARDS.get(sid) or {}).get(kind, []):
            if all(clause_holds(c, metrics) for c in entry["when"]):
                seen.setdefault(entry["id"], {"id": entry["id"], "text": entry["text"]})
    return list(seen.values())


def _availability(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    data, inventory, names, metric, metrics, gaps = ctx["data"], ctx["inventory"], ctx["names"], ctx["metric"], ctx["metrics"], ctx["gaps"]
    sections: Dict[str, Dict[str, Any]] = {}
    threshold = data.get("availability_threshold") or {}
    # Appliance reachability: minute samples, so % = reachable minutes / sample count.
    limits = _target_limits(ctx, "reachability")
    rows, total_reach, total_samples = [], 0.0, 0.0
    for ne, name in names.items():
        sample = (data.get("reach:" + str(ne)) or [{}])[0] if isinstance(data.get("reach:" + str(ne)), list) else {}
        samples, reach = float(sample.get("samplecount") or 0), float(sample.get("appliancereachability") or 0)
        pct = _pct(reach, samples)
        if pct is None and not ctx["stats_down"]:
            state = next((a.get("state") for a in inventory if a.get("nePk") == ne), None)
            gaps.append("{}: no reachability samples for the month{}.".format(name, " although it is reachable now (check ECOS 9.3.4/9.4.2/9.5.0 or later, and retention)" if state == 1 else ""))
        total_reach, total_samples = total_reach + reach, total_samples + samples
        rows.append({"appliance": name, "nePk": ne, "value": pct, "status": band(pct, limits)})
    fleet = _pct(total_reach, total_samples)
    m_fleet = metric("fleet_reach_pct", fleet, "%", "Fleet appliance reachability", band(fleet, limits))
    below = [r for r in rows if r["status"] in ("amber", "red")]
    m_below = metric("appliances_below_target", len(below) if fleet is not None else None, "appliances", "Appliances below the reachability target")
    m_measured = metric("appliances_measured", sum(1 for r in rows if r["value"] is not None), "appliances", "Appliances with reachability data")
    metric("reach_target_pct", max(limits), "%", "Reachability target")
    rows.sort(key=lambda r: (r["value"] is None, r["value"] if r["value"] is not None else 0))
    sections["avail-appliances"] = {"status": metrics[m_fleet]["status"], "metrics": [m_fleet, m_below, m_measured, "reach_target_pct"],
                                    "table": rows, "chart": {"title": "Lowest appliance reachability, % of the month", "zoom": True,
                                                             "points": [(r["appliance"], r["value"], r["status"]) for r in rows if r["value"] is not None][:25]}}

    # Tunnel availability, derived: 1 - down seconds / sampled seconds; brownout is shown as a degraded share.
    tunnel_metrics, tunnel_rows, tunnel_status, always_down = [], [], [], []
    separate = ctx["options"].get("down_tunnels") == "separate"
    for kind, key, label in (("overlay", "overlayAvailability", "Overlay"), ("underlay", "underlayAvailability", "Underlay")):
        lim = _target_limits(ctx, key)
        totals = {"seconds": 0.0, "down": 0.0, "brownout": 0.0}
        for ne, name in names.items():
            t = _tunnel_totals(data.get("{}:{}".format(kind, ne)), separate)
            for k in totals:
                totals[k] += t[k]
            for row in t["always_down"]:
                always_down.append({"appliance": name, "kind": label, "label": row.get("label"), "service": row.get("serviceName"), "tunnels": row.get("tunnelcount")})
            if t["seconds"]:
                pct = _pct(t["seconds"] - t["down"], t["seconds"])
                tunnel_rows.append({"appliance": name, "kind": label, "value": pct, "degraded_pct": _pct(t["brownout"], t["seconds"]), "status": band(pct, lim)})
        pct = _pct(totals["seconds"] - totals["down"], totals["seconds"])
        tunnel_status.append(band(pct, lim))
        tunnel_metrics += [metric(kind + "_avail_pct", pct, "%", label + " tunnel availability (derived)", band(pct, lim)),
                           metric(kind + "_degraded_pct", _pct(totals["brownout"], totals["seconds"]), "%", label + " brownout share")]
    tunnel_rows.sort(key=lambda r: (r["value"] is None, r["value"] or 0))
    notes = ["Derived from the Orchestrator's tunnel availability data as 1 - downtime / time sampled (samples are minutes, downtime is seconds); brownout is reported separately."]
    tunnel_metrics.append(metric("tunnel_groups_down_all_period", sum(int(r["tunnels"] or 1) for r in always_down), "tunnels",
                                 "Tunnels down for the whole period ({})".format("left out of the figures" if separate else "included in the figures")))
    if always_down:
        notes.append("Down for the whole period (up less than 1% of it), {}; often unused or decommissioned paths: ".format(
                     "so left out of the figures above (option: down tunnels separate)" if separate else "and counted in the figures above (option: down tunnels include)")
                     + "; ".join(" ".join([r["appliance"], r["kind"].lower()] + [str(x) for x in (r["label"], r["service"]) if x and x not in ("none", "unassigned")]
                                          + ["({} tunnel{})".format(r["tunnels"], "" if r["tunnels"] == 1 else "s")]) for r in always_down) + ".")
    sections["avail-tunnels"] = {"status": worst(tunnel_status), "metrics": tunnel_metrics, "table": tunnel_rows, "notes": notes}

    # Alarms raised in the period: the full list if the read POST ran, otherwise per-appliance counts (GET).
    counts = {"CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "WARNING": 0}
    alarm_rows: List[Dict[str, Any]] = []
    listed = data.get("appliance_alarms")
    covered = data.get("period_alarms_covered", True)
    if not covered:
        gaps.append("Alarms in the period: the Orchestrator keeps 7 days of alarms and the alarm archive (`report store`) does not cover the rest of the period, "
                    "so the counts are not shown.")
    if isinstance(listed, list) and data.get("appliance_alarms_capped", len(listed) >= MAX_ALARMS):
        gaps.append("Alarms in the period: the list reached the {}-alarm cap, so the counts may be low.".format(MAX_ALARMS))
    if isinstance(listed, list):
        for alarm in listed:
            sev = str(alarm.get("severity") or "").upper()
            if sev in counts:
                counts[sev] += 1
            alarm_rows.append({"appliance": names.get(alarm.get("applianceId"), alarm.get("applianceId")), "severity": sev.lower(), "description": str(alarm.get("description") or "")[:160]})
        alarm_rows.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], len(SEVERITY_ORDER)))
        source = "POST /alarm/appliance"
    else:
        for ne in names:
            period = data.get("alarm_period:" + str(ne)) or {}
            for sev, n in ((period.get("alarmCountsInPeriod") or {}) if isinstance(period, dict) else {}).items():
                if str(sev).upper() in counts and isinstance(n, int):
                    counts[str(sev).upper()] += n
        source = "GET /health/alarmPeriodSummary per appliance"
    have_alarms = covered and (isinstance(listed, list) or any(("alarm_period:" + str(ne)) in data for ne in names))
    alarm_status = "grey" if not have_alarms else "red" if counts["CRITICAL"] else "amber" if counts["MAJOR"] else "green"
    alarm_ids = [metric("alarms_" + sev.lower(), counts[sev] if have_alarms else None, "alarms", sev.title() + " alarms in the period") for sev in counts]
    sections["avail-alarms"] = {"status": alarm_status, "metrics": alarm_ids, "table": alarm_rows, "notes": ["Source: " + source + "."]}

    # Interfaces: like tunnels, `count` is minute samples and `state` is seconds down (9.7.1, 10.0).
    if_limits = _target_limits(ctx, "interfaceAvailability" if "interfaceAvailability" in threshold else "reachability")
    if_rows = []
    for ne, name in names.items():
        for row in data.get("ifavail:" + str(ne)) or []:
            if isinstance(row, dict) and row.get("count"):
                seconds = 60.0 * float(row["count"])
                pct = _pct(seconds - min(seconds, float(row.get("state") or 0)), seconds)
                if_rows.append({"appliance": name, "interface": row.get("ifname"), "label": "" if row.get("label") in (None, "none") else row.get("label"),
                                "availability_pct": pct, "status": band(pct, if_limits)})
    if_rows.sort(key=lambda r: (r["availability_pct"] if r["availability_pct"] is not None else 101, str(r["appliance"])))
    # Interfaces up less than 1% of the period are unused or unplugged ports, as down-all-period tunnels are: listed apart unless --down-tunnels include.
    unused = [r for r in if_rows if r["availability_pct"] is not None and r["availability_pct"] < 100 * (1 - ALWAYS_DOWN)]
    if separate:
        if_rows = [r for r in if_rows if r not in unused]
    below_if = sum(r["status"] in ("amber", "red") for r in if_rows)
    if_notes = ["Every interface with samples, lowest first (WAN, LAN and virtual)."]
    if unused:
        if_notes.append("{} interfaces were up less than 1% of the period, usually unused or unplugged ports, {}: {}.".format(
            len(unused), "listed here and left out of the table and status" if separate else "counted in the table and status",
            "; ".join("{} {}".format(r["appliance"], r["interface"]) for r in unused)))
    sections["avail-interfaces"] = {"status": worst([r["status"] for r in if_rows]) if if_rows else "grey", "table": if_rows,
                                    "metrics": [metric("interfaces_below_target", below_if if if_rows else None, "interfaces", "Interfaces below the availability target"),
                                                metric("interfaces_unused", len(unused), "interfaces", "Interfaces up less than 1% of the period")],
                                    "notes": if_notes}
    # Hubs and branches: the same reachability minutes, grouped by the appliance's network role.
    role_of = {a.get("nePk"): ROLE_NAMES.get(str(a.get("networkRole")), "unknown role") for a in inventory if a.get("networkRole") is not None}
    by_role: Dict[str, List[float]] = {}
    for ne in names:
        sample = (data.get("reach:" + str(ne)) or [{}])[0] if isinstance(data.get("reach:" + str(ne)), list) else {}
        if sample.get("samplecount") and ne in role_of:
            r = by_role.setdefault(role_of.get(ne, "unknown"), [0.0, 0.0, 0])
            r[0], r[1], r[2] = r[0] + float(sample.get("appliancereachability") or 0), r[1] + float(sample["samplecount"]), r[2] + 1
    role_rows = [{"role": role, "appliances": int(v[2]), "reachability_pct": _pct(v[0], v[1]), "status": band(_pct(v[0], v[1]), limits)} for role, v in sorted(by_role.items())]
    sections["avail-roles"] = {"status": worst([r["status"] for r in role_rows]) if role_rows else "grey", "metrics": [], "table": role_rows}
    sections["avail-paths"] = _paths(ctx)
    availability_status = worst([sections["avail-appliances"]["status"], sections["avail-tunnels"]["status"], sections["avail-paths"]["status"]])
    sections["avail-summary"] = {"status": availability_status, "metrics": [m_fleet, "overlay_avail_pct", "underlay_avail_pct", "alarms_critical", "appliances_total"]}
    return sections


def _paths(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Loss (after FEC), latency, jitter and MOS per tunnel over the period, graded against GET /health/healthThresholdConfig.

    Three kinds of tunnel: carrying traffic (loss % = lost / (received + lost)); near-idle but losing probes, which is a broken
    path and is red, counted or listed apart as --down-tunnels says; and no packets and no probe loss at all (loss: no data)."""
    data, names, metric, gaps = ctx["data"], ctx["names"], ctx["metric"], ctx["gaps"]
    separate = ctx["options"].get("down_tunnels") == "separate"
    # The floor is set for a month; a shorter window (an incident hour) gets a proportionally lower one, at least 100 packets.
    floor = max(100, int(MIN_LOSS_PACKETS * ctx.get("period_s", 30 * 86400) / (30 * 86400)))
    rows, broken = [], []
    for ne, name in names.items():
        value = data.get("paths:" + str(ne))
        for tunnel_id, per_ne in (value.items() if isinstance(value, dict) else []):
            stats = per_ne.get(ne) if isinstance(per_ne, dict) else None
            if not isinstance(stats, dict):
                continue
            received, lost, pre = float(stats.get("SUM_WRX_PKTS") or 0), float(stats.get("SUM_POST_LOSS") or 0), float(stats.get("SUM_PRE_LOSS") or 0)
            row = {"appliance": name, "tunnel": stats.get("alias") or tunnel_id, "kind": "underlay" if str(stats.get("overlayid")) == "0" else "overlay",
                   "loss_pct": round(100.0 * lost / (received + lost), 3) if received >= floor or (received and not lost) else None,
                   "pre_fec_loss_pct": round(100.0 * pre / (received + pre), 3) if received >= floor or (received and not pre) else None,
                   "latency_ms": float(stats["AVG_LATENCY_AVG"]) if isinstance(stats.get("AVG_LATENCY_AVG"), (int, float)) else None,
                   "jitter_ms": float(stats["AVG_JITTER"]) if isinstance(stats.get("AVG_JITTER"), (int, float)) else None,
                   "mos": round(stats["mos"] / 100.0, 2) if isinstance(stats.get("mos"), (int, float)) and stats["mos"] > 0 else None,  # tunnel aggregate MOS is x100
                   "note": ""}
            if received < floor and lost:
                row["note"] = "no traffic, probes lost"
                if separate:
                    broken.append(row)
                    continue
            rows.append(row)
    if not rows and not broken:
        return {"status": "grey", "metrics": [metric("paths_measured", 0, "tunnels", "Tunnels with path statistics")], "notes": ["No tunnel statistics for the period."]}
    limits = {key: health_limits(data, key, gaps) for key in ("packetLoss", "latency", "jitter", "mos")}
    for row in rows + broken:
        row["status"] = "red" if row["note"] else worst([band(row["loss_pct"], limits["packetLoss"], higher_is_better=False), band(row["latency_ms"], limits["latency"], higher_is_better=False),
                                                          band(row["jitter_ms"], limits["jitter"], higher_is_better=False), band(row["mos"], limits["mos"])])
    rows.sort(key=lambda r: (-("grey", "green", "amber", "red").index(r["status"]), -(r["loss_pct"] or 0), -(r["latency_ms"] or 0)))
    red, amber = sum(r["status"] == "red" for r in rows), sum(r["status"] == "amber" for r in rows)
    idle = sum(1 for r in rows if r["note"]) + len(broken)
    notes = ["Each tunnel graded on loss after FEC, latency, jitter and MOS against the Orchestrator's health thresholds: loss {} / {} %, latency {} / {} ms, jitter {} / {} ms, MOS {} / {}.".format(
        *(limits["packetLoss"] + limits["latency"] + limits["jitter"] + limits["mos"])),
             "Under {} packets received in the period a loss % means little, so a tunnel that lost probes there is shown as \"no traffic, probes lost\" and counted red: "
             "usually a broken path or a dead configuration.".format(floor)]
    if broken:
        notes.append("{} tunnels with no traffic and lost probes are listed apart and left out of the status (option: down tunnels separate): {}{}.".format(
            len(broken), "; ".join("{} {}".format(r["appliance"], r["tunnel"]) for r in broken), ""))
    return {"status": worst([r["status"] for r in rows]), "table": rows, "notes": notes,
            "metrics": [metric("paths_measured", len(rows), "tunnels", "Tunnels graded"),
                        metric("paths_red", red, "tunnels", "Tunnels outside the health thresholds", "red" if red else "green"),
                        metric("paths_amber", amber, "tunnels", "Tunnels between the health thresholds", "amber" if amber else "green"),
                        metric("paths_idle_probe_loss", idle, "tunnels", "Tunnels with no traffic and lost probes ({})".format("left out" if separate else "counted red"),
                               None if separate else ("red" if idle else "green"))]}


def _path_report(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """R3: the graded paths of _paths, plus loss that FEC hid and the underlay transports side by side."""
    metric, gaps = ctx["metric"], ctx["gaps"]
    ranked = _paths(ctx)
    rows = ranked.get("table") or []
    loss = health_limits(ctx["data"], "packetLoss", gaps) if rows else DEFAULT_HEALTH["packetLoss"]
    # FEC masking: before FEC above the higher loss limit, after FEC within the lower one. The circuit is bad; FEC pays for it in bandwidth.
    masked = [dict(r) for r in rows if r.get("pre_fec_loss_pct") is not None and r["pre_fec_loss_pct"] >= max(loss)
              and r.get("loss_pct") is not None and r["loss_pct"] <= min(loss)]
    masked.sort(key=lambda r: -r["pre_fec_loss_pct"])
    m_masked = metric("paths_fec_masking", len(masked) if rows else None, "tunnels", "Paths where FEC hides loss above {:g}%".format(max(loss)), "amber" if masked else "green")
    transports: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        if r["kind"] != "underlay" or r.get("note"):
            continue
        label = str(r["tunnel"]).rsplit("_", 1)[-1]  # underlay aliases end in <local label>-<remote label>, e.g. to_hub_INETA-INETA
        t = transports.setdefault(label, {"transport": label, "paths": 0, "outside_thresholds": 0, "between_thresholds": 0, "loss": [], "latency": []})
        t["paths"] += 1
        t["outside_thresholds"] += r["status"] == "red"
        t["between_thresholds"] += r["status"] == "amber"
        t["loss"] += [r["loss_pct"]] if r["loss_pct"] is not None else []
        t["latency"] += [r["latency_ms"]] if r["latency_ms"] is not None else []
    t_rows = [{"transport": t["transport"], "paths": t["paths"], "outside_thresholds": t["outside_thresholds"], "between_thresholds": t["between_thresholds"],
               "median_loss_pct": round(statistics.median(t["loss"]), 3) if t["loss"] else None,
               "median_latency_ms": round(statistics.median(t["latency"]), 1) if t["latency"] else None} for t in transports.values()]
    t_rows.sort(key=lambda r: (-r["outside_thresholds"], -r["between_thresholds"], r["transport"]))
    grey = "grey" if not rows else None
    ok = sum(r["status"] == "green" for r in rows)
    metric("paths_ok_pct", _pct(ok, len(rows)), "%", "Paths within every health threshold", "grey" if not rows else band(_pct(ok, len(rows)), (90.0, 98.0)))
    sections = {"paths-ranked": ranked,
                "paths-fec": {"status": grey or ("amber" if masked else "green"), "metrics": [m_masked], "table": masked,
                              "notes": ["A path is listed when loss before FEC is at or above {:g}% and loss after FEC is at or below {:g}% (the packet loss health limits).".format(max(loss), min(loss))]},
                "paths-transport": {"status": grey or worst(["red" if r["outside_thresholds"] else "amber" if r["between_thresholds"] else "green" for r in t_rows]) if t_rows else "grey",
                                    "metrics": [], "table": t_rows, "notes": ["Underlay paths only, grouped by the transport labels at the end of the tunnel name; medians across the paths."]}}
    sections["paths-summary"] = {"status": worst([ranked["status"], sections["paths-fec"]["status"]]),
                                 "metrics": [m for m in ("paths_ok_pct", "paths_measured", "paths_red", "paths_amber", "paths_fec_masking", "paths_idle_probe_loss") if m in ctx["metrics"]]}
    return sections


def _optimisation(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Optimised traffic only: LAN bytes in and out against WAN bytes; saved = LAN - WAN, reduction = saved / LAN."""
    data, names, metric = ctx["data"], ctx["names"], ctx["metric"]
    rows = []
    for ne, name in names.items():
        lan = wan = 0.0
        found = False

        def walk(node: Any) -> None:
            nonlocal lan, wan, found
            if isinstance(node, dict):
                if node.get("nePk") == ne and "SUM_LRX_BYTES" in node:
                    found = True
                    lan += float(node.get("SUM_LRX_BYTES") or 0) + float(node.get("SUM_LTX_BYTES") or 0)
                    wan += float(node.get("SUM_WTX_BYTES") or 0) + float(node.get("SUM_WRX_BYTES") or 0)
                    return
                for v in node.values():
                    walk(v)
        walk(data.get("flows:" + str(ne)))
        if found:
            rows.append({"appliance": name, "lan_bytes": int(lan), "wan_bytes": int(wan), "saved_bytes": int(lan - wan), "reduction_pct": _pct(lan - wan, lan)})
    rows.sort(key=lambda r: -r["saved_bytes"])
    lan, wan = sum(r["lan_bytes"] for r in rows), sum(r["wan_bytes"] for r in rows)
    status = "green" if rows else "grey"
    ids = [metric("opt_reduction_pct", _pct(lan - wan, lan), "%", "Reduction of optimised traffic"), metric("opt_saved_bytes", lan - wan if rows else None, "bytes", "WAN bytes saved"),
           metric("opt_lan_bytes", lan if rows else None, "bytes", "Optimised traffic before reduction")]
    return {"opt-summary": {"status": status, "metrics": ids},
            "opt-appliances": {"status": status, "metrics": [], "table": rows, "notes": ["Optimised traffic only (GET /stats/aggregate/flow, trafficType optimized_traffic): "
                                                                                    "LAN bytes in and out against WAN bytes out and in. Pass-through traffic is not reduced and is left out."],
                               "chart": {"title": "Reduction by appliance, % (largest 15 by bytes saved)", "zoom": False,
                                         "points": [(r["appliance"], r["reduction_pct"]) for r in rows[:15] if r["reduction_pct"] is not None]}}}


def _security(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Firewall flows allowed and dropped per zone pair, summed over the appliances; zone ids named from GET /zones."""
    data, names, metric = ctx["data"], ctx["names"], ctx["metric"]
    zones = data.get("zones") if isinstance(data.get("zones"), dict) else {}
    zone = lambda z: str((zones.get(str(z)) or {}).get("name") or "zone {}".format(z))
    pairs: Dict[Tuple[str, str], Dict[str, float]] = {}
    for ne in names:
        for row in data.get("security:" + str(ne)) or []:
            if isinstance(row, dict):
                p = pairs.setdefault((zone(row.get("fromZone")), zone(row.get("toZone"))), {"allowed": 0, "dropped": 0, "policy": 0, "routing": 0})
                for key, field in (("allowed", "flows_allowed"), ("dropped", "flows_dropped"), ("policy", "policy_drop_pkts"), ("routing", "routing_drop_pkts")):
                    p[key] += float(row.get(field) or 0)
    rows = [{"from_zone": a, "to_zone": b, "flows_allowed": int(v["allowed"]), "flows_dropped": int(v["dropped"]), "dropped_pct": _pct(v["dropped"], v["allowed"] + v["dropped"]),
             "policy_drop_packets": int(v["policy"]), "routing_drop_packets": int(v["routing"])} for (a, b), v in pairs.items()]
    rows.sort(key=lambda r: (-r["flows_dropped"], r["from_zone"], r["to_zone"]))
    status = "green" if rows else "grey"
    ids = [metric("sec_flows_dropped", sum(r["flows_dropped"] for r in rows) if rows else None, "flows", "Flows dropped by the firewall"),
           metric("sec_flows_allowed", sum(r["flows_allowed"] for r in rows) if rows else None, "flows", "Flows allowed"),
           metric("sec_zone_pairs", len(rows), "zone pairs", "Zone pairs with traffic")]
    return {"sec-summary": {"status": status, "metrics": ids},
            "sec-pairs": {"status": status, "metrics": [], "table": rows, "notes": ["Policy drops are flows denied by a firewall rule; routing drops are packets with no route."]}}


def _activity(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Changes from the audit log and alarms raised in the window: by type, repeating ones, and alarms soon after a change."""
    data, names, metric, gaps = ctx["data"], ctx["names"], ctx["metric"], ctx["gaps"]
    audit = data.get("activity_audit")
    alarms = [a for a in data.get("activity_alarms") or [] if a.get("applianceId") in names]
    for note in data.get("activity_alarm_notes") or []:
        gaps.append("Alarms: " + note)
    if audit is None:
        gaps.append("Changes: GET /action could not be read.")
    if data.get("activity_audit_full"):
        gaps.append("Changes: {} pages of the audit log were read ({} entries); older changes in the window are not listed.".format(AUDIT_MAX_PAGES, AUDIT_MAX_PAGES * AUDIT_PAGE))
    # Busy Orchestrators log hundreds of thousands of automatic changes a week, so changes are grouped (every group listed), not one row each.
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in audit or []:
        g = groups.setdefault((str(r.get("user") or ""), str(r.get("name") or "")), {"user": r.get("user"), "change": r.get("name"), "times": 0, "failed": 0,
                                                                                   "appliances": set(), "last": 0})
        g["times"] += 1
        g["failed"] += _failed(r)
        g["appliances"].add(r.get("nepk"))
        g["last"] = max(g["last"], r.get("queuedTime") or 0)
    changes = [{"user": g["user"], "change": g["change"], "times": g["times"], "failed": g["failed"], "appliances": len(g["appliances"] - {None, ""}),
                "last": _when(g["last"])} for g in sorted(groups.values(), key=lambda g: (-g["failed"], -g["times"]))]
    by_type: Dict[Tuple[str, str], int] = {}
    repeat: Dict[Tuple[Any, str], int] = {}
    for a in alarms:
        sev, name = str(a.get("severity") or "").lower(), str(a.get("name") or a.get("description") or "")
        by_type[(name, sev)] = by_type.get((name, sev), 0) + 1
        repeat[(a.get("applianceId"), name)] = repeat.get((a.get("applianceId"), name), 0) + 1
    type_rows = [{"alarm": n, "severity": sev, "times": k} for (n, sev), k in sorted(by_type.items(), key=lambda i: (SEVERITY_ORDER.get(i[0][1], 9), -i[1]))]
    repeat_rows = [{"appliance": names.get(ne, ne), "alarm": n, "times": k} for (ne, n), k in sorted(repeat.items(), key=lambda i: -i[1]) if k >= 3]
    changes_by_ne: Dict[Any, List[Tuple[int, str]]] = {}
    for r in audit or []:
        changes_by_ne.setdefault(r.get("nepk"), []).append((int(r.get("queuedTime") or 0), str(r.get("name") or "")))
    for times in changes_by_ne.values():
        times.sort()
    after = []
    for a in alarms:  # raised within an hour after a change on the same appliance (the latest such change is named)
        raised = int(a.get("timeOccurredInMills") or 0)
        times = changes_by_ne.get(a.get("applianceId"), [])
        i = bisect.bisect_right(times, (raised, "\uffff")) - 1
        if i >= 0 and raised - times[i][0] <= 3600000:
            after.append({"appliance": names.get(a.get("applianceId")), "alarm": str(a.get("name") or ""), "raised": _when(raised), "after_change": times[i][1]})
    to_clear = sorted((a["clearedTimeInMills"] - a["timeOccurredInMills"]) / 60000.0 for a in alarms
                      if isinstance(a.get("clearedTimeInMills"), (int, float)) and a["clearedTimeInMills"] > 0 and isinstance(a.get("timeOccurredInMills"), (int, float)))
    failed = sum(r["failed"] for r in changes)
    ids = [metric("act_changes", sum(r["times"] for r in changes) if audit is not None else None, "changes", "Changes in the audit log"),
           metric("act_changes_failed", failed if audit is not None else None, "changes", "Changes that failed", "amber" if failed else "green"),
           metric("act_alarms", len(alarms), "alarms", "Alarms raised"), metric("act_repeat", len(repeat_rows), "alarms", "Alarms raised 3 or more times on one appliance"),
           metric("act_median_clear_min", round(statistics.median(to_clear), 1) if to_clear else None, "minutes", "Median time to clear")]
    return {"act-summary": {"status": "amber" if failed or repeat_rows else "green", "metrics": ids},
            "act-changes": {"status": "amber" if failed else "green" if audit is not None else "grey", "metrics": [], "table": changes,
                            "notes": ["Changes grouped by user and type, those with failures first; system users such as OverlayManager are the Orchestrator's own automation."]},
            "act-alarms": {"status": "green", "metrics": [], "table": type_rows},
            "act-repeat": {"status": "amber" if repeat_rows else "green", "metrics": [], "table": repeat_rows, "notes": ["An alarm raised 3 or more times on one appliance in the window."]},
            "act-after-change": {"status": "amber" if after else "green", "metrics": [], "table": after,
                                 "notes": ["Alarms raised within an hour after a change on the same appliance. Timing only: it does not show that the change caused the alarm."]}}


def _when(ms: Any) -> str:
    return datetime.fromtimestamp(float(ms) / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M") if isinstance(ms, (int, float)) and ms > 0 else ""


def _failed(entry: Mapping[str, Any]) -> bool:
    return str(entry.get("completionStatus")).lower() == "false"



def _incident(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """What the data shows around an incident. Code never names a cause; the narrative may only describe what is here."""
    data, names, metric, gaps = ctx["data"], ctx["names"], ctx["metric"], ctx["gaps"]
    inc = data.get("incident") or {}
    start, end = inc.get("from_ms", 0), inc.get("to_ms", 0)
    if not data.get("incident_alarms_stored"):
        gaps.append("Part of the window, or the 24 hours before it, is older than the 7 days of alarms the Orchestrator keeps and is not in the alarm archive "
                    "(`report store`), so alarms raised then may be missing.")
    for note in dict.fromkeys(data.get("incident_alarm_notes") or []):  # the alarm-id lookup and the window read can say the same thing
        gaps.append("Alarms: " + note)
    get_only_list = data.get("incident_alarm_source") == "GET /alarm/correlatedAlarms"
    if get_only_list:
        gaps.append("Alarms come from the correlated alarm list (GET-only): it is empty when alarm correlation is off, and closed alarms carry no clear time, "
                    "so alarms raised before the window that closed since cannot be placed, and time to clear and alarms still open are not shown.")
    if data.get("incident_dropped"):
        gaps.append("{} more appliances had alarms in the window; only the {} with the most are covered.".format(data["incident_dropped"], INCIDENT_MAX_APPLIANCES))
    # Alarms open at any time in the window: raised before its end, and not cleared before its start.
    alarms = []
    for a in data.get("incident_alarms") or []:
        raised, cleared = a.get("timeOccurredInMills") or 0, a.get("clearedTimeInMills") or 0
        if cleared or not a.get("closed"):
            if raised <= end and (not cleared or cleared >= start):
                alarms.append(a)
        elif start <= raised <= end:  # closed without a clear time (GET-only correlated list): only those raised in the window
            alarms.append(a)
    # Alarms raised in the window first (they are the incident), then the ones that were already open; oldest first within each.
    alarms.sort(key=lambda a: (not start <= (a.get("timeOccurredInMills") or 0) <= end, a.get("timeOccurredInMills") or 0))
    counts = {sev: sum(1 for a in alarms if str(a.get("severity")).upper() == sev) for sev in ("CRITICAL", "MAJOR", "MINOR", "WARNING")}
    to_clear = sorted((a["clearedTimeInMills"] - a["timeOccurredInMills"]) / 60000.0 for a in alarms
                      if isinstance(a.get("clearedTimeInMills"), (int, float)) and a["clearedTimeInMills"] > 0 and isinstance(a.get("timeOccurredInMills"), (int, float)))
    still_open = None if get_only_list else sum(1 for a in alarms if not a.get("clearedTimeInMills") or a["clearedTimeInMills"] > end)
    rows = [{"raised": _when(a.get("timeOccurredInMills")), "appliance": names.get(a.get("applianceId"), a.get("applianceId")), "severity": str(a.get("severity") or "").lower(),
             "alarm": str(a.get("name") or ""), "description": str(a.get("description") or "")[:120],
             "cleared": _when(a.get("clearedTimeInMills")) or ("closed, time not given" if a.get("closed") else "open"), "minutes_to_clear": round((a["clearedTimeInMills"] - a["timeOccurredInMills"]) / 60000.0, 1)
             if a.get("clearedTimeInMills") and a.get("timeOccurredInMills") else None} for a in alarms]
    read = data.get("incident_alarm_source") not in (None, "none") or bool(data.get("incident_alarms"))
    alarm_status = "grey" if not read else "red" if counts["CRITICAL"] else "amber" if counts["MAJOR"] else "green"
    sections: Dict[str, Dict[str, Any]] = {}
    sections["inc-timeline"] = {"status": alarm_status, "table": rows,
                                "metrics": [metric("inc_alarms", len(alarms), "alarms", "Alarms open in the window"),
                                            metric("inc_critical", counts["CRITICAL"], "alarms", "Critical alarms"), metric("inc_major", counts["MAJOR"], "alarms", "Major alarms"),
                                            metric("inc_open_at_end", still_open, "alarms", "Still open at the end of the window"),
                                            metric("inc_median_clear_min", round(statistics.median(to_clear), 1) if to_clear else None, "minutes", "Median time to clear"),
                                            metric("inc_max_clear_min", round(to_clear[-1], 1) if to_clear else None, "minutes", "Longest time to clear")],
                                "notes": ["Every alarm open at any time in the window: those raised in it first, then those already open, oldest first within each."]}
    # Reachability of each affected appliance inside the window, from the minute samples.
    limits = _target_limits(ctx, "reachability")
    app_rows = []
    for ne in inc.get("affected") or []:
        samples = reach = 0.0
        for key, value in data.items():
            if key.startswith("reach_minutes:{}:".format(ne)) and isinstance(value, dict):
                for row in value.get("data") or []:
                    if isinstance(row, dict) and start <= float(row.get("timestamp") or 0) * 1000 <= end:
                        samples += float(row.get("samplecount") or 0)
                        reach += float(row.get("appliancereachability") or 0)
        pct = _pct(reach, samples)
        app_rows.append({"appliance": names.get(ne, ne), "alarms": sum(1 for a in alarms if a.get("applianceId") == ne), "reachable_pct": pct, "status": band(pct, limits)})
    sections["inc-appliances"] = {"status": worst([r["status"] for r in app_rows]) if app_rows else "grey", "table": app_rows,
                                  "metrics": [metric("inc_affected", len(app_rows), "appliances", "Appliances affected")],
                                  "notes": ["Affected: the --scope appliances, else those with alarms raised in the window (at most {}). Reachability from minute samples.".format(INCIDENT_MAX_APPLIANCES)]}
    sections["inc-paths"] = _paths(dict(ctx, names={ne: names.get(ne, ne) for ne in inc.get("affected") or []}))
    sections["inc-paths"].setdefault("notes", []).insert(0, "Statistics basis: {} buckets (finer data is no longer kept for older windows).".format(inc.get("granularity", "?")))
    # Changes: the audit log in the window and the 24 hours before it.
    changes = sorted([r for r in data.get("incident_audit") or [] if isinstance(r, dict) and start - INCIDENT_LOOKBACK_MS <= (r.get("queuedTime") or 0) <= end],
                     key=lambda r: r.get("queuedTime") or 0)
    before = [r for r in changes if r.get("queuedTime", 0) < start]
    full = data.get("incident_audit_full") or []
    for page in full:
        gaps.append("Changes{}: the audit log returned its limit of {} entries, newest first, so nothing before {} UTC is shown (a busy audit log). "
                    "A full audit trail needs a remote log receiver (syslog or HTTPS).".format(
                        " for " + str(names.get(page["appliance"], page["appliance"])) if page.get("appliance") else "", AUDIT_PAGE, _when(page["oldest"])))
    read_ok = data.get("incident_audit_ok", True)
    if not read_ok:
        gaps.append("Changes: the audit log could not be read for every appliance in scope.")
    # A count that a full page may have cut is not shown as a number: before is cut whenever a page is full, during if a page
    # reached back no further than the window's start.
    reached = max((page["oldest"] for page in full), default=None)  # "during" is complete only if every full page reached back before the start
    n_before = None if full or not read_ok else len(before)
    n_during = None if not read_ok or (reached is not None and reached > start) else len(changes) - len(before)
    sections["inc-changes"] = {"status": "grey" if not read_ok and not changes else "green",
                               "table": [{"time": _when(r.get("queuedTime")), "when": "before" if r.get("queuedTime", 0) < start else "during", "user": r.get("user"),
                                          "action": str(r.get("name") or "").strip(), "appliance": names.get(r.get("nepk"), r.get("nepk") or ""),
                                          "result": "failed" if _failed(r) else "ok"} for r in changes][-40:],
                               "metrics": [metric("inc_changes_before", n_before, "changes", "Changes in the 24 hours before"),
                                           metric("inc_changes_during", n_during, "changes", "Changes during the window")],
                               "notes": ["Shown next to the alarms so a reader can compare times; the report does not say whether any change caused the incident. Newest 40 shown."]}
    sections["inc-summary"] = {"status": worst([alarm_status, sections["inc-appliances"]["status"], sections["inc-paths"]["status"]]),
                               "metrics": ["inc_alarms", "inc_critical", "inc_affected", "inc_open_at_end", "inc_changes_before", "inc_changes_during"],
                               "notes": ["Window {} to {} UTC{}.".format(_when(start), _when(end), " (around alarm {})".format(inc["alarm_id"]) if inc.get("alarm_id") else "")]}
    return sections


def _noc(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    data, inventory, names, metric, gaps, now_s = ctx["data"], ctx["inventory"], ctx["names"], ctx["metric"], ctx["gaps"], ctx["now_s"]
    sections: Dict[str, Dict[str, Any]] = {}
    # Appliance state now.
    counts = {name: 0 for name in STATE_NAMES.values()}
    state_of: Dict[Any, str] = {}
    for a in inventory:
        state_of[a.get("nePk")] = STATE_NAMES.get(a.get("state"), "state {}".format(a.get("state")))
        counts[state_of[a.get("nePk")]] = counts.get(state_of[a.get("nePk")], 0) + 1
    not_normal = len(inventory) - counts["normal"]
    share = _pct(not_normal, len(inventory))
    state_status = "grey" if not inventory else "green" if not not_normal else "red" if share > 10 else "amber"
    paused = set(((data.get("maintenance") or {}).get("pauseOrchestration") or []) if isinstance(data.get("maintenance"), dict) else [])
    sections["noc-appliances"] = {"status": state_status, "metrics": [metric("state_" + name.replace(" ", "_"), counts[name], "appliances", "Appliances " + name)
                                                                      for name in STATE_NAMES.values()],
                                  "table": [{"appliance": names[ne], "state": st, "maintenance": "yes" if ne in paused else ""} for ne, st in sorted(state_of.items(), key=lambda i: str(names[i[0]])) if st != "normal"],
                                  "notes": ["Rule: any appliance not normal is amber; more than 10% is red."]}

    # Active alarms: the list through the read POST, else the GET totals and per-appliance counts.
    sev_counts: Dict[str, Optional[int]] = {"critical": 0, "major": 0, "minor": 0, "warning": 0}
    per_ne: Dict[Any, Dict[str, int]] = {}
    rows: List[Dict[str, Any]] = []
    active = data.get("active_alarms")
    if isinstance(active, list) and len(active) >= MAX_ALARMS:
        gaps.append("Active alarms: the list reached the {}-alarm cap, so the counts may be low.".format(MAX_ALARMS))
    if isinstance(active, list):
        for alarm in active:
            sev = str(alarm.get("severity") or "").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
                per_ne.setdefault(alarm.get("applianceId"), {}).setdefault(sev, 0)
                per_ne[alarm.get("applianceId")][sev] += 1
            if sev:
                since = alarm.get("timeOccurredInMills")
                rows.append({"appliance": names.get(alarm.get("applianceId"), alarm.get("applianceId")), "severity": sev, "description": str(alarm.get("description") or "")[:160],
                             "since": datetime.fromtimestamp(since / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M") if isinstance(since, (int, float)) else ""})
        rows.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], len(SEVERITY_ORDER)))
        source = "POST /alarm/appliance (active)"
    else:
        summary = data.get("alarm_summary") if isinstance(data.get("alarm_summary"), dict) else None
        counts = data.get("alarm_counts")
        for item in counts if isinstance(counts, list) else []:
            if isinstance(item, dict) and item.get("applianceId") in names:
                per_ne[item["applianceId"]] = {sev: int(item.get("numOf{}Alarms".format(sev.title())) or 0) for sev in ("critical", "major", "minor", "warning")}
        if isinstance(counts, list):  # only the appliances in scope; GET /alarm/summary is network-wide
            sev_counts = {sev: sum(c.get(sev, 0) for c in per_ne.values()) for sev in sev_counts}
        elif ctx["options"].get("scope", "all") == "all":
            sev_counts = {sev: summary.get("numOf{}Alarms".format(sev.title())) if summary else None for sev in sev_counts}
        else:  # a scoped report must not show fleet-wide totals
            sev_counts = {sev: None for sev in sev_counts}
            gaps.append("Active alarms: GET /alarm/count/appliance gave nothing and GET /alarm/summary is network-wide, so the scoped counts are not shown.")
        rows = [{"appliance": names[ne], "critical": c.get("critical", 0), "major": c.get("major", 0), "minor": c.get("minor", 0), "warning": c.get("warning", 0)}
                for ne, c in sorted(per_ne.items(), key=lambda i: (-i[1].get("critical", 0), -i[1].get("major", 0)))]
        source = "GET /alarm/summary and GET /alarm/count/appliance (counts only; the alarm list needs the read POST)"
    alarm_status = "grey" if sev_counts["critical"] is None else "red" if sev_counts["critical"] else "amber" if sev_counts["major"] else "green"
    retention = (data.get("alarm_retention") or {}).get("historical_appliance_alarm", {}).get("retention") if isinstance(data.get("alarm_retention"), dict) else None
    notes = ["Source: " + source + "."]
    if isinstance(retention, (int, float)):
        notes.append("This Orchestrator keeps {:g} days of alarm history.".format(retention / 86400))
    sections["noc-alarms"] = {"status": alarm_status, "notes": notes, "table": rows,
                              "metrics": [metric("active_" + sev, n, "alarms", "Active {} alarms".format(sev)) for sev, n in sev_counts.items()]}

    # Health: share of appliance-hours in good health (POST /health hourly entries; blank hours are not counted). Read once per
    # category; the combined hour is the worst category, as the Orchestrator's own combined status is.
    per_category = {v: data.get("health:" + v) for v in HEALTH_VERTICALS if isinstance(data.get("health:" + v), dict)}
    health = _combine_health(per_category) if per_category else data.get("health")  # "health": bundles from before 0.4.3
    health_ids, health_status, seen = [], "grey", set()
    bad_hours: Dict[Any, int] = {}
    if isinstance(health, dict):
        for window, seconds in (("24h", 86400), ("7d", 7 * 86400)):
            total = good = 0
            for ne, entries in health.items():
                for entry in entries if isinstance(entries, list) and ne in names else []:
                    status = str(entry.get("status") or "").upper()
                    if entry.get("blank") or not status or float(entry.get("time") or 0) < now_s - seconds:
                        continue
                    seen.add(status)
                    total += 1
                    good += status in GOOD_HEALTH
                    if window == "24h" and status not in GOOD_HEALTH:
                        bad_hours[ne] = bad_hours.get(ne, 0) + 1
            pct = _pct(good, total)
            health_ids.append(metric("health_good_{}_pct".format(window), pct, "%", "Appliance-hours in good health, last {}".format(window), band(pct, (95.0, 99.0))))
        health_status = metrics_status(ctx, health_ids[0])
    else:
        gaps.append("Health: POST /health did not run, so hourly health is not shown.")
        health_ids = [metric("health_good_24h_pct", None, "%", "Appliance-hours in good health, last 24h"), metric("health_good_7d_pct", None, "%", "Appliance-hours in good health, last 7d")]
    notes = ["Rule (the report's own rule: the Orchestrator has no setting for it): at least 99% of appliance-hours healthy is green, 95% amber, less red. Statuses seen: {}.".format(", ".join(sorted(seen)) or "none")]
    table: List[Dict[str, Any]] = []
    if per_category:
        shares = {}
        for vertical, value in per_category.items():
            key = vertical.lower()
            shares[vertical] = {w: _good_share(value, names, now_s - seconds) for w, seconds in (("24h", 86400), ("7d", 7 * 86400))}
            health_ids += [metric("health_{}_good_{}_pct".format(key, w), shares[vertical][w]["all"], "%", "Appliance-hours with {} healthy, last {}".format(HEALTH_LABELS[vertical], w),
                                  band(shares[vertical][w]["all"], (95.0, 99.0))) for w in ("24h", "7d")]
        for ne, name in names.items():
            table.append(dict({"appliance": name}, **{v.lower(): shares[v]["24h"]["by_ne"].get(ne) for v in per_category}))
        table.sort(key=lambda r: min([x for k, x in r.items() if k != "appliance" and x is not None], default=101))
        measured = {v: s["24h"]["all"] for v, s in shares.items() if s["24h"]["all"] is not None}
        bad = [v for v, pct in measured.items() if pct < 50]
        if len(bad) == 1 and len(measured) > 1 and all(pct >= 99 for v, pct in measured.items() if v not in bad):
            notes.append("Only {0} is unhealthy, in most hours, while every other category is healthy: check the {0} health thresholds (GET /health/healthThresholdConfig) "
                         "against the measured {0} values before treating this as a network problem.".format(HEALTH_LABELS[bad[0]]))
        notes.append("Table: share of the last 24 hours each category was healthy, per appliance, worst first; blank means the category had no data.")
    sections["noc-health"] = {"status": health_status, "metrics": health_ids, "table": table, "notes": notes}

    # Tunnels down now, from the cached tunnel state (one network-wide read each).
    tunnel_ids, tunnel_rows, tunnel_status = [], [], []
    down_per_ne: Dict[Any, int] = {}
    for kind, key in (("physical", "tunnels_physical"), ("bonded", "tunnels_bonded")):
        value = data.get(key)
        if not isinstance(value, dict):
            tunnel_ids += [metric("tunnels_{}_down".format(kind), None, "tunnels", "{} tunnels down".format(kind.title()))]
            continue
        total = down = 0
        for ne, tunnels in value.items():
            for tunnel in (tunnels.values() if isinstance(tunnels, dict) and ne in names else []):
                total += 1
                if not str(tunnel.get("operStatus") or "").lower().startswith("up"):
                    down += 1
                    down_per_ne[ne] = down_per_ne.get(ne, 0) + 1
                    tunnel_rows.append({"appliance": names[ne], "kind": kind, "tunnel": tunnel.get("alias"), "state": tunnel.get("operStatus")})
        share = _pct(down, total)
        tunnel_status.append("grey" if not total else "green" if not down else "red" if share > 10 else "amber")
        tunnel_ids += [metric("tunnels_{}_down".format(kind), down, "tunnels", "{} tunnels down".format(kind.title()), tunnel_status[-1]),
                       metric("tunnels_{}_total".format(kind), total, "tunnels", "{} tunnels".format(kind.title()))]
    sections["noc-tunnels"] = {"status": worst(tunnel_status), "metrics": tunnel_ids, "table": tunnel_rows,
                               "notes": ["Rule: any tunnel not up is amber; more than 10% of tunnels is red. Bonded tunnels are the overlays."]}

    # Sites needing attention: a fixed score so the order is reproducible.
    scored = []
    for ne, name in names.items():
        alarms = per_ne.get(ne, {})
        score = (100 if state_of.get(ne) != "normal" else 0) + 10 * alarms.get("critical", 0) + 3 * alarms.get("major", 0) + 2 * down_per_ne.get(ne, 0) + bad_hours.get(ne, 0)
        if score:
            scored.append({"appliance": name, "state": state_of.get(ne), "critical": alarms.get("critical", 0), "major": alarms.get("major", 0),
                           "tunnels_down": down_per_ne.get(ne, 0), "unhealthy_hours_24h": bad_hours.get(ne, 0), "score": score})
    scored.sort(key=lambda r: -r["score"])
    sections["noc-worst"] = {"status": "green" if not scored else worst([state_status, alarm_status, worst(tunnel_status)]), "table": scored,
                             "metrics": [metric("sites_needing_attention", len(scored), "appliances", "Appliances needing attention")],
                             "notes": ["Score: not normal 100, each critical alarm 10, each major 3, each tunnel down 2, each unhealthy hour 1."]}
    sections["noc-summary"] = {"status": worst([state_status, alarm_status, health_status, worst(tunnel_status)]),
                               "metrics": ["state_unreachable", "active_critical", "active_major", "tunnels_bonded_down", "health_good_24h_pct", "sites_needing_attention"]}
    return sections


HEALTH_RANK = {"HEALTHY": 0, "WARNING": 1, "MINOR": 2, "MAJOR": 3, "CRITICAL": 4}
HEALTH_LABELS = {"ALARM": "alarms", "LOSS": "loss", "LATENCY": "latency", "JITTER": "jitter", "MOS": "MOS", "BW_UTILIZATION": "utilisation"}


def _combine_health(per_category: Mapping[str, Any]) -> Dict[Any, List[Dict[str, Any]]]:
    """One entry per appliance-hour whose status is the worst category with a status (hours no category rated are left out)."""
    worst_of: Dict[Tuple[Any, Any], str] = {}
    for value in per_category.values():
        for ne, entries in value.items():
            for entry in entries if isinstance(entries, list) else []:
                status = str(entry.get("status") or "").upper()
                if entry.get("blank") or status not in HEALTH_RANK:
                    continue
                key = (ne, entry.get("time"))
                if key not in worst_of or HEALTH_RANK[status] > HEALTH_RANK[worst_of[key]]:
                    worst_of[key] = status
    combined: Dict[Any, List[Dict[str, Any]]] = {}
    for (ne, at), status in worst_of.items():
        combined.setdefault(ne, []).append({"status": status, "time": at})
    return combined


def _good_share(value: Any, names: Mapping[Any, Any], since: float) -> Dict[str, Any]:
    """% of rated appliance-hours since `since` that were HEALTHY, overall and per appliance (None where nothing was rated)."""
    total = good = 0
    by_ne: Dict[Any, Optional[float]] = {}
    for ne, entries in (value.items() if isinstance(value, dict) else []):
        n = g = 0
        for entry in entries if isinstance(entries, list) and ne in names else []:
            status = str(entry.get("status") or "").upper()
            if entry.get("blank") or status not in HEALTH_RANK or float(entry.get("time") or 0) < since:
                continue
            n, g = n + 1, g + (status in GOOD_HEALTH)
        by_ne[ne] = _pct(g, n)
        total, good = total + n, good + g
    return {"all": _pct(good, total), "by_ne": by_ne}


def _wan(row: Mapping[str, Any], tx: str, rx: str) -> int:
    return int(float(row.get(tx) or 0) + float(row.get(rx) or 0))


def _header_rows(value: Any) -> List[Dict[str, Any]]:
    """Positional rows ([{"<nePk>": [[...], ...]}, {"header": [[names]]}]) as dicts, for every appliance in the answer."""
    items = value if isinstance(value, list) else []
    header = next((i["header"][0] for i in items if isinstance(i, dict) and isinstance(i.get("header"), list) and i["header"]), None)
    if not header:
        return []
    return [dict(zip(header, row)) for i in items if isinstance(i, dict) and "header" not in i for rows in i.values() if isinstance(rows, list)
            for row in rows if isinstance(row, list)]


def _shares(totals: Mapping[str, int], key: str) -> List[Dict[str, Any]]:
    """Every entry, largest first, with its share of the table's total."""
    whole = sum(totals.values())
    return [{key: name, "wan_bytes": n, "share_pct": round(100.0 * n / whole, 2) if whole else None}
            for name, n in sorted(totals.items(), key=lambda i: (-i[1], str(i[0])))]


def _traffic(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """WAN bytes (sent + received) by application, talker, domain, country, port and traffic class, summed over the appliances."""
    data, names, metric = ctx["data"], ctx["names"], ctx["metric"]
    apps: Dict[str, int] = {}
    total = previous = 0
    read_now = read_before = False
    stamps: List[float] = []
    for ne in names:
        for key, is_now in (("apps:", True), ("apps_previous:", False)):
            rows = data.get(key + str(ne))
            if not isinstance(rows, list):
                continue
            for row in rows:
                n = _wan(row, "SUM_WTX_BYTES", "SUM_WRX_BYTES")
                if row.get("APPNAME") == "__total__":
                    total, previous = (total + n, previous) if is_now else (total, previous + n)
                    if is_now:
                        stamps += [float(row[k]) for k in ("MIN_TIMESTAMP", "MAX_TIMESTAMP") if isinstance(row.get(k), (int, float))]
                elif is_now:
                    apps[str(row.get("APPNAME"))] = apps.get(str(row.get("APPNAME")), 0) + n
            read_now, read_before = read_now or is_now, read_before or not is_now
    app_rows = _shares(apps, "application")
    for r in app_rows:  # share of all WAN traffic (the __total__ rows), not of the named applications only
        r["share_pct"] = round(100.0 * r["wan_bytes"] / total, 2) if total else None
    # Application stats are hourly only and kept about 14 days (GET /gms/stats/retention "flowapp"): an older period is only partly there.
    start_s, end_s = ctx["period_from_s"], ctx["period_from_s"] + ctx["period_s"]
    covered = round((max(stamps) + 3600 - min(stamps)) / 86400, 1) if stamps else None
    partial = bool(stamps) and min(stamps) > start_s + 86400
    if partial:
        ctx["gaps"].append("Traffic: application data covers only {} to {} UTC of the period; the Orchestrator keeps hourly application statistics for about 14 days, "
                           "so the totals are for that part only and are not compared with the period before.".format(
                               datetime.fromtimestamp(min(stamps), timezone.utc).strftime("%Y-%m-%d"), datetime.fromtimestamp(min(max(stamps), end_s), timezone.utc).strftime("%Y-%m-%d")))
    change = round(100.0 * (total - previous) / previous, 2) if read_before and previous and not partial else None
    status = "green" if read_now else "grey"
    sections: Dict[str, Dict[str, Any]] = {}
    m_total = metric("wan_bytes_total", total if read_now else None, "bytes", "WAN traffic, sent and received")
    m_change = metric("wan_bytes_change_pct", change, "%", "Change against the previous period of the same length")
    m_top = metric("top_app_share_pct", app_rows[0]["share_pct"] if app_rows else None, "%", "Largest application's share of WAN traffic")
    m_apps = metric("applications_seen", len(app_rows), "applications", "Applications with traffic")
    m_days = metric("traffic_days_covered", covered, "days", "Days of the period with application data")
    sections["traffic-apps"] = {"status": status, "metrics": [m_apps, m_top], "table": app_rows,
                                "chart": {"title": "Share of WAN traffic by application, % (largest 15)", "zoom": False,
                                          "points": [(r["application"], r["share_pct"]) for r in app_rows[:15] if r["share_pct"] is not None]}}
    talkers = []
    for ne, name in names.items():
        for item in data.get("talkers:" + str(ne)) or []:
            for row in (item.get(ne) or []) if isinstance(item, dict) else []:
                talkers.append({"appliance": name, "source_ip": row.get("SOURCE_IP"), "wan_bytes": _wan(row, "WANTX_BYTES", "WANRX_BYTES")})
    talkers.sort(key=lambda r: -r["wan_bytes"])
    sections["traffic-talkers"] = {"status": "green" if talkers else "grey", "metrics": [], "table": talkers,
                                   "notes": ["The Orchestrator returns the top talkers capped at {} per appliance, so smaller talkers are not listed.".format(TALKERS_CAP)]}
    domains: Dict[str, int] = {}
    countries: Dict[str, int] = {}
    ports: Dict[str, int] = {}
    for ne in names:
        for row in _header_rows(data.get("dns:" + str(ne))):
            n = _wan(row, "WANTX_BYTES", "WANRX_BYTES")
            domain = str(row.get("DNS") or row.get("CALC_DNS") or row.get("IPADDR") or "unknown")
            country = str(row.get("COUNTRY") or "unknown")
            domains[domain] = domains.get(domain, 0) + n
            countries[country] = countries.get(country, 0) + n
        for row in _header_rows(data.get("ports:" + str(ne))):
            key = "{}/{}".format(row.get("PORT"), PROTOCOLS.get(row.get("PROTOCOL"), row.get("PROTOCOL")))
            ports[key] = ports.get(key, 0) + _wan(row, "WANTX_BYTES", "WANRX_BYTES")
    for sid, totals, key, note in (("traffic-domains", domains, "domain", "Named by DNS where the appliance saw the lookup, else by IP address."),
                                   ("traffic-countries", countries, "country", "RFC1918 is private address space (inside your network)."),
                                   ("traffic-ports", ports, "port", "Port and protocol of the flows, both directions.")):
        rows = _shares(totals, key)
        sections[sid] = {"status": "green" if rows else "grey", "metrics": [], "table": rows, "notes": [note],
                         "chart": {"title": "Share of WAN traffic, % (largest 15)", "zoom": False, "points": [(r[key], r["share_pct"]) for r in rows[:15] if r["share_pct"] is not None]}}
    classes: Dict[str, int] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if "TRAFFIC_CLASS" in node and node.get("nePk") in names:
                cls = "class {}".format(node["TRAFFIC_CLASS"])
                classes[cls] = classes.get(cls, 0) + _wan(node, "SUM_WTX_BYTES", "SUM_WRX_BYTES")
                return
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    for ne in names:
        walk(data.get("classes:" + str(ne)))
    rows = _shares(classes, "traffic_class")
    sections["traffic-classes"] = {"status": "green" if rows else "grey", "metrics": [], "table": rows, "notes": ["Traffic classes as defined in the QoS (shaper) policy, all traffic types."]}
    sections["traffic-summary"] = {"status": status, "metrics": [m_total, m_change, m_top, m_apps, m_days]}
    if read_now and not read_before:
        ctx["gaps"].append("Traffic: the previous period could not be read, so the change is not shown.")
    return sections


def metrics_status(ctx: Dict[str, Any], mid: str) -> str:
    return ctx["metrics"][mid].get("status") or "grey"


def _drivers(rows: Any, count: int = 3) -> str:
    """The appliance's largest applications with their share of its WAN traffic, e.g. "Backup 60%, Zoom 30%"."""
    rows = rows if isinstance(rows, list) else []
    total = sum(_wan(r, "SUM_WTX_BYTES", "SUM_WRX_BYTES") for r in rows if r.get("APPNAME") == "__total__")
    named = sorted((r for r in rows if r.get("APPNAME") != "__total__"), key=lambda r: -_wan(r, "SUM_WTX_BYTES", "SUM_WRX_BYTES"))[:count]
    return ", ".join("{} {:.0f}%".format(r.get("APPNAME"), 100.0 * _wan(r, "SUM_WTX_BYTES", "SUM_WRX_BYTES") / total) for r in named) if total else ""


def _capacity(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    data, names, metric, gaps = ctx["data"], ctx["names"], ctx["metric"], ctx["gaps"]
    links = wan_links(data, names)
    basis = data.get("capacity_basis") or {"granularity": "hour", "retention_known": True}
    bucket = 86400 if basis.get("granularity") == "day" else 3600
    if not basis.get("retention_known"):
        gaps.append("Capacity: hourly retention not readable from GET /gms/stats/retention; {:g} days assumed.".format(HOURLY_RETENTION / 86400))
    limits = health_limits(data, "bwUtilization", gaps) if links else DEFAULT_HEALTH["bwUtilization"]
    before = {(l["nePk"], l["interface"]): max(l["avg_tx_pct"] or 0, l["avg_rx_pct"] or 0) for l in wan_links({"interface_totals": data.get("interface_totals_previous")}, names)} \
        if isinstance(data.get("interface_totals_previous"), list) else {}
    rows = []
    for link in links:
        hourly = data.get("hourly:{}:{}".format(link["nePk"], link["interface"]))
        tx, rx = [], []
        by_hour: Dict[int, List[float]] = {}
        for row in hourly if isinstance(hourly, list) else []:
            if bucket == 3600 and isinstance(row.get("timestamp"), (int, float)):
                load = [_util(float(row.get(k) or 0), bucket, float(row.get(b) or 0)) for k, b in (("tx_bytes", "max_bw_tx"), ("rx_bytes", "max_bw_rx"))]
                by_hour.setdefault(int(row["timestamp"]) // 3600 % 24, []).append(max([v for v in load if v is not None], default=0.0))
            # Each hourly row carries the configured bandwidth (kbps) at that time.
            for values, key, bw in ((tx, "tx_bytes", "max_bw_tx"), (rx, "rx_bytes", "max_bw_rx")):
                pct = _util(float(row.get(key) or 0), bucket, float(row.get(bw) or 0))
                if pct is not None:
                    values.append(pct)
        p95_tx, p95_rx = _p95(tx), _p95(rx)
        peak = max([v for v in (p95_tx, p95_rx) if v is not None], default=None)
        peak_hour = max(sorted(by_hour), key=lambda h: statistics.mean(by_hour[h])) if by_hour else None
        now_avg = max(link["avg_tx_pct"] or 0, link["avg_rx_pct"] or 0)
        status = _load_status(peak, limits)
        rows.append({"appliance": names.get(link["nePk"], link["nePk"]), "interface": link["interface"], "label": link["label"],
                     "outbound_mbps": round(link["bw_tx"] / 1000, 1), "inbound_mbps": round(link["bw_rx"] / 1000, 1),
                     "avg_out_pct": link["avg_tx_pct"], "avg_in_pct": link["avg_rx_pct"], "p95_out_pct": p95_tx, "p95_in_pct": p95_rx,
                     "buckets": max(len(tx), len(rx)), "peak_hour_utc": "{:02d}:00".format(peak_hour) if peak_hour is not None else None,
                     "avg_change_pts": round(now_avg - before[(link["nePk"], link["interface"])], 2) if (link["nePk"], link["interface"]) in before else None,
                     "top_applications": _drivers(data.get("apps:" + str(link["nePk"]))) if status in ("amber", "red") else "", "status": status})
    measured = [r for r in rows if r["status"] != "grey"]
    flagged = [r for r in measured if r["status"] in ("amber", "red")]
    worst_p95 = max([max(v for v in (r["p95_out_pct"], r["p95_in_pct"]) if v is not None) for r in measured], default=None)
    status = "grey" if not measured else worst([r["status"] for r in measured])
    rows.sort(key=lambda r: (r["status"] == "grey", -max(r["p95_out_pct"] or 0, r["p95_in_pct"] or 0), -max(r["avg_out_pct"] or 0, r["avg_in_pct"] or 0)))
    if not links:
        gaps.append("Capacity: no WAN interfaces found (POST /stats/aggregate/interface, or GET /stats/timeseries/interfaceOverlay under GET-only).")
    window = "P95 of hourly averages over the part of the period inside hourly retention; hourly averages understate short bursts." if bucket == 3600 else \
        "P95 of daily averages: the period is older than the hourly data the Orchestrator keeps, and daily averages understate peaks much more than hourly ones."
    notes = [window, "Outbound = WAN Tx, inbound = WAN Rx, against the configured bandwidth. Rule: P95 at or above {:g}% is amber, {:g}% red (bwUtilization limits).".format(*sorted(limits)),
             "Links ranked by average utilisation from {}.".format(links[0]["source"] if links else "the interface totals")]
    if data.get("capacity_top"):
        notes.append("Only the {} busiest links got a P95 read (option --top); the rest stay grey.".format(data["capacity_top"]))
    m_flag = metric("links_flagged", len(flagged) if measured else None, "links", "WAN links at or above {:g}% P95".format(min(limits)), status)
    sections = {"cap-links": {"status": status, "metrics": [m_flag], "table": rows, "notes": notes,
                              "chart": {"title": "Highest WAN P95 utilisation, % of configured bandwidth", "zoom": False,
                                        "points": [("{} {}".format(r["appliance"], r["interface"]), max(r["p95_out_pct"] or 0, r["p95_in_pct"] or 0), r["status"]) for r in rows if r["status"] != "grey"][:20]}}}
    sections["cap-summary"] = {"status": status, "metrics": [m_flag, metric("worst_p95_pct", worst_p95, "%", "Highest WAN P95 utilisation", _load_status(worst_p95, limits)),
                                                             metric("links_measured", len(measured), "links", "WAN links with a P95"),
                                                             metric("wan_links", len(links), "links", "WAN links found")]}
    return sections


def _lifecycle(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    data, inventory, names, metric, gaps, now_s = ctx["data"], ctx["inventory"], ctx["names"], ctx["metric"], ctx["gaps"], ctx["now_s"]
    sections: Dict[str, Dict[str, Any]] = {}
    groups: Dict[Tuple[str, str], int] = {}
    for a in inventory:
        key = (str(a.get("model") or "unknown"), str(a.get("softwareVersion") or "unknown"))
        groups[key] = groups.get(key, 0) + 1
    versions = {v for _, v in groups}
    trains = {".".join(map(str, _version(v)[:2])) or v for v in versions}
    sw_status = "grey" if not inventory else "green" if len(trains) <= 1 else "amber"
    orch_version = (data.get("versions") or {}).get("current") if isinstance(data.get("versions"), dict) else None
    sections["life-inventory"] = {"status": sw_status, "table": [{"model": m, "ecos": v, "appliances": n} for (m, v), n in sorted(groups.items(), key=lambda i: (-i[1], i[0]))],
                                  "metrics": [metric("ecos_versions", len(versions), "versions", "Distinct ECOS builds"),
                                              metric("ecos_trains", len(trains), "trains", "Distinct ECOS trains (major.minor)", sw_status),
                                              metric("orchestrator_version", orch_version, "", "Orchestrator release")],
                                  "notes": ["Rule: more than one ECOS train in use is amber."]}

    # Licences: the Orchestrator's, and each portal-licensed appliance's expiry (epoch ms) where the portal gives one.
    lic = data.get("gms_license") if isinstance(data.get("gms_license"), dict) else None
    days = lic.get("daysToExpiration") if lic else None
    portal = data.get("portal_appliances")
    expiring, lic_rows = {30: 0, 90: 0}, []
    for item in (portal.get("data") or []) if isinstance(portal, dict) else []:
        expiry = item.get("expirationDate") if isinstance(item, dict) else None
        if isinstance(expiry, (int, float)) and item.get("applianceId") in names:
            left = int((expiry / 1000 - now_s) // 86400)
            for limit in expiring:
                expiring[limit] += left <= limit
            if left <= 90:
                lic_rows.append({"appliance": names[item["applianceId"]], "days_left": left})
    portal_dates = any(isinstance(i, dict) and isinstance(i.get("expirationDate"), (int, float)) for i in ((portal or {}).get("data") or [] if isinstance(portal, dict) else []))
    have = isinstance(days, int) or portal_dates  # a list with no expiry dates says nothing about expiry
    worst_days = min([d for d in [days] + [r["days_left"] for r in lic_rows] if isinstance(d, int)], default=None)
    lic_status = "grey" if not have else "green" if worst_days is None else _expiry_status(worst_days)
    sections["life-licences"] = {"status": lic_status, "table": sorted(lic_rows, key=lambda r: r["days_left"]),
                                 "metrics": [metric("license_days_left", days, "days", "Days until the Orchestrator licence expires", _expiry_status(days) if isinstance(days, int) else None),
                                             metric("license_used", lic.get("usedAppliances") if lic else None, "appliances", "Licensed appliances in use"),
                                             metric("licences_expiring_90", expiring[90] if portal_dates else None, "appliances", "Appliance licences expiring within 90 days"),
                                             metric("licences_expiring_30", expiring[30] if portal_dates else None, "appliances", "Appliance licences expiring within 30 days")],
                                 "notes": ["Rule: 30 days or less red, 90 days or less amber."]}

    # Backups: the newest appliance backup each appliance has on the Orchestrator.
    backup_rows, stale, read = [], 0, 0
    for ne, name in names.items():
        history = data.get("backup:" + str(ne))
        if history is None:
            continue
        read += 1
        times = [float(b.get("backupTime")) for b in history if isinstance(b, dict) and isinstance(b.get("backupTime"), (int, float))] if isinstance(history, list) else []
        age = int((now_s - max(times)) // 86400) if times else None
        stale += age is None or age > 30
        backup_rows.append({"appliance": name, "last_backup": datetime.fromtimestamp(max(times), timezone.utc).strftime("%Y-%m-%d") if times else "none", "days_ago": age})
    backup_status = "grey" if not read else "amber" if stale else "green"
    sections["life-backups"] = {"status": backup_status, "table": sorted(backup_rows, key=lambda r: -(r["days_ago"] if r["days_ago"] is not None else 10 ** 6)),
                                "metrics": [metric("backups_stale", stale if read else None, "appliances", "Appliances without a backup in 30 days", backup_status),
                                            metric("backups_read", read, "appliances", "Appliances whose backup history was read")],
                                "notes": ["Rule: an appliance with no backup in the last 30 days is amber."]}

    # Advisories: a dated, hand-kept list (there is no API); Orchestrator entries are checked against its release.
    hits = []
    for advisory in ADVISORIES:
        targets = [("Orchestrator", orch_version)] if advisory["product"] == "orchestrator" else [(names.get(a.get("nePk")), a.get("softwareVersion")) for a in inventory]
        for target, version in targets:
            why = advisory_hit(version, advisory)
            if why:
                hits.append({"target": target, "version": version, "advisory": advisory["id"], "why": why, "cves": ", ".join(advisory["cves"])})
    checked = bool(orch_version) or bool(inventory)
    adv_status = "grey" if not checked else "red" if hits else "green"
    sections["life-advisories"] = {"status": adv_status, "table": hits,
                                   "metrics": [metric("advisory_hits", len(hits) if checked else None, "findings", "Advisory findings", adv_status),
                                               metric("advisories_checked", len(ADVISORIES), "advisories", "Advisories in the list")],
                                   "notes": ["Advisory list as of {}; there is no API for advisories, so check the HPE security portal for newer ones.".format(ADVISORIES_AS_OF)]
                                   + ["{}: {}. {}".format(a["id"], a["title"], a["url"]) for a in ADVISORIES]}
    sections["life-eol"] = {"status": "grey", "metrics": [], "notes": ["No API gives hardware end-of-life dates; not supplied."]}
    sections["life-summary"] = {"status": worst([sw_status, lic_status, backup_status, adv_status]),
                                "metrics": ["advisory_hits", "licences_expiring_90", "license_days_left", "backups_stale", "ecos_trains"]}
    return sections


# --- narrative -----------------------------------------------------------------

def template(metrics: Mapping[str, Any]) -> Dict[str, Any]:
    order = [sid for sid, _ in SECTIONS[metrics["report"]] if sid in metrics["sections"]]  # metrics.json keys are sorted
    return {"report": metrics["report"], "sections": {sid: {"status": metrics["sections"][sid]["status"], "text": "", "cite": [m for m in metrics["sections"][sid]["metrics"] if m in metrics["metrics"]]} for sid in order}}


def validate(metrics: Mapping[str, Any], narrative: Any) -> List[str]:
    problems: List[str] = []
    if not isinstance(narrative, dict) or narrative.get("report") != metrics["report"] or not isinstance(narrative.get("sections"), dict):
        return ["narrative must be {\"report\": \"%s\", \"sections\": {...}}" % metrics["report"]]
    for sid, section in narrative["sections"].items():
        if sid not in metrics["sections"]:
            problems.append("{}: unknown section".format(sid))
            continue
        if not isinstance(section, dict) or set(section) - {"status", "text", "cite"}:
            problems.append("{}: a section has only status, text and cite".format(sid))
            continue
        computed = metrics["sections"][sid]["status"]
        if section.get("status") not in (None, computed):
            problems.append("{}: status {!r} contradicts the computed status {!r}".format(sid, section.get("status"), computed))
        text = section.get("text") or ""
        if not isinstance(text, str) or len(text) > MAX_TEXT:
            problems.append("{}: text must be a string of at most {} characters".format(sid, MAX_TEXT))
            continue
        for mid in _TOKEN.findall(text):
            if mid not in metrics["metrics"]:
                problems.append("{}: {{{{m:{}}}}} is not a metric".format(sid, mid))
        prose = _TOKEN.sub(" ", text)
        plain = _FIXED_TERMS.sub(" ", prose)
        figure = re.search(r"\d", plain) or _NUMBER_WORDS.search(plain)
        if figure:
            problems.append("{}: bare number in the text; cite numbers only as {{{{m:<metric id>}}}}: {!r}".format(sid, plain[max(0, figure.start() - 20):figure.end() + 20]))
        if "{{" in prose or "}}" in prose:
            problems.append("{}: malformed token; use {{{{m:<metric id>}}}}".format(sid))
        lowered = prose.lower()
        for status, words in _STATUS_WORDS.items():
            if status != computed and any(re.search(r"\b" + re.escape(w) + r"\b", lowered) for w in words):
                problems.append("{}: wording implies {} but the computed status is {}".format(sid, status, computed))
    return problems


# --- render ------------------------------------------------------------------

def _fmt(metric: Mapping[str, Any], unit_word: bool = True) -> str:
    """A metric for display; in prose (unit_word False) only % is kept, so "{{m:alarms_critical}} critical alarms" reads right."""
    value = metric.get("value")
    if value is None:
        return "no data"
    if isinstance(value, float):
        value = "{:.2f}".format(value)
    unit = metric.get("unit") or ""
    if unit == "bytes" and isinstance(metric.get("value"), (int, float)):
        return layout.human_bytes(metric["value"])
    if value == 1 and unit.endswith("s"):
        unit = unit[:-1]  # 1 alarm, 1 appliance
    return "{}{}".format(value, unit if unit == "%" else (" " + unit if unit and unit_word else ""))


def options_line(metrics: Mapping[str, Any]) -> str:
    """Report options: what the reader needs to know was chosen, for example "down tunnels: separate (37 excluded)"."""
    o = dict(DEFAULT_OPTIONS, **(metrics.get("options") or {}))
    scope = "all ({} appliances)".format((metrics.get("coverage") or {}).get("appliances")) if o["scope"] == "all" else ", ".join(o["scope"])
    target = "Orchestrator thresholds" if o["target"] == "orchestrator" else "{}%".format(o["target"])
    if metrics["report"] == "incident" and o.get("window"):
        parts = ["window: {} to {} UTC{}".format(_when(o["window"][0]), _when(o["window"][1]), " (alarm {})".format(o["alarm_id"]) if o.get("alarm_id") else ""), "scope: " + scope]
    else:
        parts = ["period: {}{}".format(o["period"], " ({})".format(o.get("month")) if metrics["report"] not in ("noc", "lifecycle") else ""), "scope: " + scope]
    if metrics["report"] in ("availability", "executive"):
        count = o.get("down_tunnels_count")
        parts += ["availability target: " + target,
                  "down tunnels: {}{}".format(o["down_tunnels"], " ({} down all period and {} idle tunnels losing probes excluded)".format(count, o.get("idle_paths_count") or 0)
                                              if o["down_tunnels"] == "separate" and count is not None else "")]
    return "Report options: " + "; ".join(parts)


def _figure(sid: str, sec: Mapping[str, Any]) -> str:
    """The section's one figure: its ranked chart, or for health the appliance x category grid."""
    chart = sec.get("chart") or {}
    if chart.get("points"):
        return layout.bars(str(chart.get("title") or ""), [(p[0], p[1]) for p in chart["points"]], bool(chart.get("zoom")))
    rows = sec.get("table") or []
    if sid == "noc-health" and rows:
        columns = [k for k in rows[0] if k != "appliance"]
        cells = [(r["appliance"], [("no data" if r[c] is None else "{:.0f}%".format(r[c]), band(r[c], (95.0, 99.0)), "") for c in columns]) for r in rows]
        return layout.grid("Share of the last 24 hours each category was healthy", cells, [HEALTH_LABELS.get(c.upper(), c) for c in columns])
    return ""


def render(metrics: Mapping[str, Any], narrative: Optional[Mapping[str, Any]] = None) -> str:
    """One self-contained page in the fixed layout (layout.py): no scripts, no external links, prints on A4."""
    if narrative is not None:
        problems = validate(metrics, narrative)
        if problems:
            raise ValueError("narrative.json is not valid:\n" + "\n".join(problems))
    name = metrics["report"]
    titles = dict(SECTIONS[name])
    texts = (narrative or {}).get("sections") or {}
    order = [sid for sid, _ in SECTIONS[name] if sid in metrics["sections"]]  # metrics.json keys are sorted
    shown = lambda mid: (metrics["metrics"][mid]["label"], _fmt(metrics["metrics"][mid]), metrics["metrics"][mid].get("status"))
    parts, index, appendix = [], [], []  # type: List[str], List[Tuple[str, str, str]], List[str]
    for number, sid in enumerate(order, 1):
        sec = metrics["sections"][sid]
        text = html.escape((texts.get(sid) or {}).get("text") or "")
        text = _TOKEN.sub(lambda m: html.escape(_fmt(metrics["metrics"][m.group(1)], unit_word=False)), text)
        parts.append(layout.section(sid, number, titles[sid], sec["status"], '<p class="summary">{}</p>'.format(text) if text else "", _figure(sid, sec),
                                    layout.stats([shown(mid) for mid in sec.get("metrics", []) if mid in metrics["metrics"]]), sec.get("table") or [],
                                    sec.get("notes", []), appendix, [c["text"] for c in sec.get("causes", [])], [a["text"] for a in sec.get("actions", [])]))
        index.append((sid, "{} {}".format(number, titles[sid]), sec["status"]))
    areas = [sid for sid in order if sid != "data-gaps"]
    head = metrics.get("headline")
    if head:
        overall, verdict, kpis = head["status"], head["text"], head["kpis"]
    else:
        overall = worst([metrics["sections"][sid]["status"] for sid in areas])
        attention = [titles[sid] for sid in areas if metrics["sections"][sid]["status"] in ("amber", "red")]
        verdict = "Attention needed in " + ", ".join(attention) + "." if attention else "No area needs attention." if overall != "grey" else "No data to judge."
        kpis = [m for m in metrics["sections"][areas[0]].get("metrics", []) if m in metrics["metrics"]] if areas else []
    attention_count = sum(metrics["sections"][sid]["status"] in ("amber", "red") for sid in areas)
    now = metrics["period"].get("now_s")
    as_of = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if now else metrics["collected_at"]
    period = {"noc": "last 24 hours and 7 days to " + as_of, "lifecycle": "as of " + as_of,
              "incident": "{} to {} UTC".format(_when(metrics["period"]["from_ms"]), _when(metrics["period"]["to_ms"]))}.get(name, metrics["period"]["month"])
    message = "{} need{} attention".format("1 area" if attention_count == 1 else "{} areas".format(attention_count), "s" if attention_count == 1 else "") if attention_count \
        else "nothing needs attention" if overall != "grey" else "no data"
    coverage = metrics.get("coverage") or {}
    options = options_line(metrics)
    banner = '<div class="banner" data-section-id="stats-store-down">Statistics store down: every statistics call returned HTTP 500, so statistics are missing.</div>' \
        if metrics.get("stats_store_down") else ""
    facts = [("Orchestrator", "{} (release {})".format(metrics["orchestrator"], metrics.get("orchestrator_version"))),
             ("Appliances", "{} in scope".format(coverage.get("appliances"))), ("Period", period), ("Generated", str(metrics["collected_at"]))]
    footer = [("Options", options), ("Coverage", "{} of {} appliances returned data in a per-appliance read.".format(coverage.get("with_data"), coverage.get("appliances"))),
              ("How it is made", "Numbers and statuses are computed by code from Orchestrator {} (release {}), data collected {}; the text only cites them. "
               "Bundle SHA-256 {}. Generated by edgeconnect-mcp {}.".format(metrics["orchestrator"], metrics.get("orchestrator_version"), metrics["collected_at"],
                                                                       metrics.get("bundle_sha256"), __version__)),
              ("Status", "Good, Warning, Critical and No data, each shown with an icon as well as a colour. Times are UTC.")]
    return layout.page("{}, {}: {}".format(TITLES[name], period, message), "EdgeConnect \u00b7 " + TITLES[name], facts, options, overall, verdict, banner, index,
                       layout.tiles([shown(m) for m in kpis]), "\n".join(parts), appendix, footer)


# --- CLI ---------------------------------------------------------------------

def _load(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _dump(path: Path, value: Any) -> None:
    Path(path).write_text(json.dumps(value, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")  # order kept: sections and table columns


def _parse_time(text: Optional[str]) -> datetime:
    if not text:
        raise ValueError("the incident window needs both --from and --to")
    value = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="edgeconnect-mcp report", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("collect", help="read the Orchestrator and write bundle.json")
    p.add_argument("--orchestrator", required=True)
    p.add_argument("--report", choices=REPORTS, required=True)
    p.add_argument("--period", choices=OPTIONS["period"], help="last-month (default; traffic: last-7-days), month-to-date, or for traffic last-7-days or last-24-hours")
    p.add_argument("--month", help="YYYY-MM: an explicit month instead of --period")
    p.add_argument("--scope", default="all", help="all (default), or comma-separated nePks or host names that this Orchestrator has")
    p.add_argument("--target", choices=OPTIONS["target"], default=DEFAULT_OPTIONS["target"], help="availability target: the Orchestrator's thresholds (default) or a fixed %%")
    p.add_argument("--down-tunnels", choices=OPTIONS["down_tunnels"], default=DEFAULT_OPTIONS["down_tunnels"],
                   help="tunnels down the whole period: include them in the figures (default) or list them separately")
    p.add_argument("--top", type=int, help="capacity: only the N busiest WAN links get an hourly P95 read (default: every link)")
    p.add_argument("--from", dest="window_from", help="incident: window start, ISO time (UTC unless it says otherwise), e.g. 2026-10-21T14:00")
    p.add_argument("--to", dest="window_to", help="incident: window end, ISO time")
    p.add_argument("--alarm-id", help="incident: build the window around this alarm instead of --from/--to")
    p.add_argument("--history", type=Path, default=HISTORY_ROOT, help="the alarm archive (default ~/.edgeconnect-mcp/history)")
    p.add_argument("--out", type=Path, default=Path("."), help="folder for bundle.json")
    p.add_argument("--dotenv", default=os.environ.get("EDGECONNECT_DOTENV"), help="settings file (default: $EDGECONNECT_DOTENV, else ~/.edgeconnect-mcp/.env, else ./.env)")
    st = sub.add_parser("store", help="keep the Orchestrator's last 7 days of alarms in the local archive (run it daily from cron or launchd)")
    st.add_argument("--orchestrator", required=True)
    st.add_argument("--history", type=Path, default=HISTORY_ROOT)
    st.add_argument("--dotenv", default=os.environ.get("EDGECONNECT_DOTENV"))
    for name, help_text in (("compute", "bundle.json -> metrics.json"), ("template", "metrics.json -> narrative skeleton")):
        q = sub.add_parser(name, help=help_text)
        q.add_argument("input", type=Path)
    q = sub.add_parser("validate", help="check narrative.json against metrics.json")
    q.add_argument("metrics", type=Path)
    q.add_argument("narrative", type=Path)
    q = sub.add_parser("render", help="metrics.json [+ narrative.json] -> report.html")
    q.add_argument("metrics", type=Path)
    q.add_argument("narrative", type=Path, nargs="?")
    q.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ("collect", "store"):
            dotenv = args.dotenv or next((str(path) for path in (HOME_DOTENV, Path(".env")) if path.is_file()), None)
            server = Server.from_dotenv(dotenv)
            server.log = lambda line: None
        if args.command == "store":
            c = Collector(server, args.orchestrator)
            nepks = [a["nePk"] for a in c.call("appliances", "/appliance") or [] if a.get("nePk")]
            summary = pull(c.pager(), History(args.history, c.orchestrator), nepks, c.read_posts, int(time.time() * 1000))
            for kind, item in summary.items():
                print("{} {}: {} read, {} new{}{}".format(c.orchestrator, kind, item["read"], item["new"],
                                                          "; {} windows not read (not covered, retried next run)".format(len(item["failed"])) if item["failed"] else "",
                                                          "; " + "; ".join(item["notes"]) if item["notes"] else ""))
            return 1 if any(item["failed"] for item in summary.values()) else 0
        if args.command == "collect":
            scope = None if args.scope.strip().lower() == "all" else [a.strip() for a in args.scope.split(",") if a.strip()]
            if args.report != "incident" and (args.window_from or args.window_to or args.alarm_id):
                raise ValueError("--from, --to and --alarm-id are only for --report incident")
            if args.alarm_id and (args.window_from or args.window_to):
                raise ValueError("give either --alarm-id or --from and --to, not both")
            window = (_parse_time(args.window_from), _parse_time(args.window_to)) if args.window_from or args.window_to else None
            bundle = collect(server, args.orchestrator, args.report, args.month, scope, top=args.top, period=args.period, target=args.target, down_tunnels=args.down_tunnels,
                             window=window, alarm_id=args.alarm_id, history_root=args.history)
            bundle["sha256"] = hashlib.sha256(json.dumps(bundle, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
            args.out.mkdir(parents=True, exist_ok=True)
            _dump(args.out / "bundle.json", bundle)
            failed = sum(1 for c in bundle["calls"] if c["outcome"] in ("error", "skipped"))
            print("{}: {} calls, {} without data; wrote {}".format(args.orchestrator, len(bundle["calls"]), failed, args.out / "bundle.json"))
        elif args.command == "compute":
            out = args.input.with_name("metrics.json")
            _dump(out, compute(_load(args.input)))
            print("wrote {}".format(out))
        elif args.command == "template":
            print(json.dumps(template(_load(args.input)), indent=1))
        elif args.command == "validate":
            problems = validate(_load(args.metrics), _load(args.narrative))
            for problem in problems:
                print(problem)
            if problems:
                return 1
            print("narrative is valid")
        elif args.command == "render":
            args.out.write_text(render(_load(args.metrics), _load(args.narrative) if args.narrative else None), encoding="utf-8")
            print("wrote {}".format(args.out))
    except (ValueError, KeyError, OSError, EdgeConnectError, ToolError) as exc:
        print("edgeconnect-mcp report: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
