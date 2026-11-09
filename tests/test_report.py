import json
import os
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from edgeconnect_mcp import layout, report
from edgeconnect_mcp.history import History
from edgeconnect_mcp.config import Config
from edgeconnect_mcp.server import Orchestrator, Server

PATHS = ["/gms/versions", "/appliance", "/stats/config/availabilityThreshold", "/gms/stats/retention", "/stats/aggregate/availability/appliance",
         "/stats/aggregate/availability/tunnel", "/health/alarmPeriodSummary", "/alarm/summary", "/gmsLicense", "/license/portal/summary",
         "/alarm/count/appliance", "/gms/stats/nonStatsTable/retention", "/maintenanceMode", "/tunnels2/physical", "/tunnels2/bonded",
         "/stats/timeseries/interfaceOverlay", "/stats/timeseries/interface", "/license/portal/appliance", "/appliance/backup",
         "/health/healthThresholdConfig", "/stats/aggregate/tunnel", "/action", "/stats/timeseries/availability/appliance", "/alarm/correlatedAlarms",
         "/stats/aggregate/availability/interface", "/gms/overlays/config", "/stats/aggregate/application2", "/stats/aggregate/boost", "/stats/aggregate/dscp",
         "/stats/timeseries/tunnel", "/stats/timeseries/appliance", "/stats/timeseries/shaper", "/stats/aggregate/flow", "/stats/aggregate/securityPolicy", "/zones"]
POSTS = ["/alarm/appliance", "/health", "/stats/aggregate/interface"]
SPEC = {"swagger": "2.0", "basePath": "/gms/rest", "paths": dict({p: {"get": {"summary": p}} for p in PATHS}, **{p: {"post": {"summary": p}} for p in POSTS})}
APPLIANCES = [{"nePk": "1.NE", "hostName": "branch-a", "state": 1, "model": "EC-V", "softwareVersion": "9.6.2.1_1", "serial": "SN-0001"},
              {"nePk": "2.NE", "hostName": "branch-b<script>", "state": 2, "model": "EC-XS", "softwareVersion": "9.7.1.0_1", "serial": "SN-0002"}]


class RoutedClient:
    """Answers each path from a table, like an Orchestrator would."""

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs.get("query"), kwargs.get("json_body")))
        answer = self.answers.get(path, [])
        if isinstance(answer, Exception):
            raise answer
        key = (kwargs.get("query") or {}).get("nePk") or (kwargs.get("query") or {}).get("applianceId")
        if isinstance(answer, dict) and key in answer and path != "/gmsLicense":
            answer = answer[key]
        return json.dumps(answer).encode()

    def _url(self, path, query):
        return "https://orch.example/gms/rest" + path


def bundle(**data):
    base = {"versions": {"current": "9.7.1.1"}, "appliances": APPLIANCES, "availability_threshold": {"reachability": {"goodLimit": 99.0, "okLimit": 99.9},
            "overlayAvailability": {"goodLimit": 99.0, "okLimit": 99.9}, "underlayAvailability": {"goodLimit": 99.0, "okLimit": 99.9}},
            "reach:1.NE": [{"samplecount": 1000, "appliancereachability": 995}], "reach:2.NE": [{"samplecount": 1000, "appliancereachability": 1000}],
            "overlay:1.NE": {"1": [{"count": 1000, "tunnel_state": 600, "blackout": 600, "brownout": 1200}]}, "underlay:1.NE": {"0": [{"count": 1000, "tunnel_state": 0, "blackout": 0, "brownout": 0}]},
            "alarm_period:1.NE": {"alarmCountsInPeriod": {"MAJOR": 2, "WARNING": 5}}}
    base.update(data)
    calls = [{"id": k, "method": "GET", "path": "/stats/aggregate/availability/appliance" if k.startswith("reach") else "/appliance", "outcome": "ok"} for k in base]
    return {"report": "availability", "orchestrator": "lab", "period": {"month": "2026-10", "from_ms": 0, "to_ms": 1}, "collected_at": "2026-10-23T00:00:00+00:00",
            "calls": calls, "data": base, "sha256": "abc"}


class ComputeTests(unittest.TestCase):
    def test_reachability_is_reachable_minutes_over_samples_weighted_across_the_fleet(self):
        m = report.compute(bundle())
        self.assertEqual(m["metrics"]["fleet_reach_pct"]["value"], 99.75)
        self.assertEqual(m["metrics"]["fleet_reach_pct"]["status"], "amber")  # between 99.0 and 99.9
        rows = {r["nePk"]: (r["reachability_pct"], r["status"]) for r in m["sections"]["avail-appliances"]["table"]}
        self.assertEqual(rows, {"1.NE": (99.5, "amber"), "2.NE": (100.0, "green")})

    def test_tunnel_availability_is_downtime_seconds_over_sample_minutes(self):
        # count is minute samples, tunnel_state / blackout / brownout are seconds (seen on 9.7.1 and 10.0); state and blackout overlap.
        m = report.compute(bundle())["metrics"]
        self.assertEqual((m["overlay_avail_pct"]["value"], m["overlay_degraded_pct"]["value"], m["underlay_avail_pct"]["value"]), (99.0, 2.0, 100.0))

    def test_alarms_use_the_full_list_when_the_read_post_ran_else_period_counts(self):
        m = report.compute(bundle())
        self.assertEqual((m["metrics"]["alarms_major"]["value"], m["metrics"]["alarms_warning"]["value"], m["sections"]["avail-alarms"]["status"]), (2, 5, "amber"))
        listed = [{"applianceId": "1.NE", "severity": "CRITICAL", "description": "Tunnel down"}, {"applianceId": "2.NE", "severity": "MINOR"}]
        m = report.compute(bundle(appliance_alarms=listed))
        self.assertEqual((m["metrics"]["alarms_critical"]["value"], m["metrics"]["alarms_major"]["value"], m["sections"]["avail-alarms"]["status"]), (1, 0, "red"))
        self.assertEqual(m["sections"]["avail-alarms"]["table"], [{"appliance": "branch-a", "severity": "critical", "description": "Tunnel down"},
                                                                  {"appliance": "branch-b<script>", "severity": "minor", "description": ""}])  # every alarm, most severe first

    def test_missing_data_is_grey_never_zero_and_listed_as_a_gap(self):
        m = report.compute(bundle(**{"reach:1.NE": [], "reach:2.NE": [], "availability_threshold": {}}))
        self.assertEqual((m["metrics"]["fleet_reach_pct"]["value"], m["metrics"]["fleet_reach_pct"]["status"]), (None, "grey"))
        gaps = " ".join(m["sections"]["data-gaps"]["notes"])
        self.assertIn("default 99.0 / 99.5", gaps)
        self.assertIn("branch-a: no reachability samples for the month although it is reachable now", gaps)

    def test_all_stats_500_is_one_stats_store_banner(self):
        b = bundle(**{"reach:1.NE": None, "reach:2.NE": None})
        b["calls"] = [{"id": "x", "method": "GET", "path": "/stats/aggregate/availability/appliance", "outcome": "error", "http_status": 500, "error": "HTTP 500"}] * 2
        m = report.compute(b)
        self.assertTrue(m["stats_store_down"])
        self.assertEqual(len([n for n in m["sections"]["data-gaps"]["notes"] if "HTTP 500" in n]), 1)

    def test_executive_statuses(self):
        b = bundle(alarm_summary={"numOfCriticalAlarms": 0, "numOfMajorAlarms": 1, "numOfMinorAlarms": 0, "numOfWarningAlarms": 3}, gms_license={"daysToExpiration": 45, "usedAppliances": 2, "maxAppliances": 10})
        b["report"] = "executive"
        m = report.compute(b)
        self.assertEqual([sid for sid in m["sections"]], [sid for sid, _ in report.SECTIONS["executive"]])
        self.assertEqual({sid: m["sections"][sid]["status"] for sid in ("exec-alarms", "exec-licensing", "exec-software", "exec-fleet", "exec-capacity")},
                         {"exec-alarms": "amber", "exec-licensing": "amber", "exec-software": "amber", "exec-fleet": "red", "exec-capacity": "grey"})

    def test_band_and_month_window(self):
        self.assertEqual([report.band(v, (99.0, 99.5)) for v in (99.5, 99.2, 98.0, None)], ["green", "amber", "red", "grey"])
        self.assertEqual([report.band(v, (1.0, 5.0), higher_is_better=False) for v in (0.5, 3, 9)], ["green", "amber", "red"])
        first, start, end = report.month_window("2026-02", now=datetime(2026, 10, 1, tzinfo=timezone.utc))
        self.assertEqual((first.isoformat(), start, end), ("2026-02-01", 1769904000000, 1772323199000))
        now = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)
        self.assertEqual(report.month_window("2026-10", now=now)[2], int(now.timestamp() * 1000))
        for bad in ("2026-13x", "26-10"):
            with self.assertRaises(ValueError):
                report.month_window(bad)
        with self.assertRaises(ValueError):
            report.month_window("2026-11", now=now)


class NarrativeTests(unittest.TestCase):
    def setUp(self):
        self.metrics = report.compute(bundle())

    def narrative(self, text, status=None, sid="avail-summary"):
        section = {"text": text}
        if status:
            section["status"] = status
        return {"report": "availability", "sections": {sid: section}}

    def test_valid_narrative_passes_and_template_lists_every_section(self):
        self.assertEqual(report.validate(self.metrics, self.narrative("Fleet reachability was {{m:fleet_reach_pct}}, short of the target.", "amber")), [])
        self.assertEqual(list(report.template(self.metrics)["sections"]), [sid for sid, _ in report.SECTIONS["availability"]])

    def test_bare_numbers_unknown_metrics_and_sections_are_rejected(self):
        self.assertIn("bare number", report.validate(self.metrics, self.narrative("Reachability was 99.75 percent."))[0])
        self.assertIn("is not a metric", report.validate(self.metrics, self.narrative("{{m:made_up}}"))[0])
        self.assertIn("unknown section", report.validate(self.metrics, self.narrative("x", sid="nope"))[0])
        self.assertIn("malformed", report.validate(self.metrics, self.narrative("{{m:fleet_reach_pct}"))[0])

    def test_status_contradicting_compute_is_rejected(self):
        self.assertIn("contradicts", report.validate(self.metrics, self.narrative("Fine.", "green"))[0])
        self.assertIn("implies green", report.validate(self.metrics, self.narrative("The network was healthy all month."))[0])
        self.assertIn("implies red", report.validate(self.metrics, self.narrative("There was an outage."))[0])


class RenderTests(unittest.TestCase):
    def test_one_self_contained_page_with_sections_in_order_tokens_filled_and_text_escaped(self):
        metrics = report.compute(bundle())
        page = report.render(metrics, {"report": "availability", "sections": {"avail-summary": {"text": "Reachability {{m:fleet_reach_pct}} <b>x</b>"},
                                                                     "avail-alarms": {"text": "{{m:alarms_major}} major alarms."}}})
        self.assertIn('<p class="summary">2 major alarms.</p>', page)  # prose tokens carry no unit word
        self.assertIn(">2 alarms</b>", page)  # tiles do
        ids = [line.split('data-section-id="')[1].split('"')[0] for line in page.split("<section ")[1:]]
        self.assertEqual(ids, [sid for sid, _ in report.SECTIONS["availability"]])
        self.assertIn("Reachability 99.75% &lt;b&gt;x&lt;/b&gt;", page)
        self.assertNotIn("<script", page)  # the hostile host name is escaped
        self.assertIn("branch-b&lt;script&gt;", page)
        self.assertIn("<svg", page)
        self.assertIn("<title>branch-a: 99.50%</title>", page)
        self.assertIn("@media print", page)
        self.assertIn("Bundle SHA-256 abc", page)
        self.assertNotRegex(page, r"(?i)<(link|img|iframe)\b|src=|https?://")

    def test_render_refuses_an_invalid_narrative(self):
        with self.assertRaises(ValueError):
            report.render(report.compute(bundle()), {"report": "availability", "sections": {"avail-summary": {"text": "99 percent"}}})


class SkillTests(unittest.TestCase):
    def test_report_skill_names_only_tested_operations(self):
        root = Path(__file__).resolve().parent.parent
        tested = set((root / "skills" / "edgeconnect-guide" / "tested-operations.tsv").read_text(encoding="utf-8").splitlines())
        named = re.findall(r"`(GET|POST|PUT|PATCH|DELETE) (/[^`\s?]+)", (root / "skills" / "edgeconnect-report" / "SKILL.md").read_text(encoding="utf-8"))
        self.assertTrue(named)
        self.assertEqual([op for op in named if "\t".join(op) not in tested], [])


class CollectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.spec = Path(self.tmp.name) / "spec.json"
        self.spec.write_text(json.dumps(SPEC))

    def tearDown(self):
        self.tmp.cleanup()

    def server(self, client, get_only):
        orchestrator = Orchestrator("lab", Config(base_url="https://orch.example/gms/rest", api_key="KEY"), False, str(self.spec), client, get_only=get_only)
        return Server({"lab": orchestrator}, default="lab", log=lambda line: None)

    def answers(self):
        return {"/gms/versions": {"current": "9.7.1.1"}, "/appliance": APPLIANCES, "/stats/aggregate/availability/appliance": {"1.NE": [{"samplecount": 10, "appliancereachability": 10}], "2.NE": []},
                "/alarm/appliance": [{"applianceId": "1.NE", "severity": "MAJOR"}], "/gmsLicense": {"licenseKey": "AAAA-BBBB", "daysToExpiration": 400, "serialNumber": "00-11"}}

    def test_read_post_runs_with_writes_off_and_times_use_the_right_units(self):
        client = RoutedClient(self.answers())
        b = report.collect(self.server(client, get_only=False), "lab", "availability", "2026-09")
        posts = [c for c in client.calls if c[0] == "POST"]
        self.assertEqual(posts, [("POST", "/alarm/appliance", {"view": "all", "from": 1788220800000, "to": 1790812799000, "maxAlarms": 10000, "orderBySeverity": True}, {"nePks": ["1.NE", "2.NE"]})])
        reach = [c for c in client.calls if c[1] == "/stats/aggregate/availability/appliance"]
        self.assertEqual(reach[0][2], {"nePk": "1.NE", "date": "2026-09-01", "granularity": "month"})
        self.assertEqual({c["id"]: c["outcome"] for c in b["calls"] if c["id"].startswith("reach:")}, {"reach:1.NE": "ok", "reach:2.NE": "empty"})
        b = report.collect(self.server(client, get_only=False), "lab", "lifecycle", "2026-09")
        self.assertNotIn("AAAA", json.dumps(b))  # licence keys and serials never reach a bundle
        self.assertNotIn("00-11", json.dumps(b))
        self.assertNotIn("SN-000", json.dumps(b))  # GET /appliance names it plain `serial`
        self.assertEqual(b["data"]["gms_license"], {"daysToExpiration": 400})

    def test_get_only_skips_the_read_post_and_falls_back_to_gets(self):
        client = RoutedClient(self.answers())
        b = report.collect(self.server(client, get_only=True), "lab", "availability", "2026-09")
        self.assertFalse([c for c in client.calls if c[0] == "POST"])
        skipped = [c for c in b["calls"] if c["outcome"] == "skipped"]
        self.assertEqual([c["path"] for c in skipped], ["/alarm/appliance"])
        self.assertIn("GET alternatives", skipped[0]["error"])
        self.assertIn("GET /health/alarmPeriodSummary", " ".join(report.compute(b)["sections"]["avail-alarms"]["notes"]))

    def test_errors_are_recorded_with_their_http_status(self):
        from edgeconnect_mcp.errors import EdgeConnectError
        answers = self.answers()
        answers["/stats/aggregate/availability/appliance"] = EdgeConnectError("HTTP 500: There was an internal server error.")
        b = report.collect(self.server(RoutedClient(answers), get_only=True), "lab", "availability", "2026-09")
        errors = [c for c in b["calls"] if c["outcome"] == "error"]
        self.assertEqual({(c["path"], c["http_status"]) for c in errors}, {("/stats/aggregate/availability/appliance", 500)})

    def test_cli_pipeline_writes_metrics_and_html(self):
        folder = Path(self.tmp.name)
        (folder / "bundle.json").write_text(json.dumps(bundle()))
        self.assertEqual(report.main(["compute", str(folder / "bundle.json")]), 0)
        (folder / "narrative.json").write_text(json.dumps({"report": "availability", "sections": {"avail-summary": {"text": "{{m:fleet_reach_pct}}"}}}))
        self.assertEqual(report.main(["validate", str(folder / "metrics.json"), str(folder / "narrative.json")]), 0)
        self.assertEqual(report.main(["render", str(folder / "metrics.json"), str(folder / "narrative.json"), "--out", str(folder / "r.html")]), 0)
        self.assertIn("<!doctype html>", (folder / "r.html").read_text())
        (folder / "narrative.json").write_text(json.dumps({"report": "availability", "sections": {"avail-summary": {"text": "7 sites"}}}))
        self.assertEqual(report.main(["validate", str(folder / "metrics.json"), str(folder / "narrative.json")]), 1)


NOW = 1790000000  # 2026-09-21


def phase2_bundle(report_name, **data):
    b = bundle(**data)
    b["report"] = report_name
    b["period"]["now_s"] = NOW
    return b


class NocTests(unittest.TestCase):
    def test_state_alarms_health_tunnels_and_worst_sites(self):
        health = {"1.NE": [{"status": "HEALTHY", "time": NOW - 3600}, {"status": "CRITICAL", "time": NOW - 7200}, {"blank": True, "status": None, "time": NOW - 60},
                           {"status": "WARNING", "time": NOW - 3 * 86400}],
                  "2.NE": [{"status": "HEALTHY", "time": NOW - 3600}, {"status": "HEALTHY", "time": NOW - 5 * 86400}]}
        tunnels = {"1.NE": {"t1": {"operStatus": "Up - Active", "alias": "a"}, "t2": {"operStatus": "Down", "alias": "b"}}, "2.NE": {"t3": {"operStatus": "Up - Idle", "alias": "c"}}}
        alarms = [{"applianceId": "2.NE", "severity": "CRITICAL", "description": "Tunnel down", "timeOccurredInMills": (NOW - 60) * 1000}, {"applianceId": "1.NE", "severity": "MINOR"}]
        m = report.compute(phase2_bundle("noc", health=health, tunnels_physical=tunnels, tunnels_bonded={}, active_alarms=alarms,
                                         alarm_retention={"historical_appliance_alarm": {"retention": 604800}}))
        v = {k: m["metrics"][k]["value"] for k in ("state_normal", "state_unreachable", "active_critical", "active_minor", "health_good_24h_pct", "health_good_7d_pct", "tunnels_physical_down", "tunnels_physical_total")}
        self.assertEqual(v, {"state_normal": 1, "state_unreachable": 1, "active_critical": 1, "active_minor": 1, "health_good_24h_pct": 66.667, "health_good_7d_pct": 60.0,
                             "tunnels_physical_down": 1, "tunnels_physical_total": 3})
        s = {sid: sec["status"] for sid, sec in m["sections"].items()}
        self.assertEqual((s["noc-appliances"], s["noc-alarms"], s["noc-health"], s["noc-tunnels"], s["noc-summary"]), ("red", "red", "red", "red", "red"))
        self.assertIn("keeps 7 days of alarm history", " ".join(m["sections"]["noc-alarms"]["notes"]))
        worst = m["sections"]["noc-worst"]["table"]
        self.assertEqual([(r["appliance"], r["score"]) for r in worst], [("branch-b<script>", 110), ("branch-a", 3)])  # not normal + critical; tunnel down + unhealthy hour

    def test_get_only_alarm_counts_and_no_health(self):
        m = report.compute(phase2_bundle("noc", alarm_summary={"numOfCriticalAlarms": 0, "numOfMajorAlarms": 2, "numOfMinorAlarms": 1, "numOfWarningAlarms": 0},
                                         alarm_counts=[{"applianceId": "1.NE", "numOfMajorAlarms": 2}]))
        self.assertEqual((m["sections"]["noc-alarms"]["status"], m["metrics"]["active_major"]["value"]), ("amber", 2))
        self.assertEqual(m["sections"]["noc-alarms"]["table"][0]["major"], 2)
        self.assertEqual((m["sections"]["noc-health"]["status"], m["metrics"]["health_good_24h_pct"]["value"]), ("grey", None))
        self.assertIn("POST /health did not run", " ".join(m["sections"]["data-gaps"]["notes"]))


class CapacityTests(unittest.TestCase):
    TOTALS = [{"nePk": "1.NE", "INTERFACE": "wan0", "TRAFFIC_TYPE": 4, "SUM_TX_BYTES": 1080000000000, "SUM_RX_BYTES": 0, "AVG_MAX_BW_TX": 100000, "AVG_MAX_BW_RX": 100000,
               "MIN_TIMESTAMP": 0, "MAX_TIMESTAMP": 0},
              {"nePk": "1.NE", "INTERFACE": "blan0", "TRAFFIC_TYPE": 4, "SUM_TX_BYTES": 9e12, "AVG_MAX_BW_TX": 1000},
              {"nePk": "2.NE", "INTERFACE": "wan1.20", "TRAFFIC_TYPE": 4, "SUM_TX_BYTES": 0, "SUM_RX_BYTES": 0, "AVG_MAX_BW_TX": 50000, "AVG_MAX_BW_RX": 50000, "MIN_TIMESTAMP": 0, "MAX_TIMESTAMP": 0}]

    def test_wan_links_average_utilisation_and_ranking(self):
        links = report.wan_links({"interface_totals": self.TOTALS}, {"1.NE": "a", "2.NE": "b"})
        self.assertEqual([(l["nePk"], l["interface"], l["avg_tx_pct"]) for l in links], [("1.NE", "wan0", 100.0), ("2.NE", "wan1.20", 0.0)])  # LAN ignored
        overlay = [{"INTERFACE": "wan0", "ISWANSIDE": True, "TX_BYTES": 540000000, "RX_BYTES": 0, "MAX_BW_TX": 1000, "MAX_BW_RX": 1000, "LABELNAME": "INET"},
                   {"INTERFACE": "wan0", "ISWANSIDE": True, "TX_BYTES": 540000000, "RX_BYTES": 0, "MAX_BW_TX": 1000, "MAX_BW_RX": 1000, "LABELNAME": "INET"},
                   {"INTERFACE": "lan0", "ISWANSIDE": False, "TX_BYTES": 1e12}]
        links = report.wan_links({"wan_side:1.NE": overlay}, ["1.NE"])
        self.assertEqual([(l["interface"], l["label"], l["avg_tx_pct"]) for l in links], [("wan0", "INET", 10.0)])  # 1.08 GB over a day on 1 Mbps

    def test_p95_of_hourly_utilisation_flags_links_at_80_percent(self):
        hourly = [{"tx_bytes": 45000000000 * pct / 100, "rx_bytes": 0, "max_bw_tx": 100000, "max_bw_rx": 100000} for pct in range(1, 101)]  # 100 hours, 1..100%
        m = report.compute(phase2_bundle("capacity", interface_totals=self.TOTALS, **{"hourly:1.NE:wan0": hourly}))
        rows = {(r["appliance"], r["interface"]): r for r in m["sections"]["cap-links"]["table"]}
        self.assertEqual((rows[("branch-a", "wan0")]["p95_out_pct"], rows[("branch-a", "wan0")]["status"]), (95.0, "red"))
        self.assertEqual(rows[("branch-b<script>", "wan1.20")]["status"], "grey")  # no hourly data: not in the top N
        self.assertEqual({k: m["metrics"][k]["value"] for k in ("links_flagged", "worst_p95_pct", "links_measured", "wan_links")},
                         {"links_flagged": 1, "worst_p95_pct": 95.0, "links_measured": 1, "wan_links": 2})
        self.assertEqual(report._p95([5.0]), 5.0)
        self.assertIsNone(report._p95([]))


class LifecycleTests(unittest.TestCase):
    def test_advisory_versions(self):
        advisory = {"fixed_in": {"9.6": "9.6.1", "9.5": "9.5.6", "9.4": "9.4.8"}}
        cases = {"9.6.0.40000": "below 9.6.1", "9.6.1.1": None, "9.5.5_1": "below 9.5.6", "9.4.8.0": None, "9.3.7.0_96892": "no fix in the 9.3 train; upgrade",
                 "9.7.1.42046": None, "10.0.0.40625": None, "": None}
        self.assertEqual({v: report.advisory_hit(v, advisory) for v in cases}, cases)

    def test_licences_backups_advisories_and_eol(self):
        portal = {"data": [{"applianceId": "1.NE", "expirationDate": (NOW + 20 * 86400) * 1000}, {"applianceId": "2.NE", "expirationDate": (NOW + 60 * 86400) * 1000}]}
        m = report.compute(phase2_bundle("lifecycle", versions={"current": "9.6.0.1"}, gms_license={"daysToExpiration": 400, "usedAppliances": 2}, portal_appliances=portal,
                                         **{"backup:1.NE": [{"backupTime": NOW - 40 * 86400}, {"backupTime": NOW - 2 * 86400}], "backup:2.NE": []}))
        v = {k: m["metrics"][k]["value"] for k in ("licences_expiring_30", "licences_expiring_90", "backups_stale", "advisory_hits", "ecos_trains")}
        self.assertEqual(v, {"licences_expiring_30": 1, "licences_expiring_90": 2, "backups_stale": 1, "advisory_hits": 1, "ecos_trains": 2})
        s = {sid: sec["status"] for sid, sec in m["sections"].items()}
        self.assertEqual((s["life-licences"], s["life-backups"], s["life-advisories"], s["life-eol"], s["life-summary"]), ("red", "amber", "red", "grey", "red"))
        self.assertEqual(m["sections"]["life-advisories"]["table"][0]["target"], "Orchestrator")
        page = report.render(m)
        self.assertIn("<title>Lifecycle, licence and vulnerability report, as of 2026-09-21", page)
        self.assertIn("2 of 2 appliances returned data", page)
        self.assertIn("as of", " ".join(m["sections"]["life-advisories"]["notes"]))


class Phase2CollectTests(CollectTests):
    def answers(self):
        a = super().answers()
        a.update({"/stats/aggregate/interface": CapacityTests.TOTALS, "/stats/timeseries/interfaceOverlay": {"1.NE": [{"INTERFACE": "wan0", "ISWANSIDE": True, "TX_BYTES": 1, "MAX_BW_TX": 10}]}})
        return a

    def test_capacity_get_only_finds_wan_links_from_overlay_stats_then_reads_hourly(self):
        client = RoutedClient(self.answers())
        report.collect(self.server(client, get_only=True), "lab", "capacity", "2026-09", now=datetime(2026, 9, 21, tzinfo=timezone.utc))
        paths = [(c[0], c[1], (c[2] or {}).get("interfaceName"), (c[2] or {}).get("granularity")) for c in client.calls if "/interface" in c[1]]  # links, not apps or QoS
        self.assertEqual(paths, [("GET", "/stats/timeseries/interfaceOverlay", None, "day"), ("GET", "/stats/timeseries/interfaceOverlay", None, "day"),
                                 ("GET", "/stats/timeseries/interface", "wan0", "hour")])
        hourly = [c for c in client.calls if c[1] == "/stats/timeseries/interface"][0][2]
        self.assertEqual(hourly["endTime"] - hourly["startTime"], 14 * 86400)  # hourly retention caps the P95 window

    def test_capacity_uses_the_totals_post_and_the_top_n(self):
        client = RoutedClient(self.answers())
        report.collect(self.server(client, get_only=False), "lab", "capacity", "2026-09", top=1, now=datetime(2026, 9, 21, tzinfo=timezone.utc))
        self.assertEqual([(c[0], c[1], (c[2] or {}).get("interfaceName")) for c in client.calls if "/interface" in c[1]],
                         [("POST", "/stats/aggregate/interface", None), ("POST", "/stats/aggregate/interface", None), ("GET", "/stats/timeseries/interface", "wan0")])  # period, previous period

    def test_noc_and_lifecycle_requests(self):
        client = RoutedClient(self.answers())
        report.collect(self.server(client, get_only=False), "lab", "executive", "2026-09", now=datetime(2026, 9, 21, tzinfo=timezone.utc))
        health = [c for c in client.calls if c[1] == "/health"][0]
        self.assertEqual((health[3]["to"] - health[3]["from"], health[3]["nePks"]), (7 * 86400, ["1.NE", "2.NE"]))  # seconds
        self.assertEqual([c[2]["runningConfig"] for c in client.calls if c[1] == "/appliance/backup"], ["false", "false"])
        self.assertEqual([c[2] for c in client.calls if c[1] == "/tunnels2/bonded"], [{"operStatus": "true", "srcNePk": "true", "alias": "true", "tag": "true"}])


class PresentationTests(unittest.TestCase):
    def executive(self, down=1, total=12, **data):
        inventory = [{"nePk": "{}.NE".format(i), "hostName": "site-{}".format(i), "state": 2 if i < down else 1, "softwareVersion": "9.7.1.0_1"} for i in range(total)]
        b = phase2_bundle("executive", appliances=inventory, **data)
        return report.compute(b)

    def test_fleet_is_amber_with_any_appliance_down_and_red_above_ten_percent(self):
        self.assertEqual([self.executive(down=d)["sections"]["exec-fleet"]["status"] for d in (0, 1, 2)], ["green", "amber", "red"])  # 0, 8.3%, 16.7% down
        self.assertNotIn("table", self.executive()["sections"]["exec-fleet"])  # the appliance list lives in the availability and NOC reports

    def test_executive_verdict_and_kpi_strip(self):
        m = self.executive(down=1, alarm_summary={"numOfCriticalAlarms": 2, "numOfMajorAlarms": 0, "numOfMinorAlarms": 0, "numOfWarningAlarms": 0})
        self.assertEqual(m["headline"]["status"], "red")
        self.assertTrue(m["headline"]["text"].startswith("Overall: Critical. Attention needed in Fleet"))  # the layout's status words
        self.assertIn("Active alarms", m["headline"]["text"])
        self.assertEqual(m["headline"]["kpis"], list(report.EXEC_KPIS))
        page = report.render(m)
        self.assertLess(page.index('data-section-id="verdict"'), page.index('data-section-id="exec-fleet"'))
        self.assertIn('data-section-id="kpi-strip"', page)
        self.assertIsNone(report.compute(bundle())["headline"])  # only the summary reports have one

    def test_availability_summary_follows_availability_not_alarms(self):
        m = report.compute(bundle(appliance_alarms=[{"applianceId": "1.NE", "severity": "CRITICAL"}]))
        self.assertEqual((m["sections"]["avail-alarms"]["status"], m["sections"]["avail-summary"]["status"]), ("red", "amber"))

    def test_tunnels_down_all_period_are_counted_or_listed_apart(self):
        overlay = {"1": [{"count": 1000, "tunnel_state": 0, "blackout": 0, "brownout": 0},
                         {"count": 1000, "tunnel_state": 60000, "blackout": 60000, "brownout": 0, "label": "INET", "serviceName": "SSE", "tunnelcount": 2}]}
        b = bundle(**{"overlay:1.NE": overlay})
        b["options"] = {"down_tunnels": "include"}
        m = report.compute(b)
        self.assertEqual((m["metrics"]["overlay_avail_pct"]["value"], m["metrics"]["tunnel_groups_down_all_period"]["value"]), (50.0, 2))
        self.assertIn("counted in the figures above", " ".join(m["sections"]["avail-tunnels"]["notes"]))
        b = bundle(**{"overlay:1.NE": overlay})
        b["options"] = {"down_tunnels": "separate"}
        m = report.compute(b)
        self.assertEqual((m["metrics"]["overlay_avail_pct"]["value"], m["metrics"]["tunnel_groups_down_all_period"]["value"]), (100.0, 2))
        self.assertEqual(m["sections"]["avail-tunnels"]["apart"]["rows"], [{"appliance": "branch-a", "kind": "Overlay", "label": "INET", "service": "SSE", "tunnels": 2}])
        self.assertIn("down tunnels: separate (2 down all period and 0 idle tunnels losing probes excluded)", report.render(m))

    def test_singular_units_status_coloured_bars_and_labelled_axis(self):
        self.assertEqual(report._fmt({"value": 1, "unit": "alarms"}), "1 alarm")
        self.assertEqual(report._fmt({"value": 2, "unit": "alarms"}), "2 alarms")
        svg = layout.bars("t", [("a", 95.0), ("b", 100.0)], True)
        self.assertEqual(svg.count('class="bar"'), 2)  # one hue; the status is in the table, with its icon
        self.assertIn("Scale 90% to 100% (zoomed)", svg)
        self.assertIn("Scale 0% to 100%", layout.bars("t", [("a", 5.0)], False))


THRESHOLDS = {"packetLoss": {"goodLimit": 0.1, "okLimit": 1.0}, "latency": {"goodLimit": 20.0, "okLimit": 50.0},
              "jitter": {"goodLimit": 10.0, "okLimit": 20.0}, "mos": {"goodLimit": 1.0, "okLimit": 4.0}}


class ReviewFixTests(unittest.TestCase):
    def test_serials_never_reach_a_bundle(self):
        self.assertEqual(report._scrub({"serial": "X", "serialNumber": "Y", "hostName": "a"}), {"hostName": "a"})

    def test_get_only_alarm_severities_count_only_the_appliances_in_scope(self):
        m = report.compute(phase2_bundle("noc", alarm_summary={"numOfCriticalAlarms": 9, "numOfMajorAlarms": 9, "numOfMinorAlarms": 9, "numOfWarningAlarms": 9},
                                         alarm_counts=[{"applianceId": "1.NE", "numOfCriticalAlarms": 1}, {"applianceId": "99.NE", "numOfCriticalAlarms": 5}]))
        self.assertEqual((m["metrics"]["active_critical"]["value"], m["metrics"]["active_major"]["value"]), (1, 0))

    def test_stats_store_down_ignores_skipped_and_refused_posts(self):
        b = bundle(**{"reach:1.NE": None, "reach:2.NE": None})
        b["calls"] = [{"id": "r", "method": "GET", "path": "/stats/aggregate/availability/appliance", "outcome": "error", "http_status": 500, "error": "HTTP 500"},
                      {"id": "i", "method": "POST", "path": "/stats/aggregate/interface", "outcome": "skipped", "error": "get_only"},
                      {"id": "j", "method": "POST", "path": "/stats/aggregate/interface", "outcome": "error", "http_status": 403, "error": "HTTP 403"}]
        self.assertTrue(report.compute(b)["stats_store_down"])

    def test_licence_tile_and_section_use_one_rule(self):
        for days, expected in ((30, "red"), (90, "amber"), (91, "green")):
            m = report.compute(phase2_bundle("lifecycle", gms_license={"daysToExpiration": days}))
            self.assertEqual((m["metrics"]["license_days_left"]["status"], m["sections"]["life-licences"]["status"]), (expected, expected), days)

    def test_alarm_list_at_the_cap_is_a_gap(self):
        m = report.compute(phase2_bundle("noc", active_alarms=[{"applianceId": "1.NE", "severity": "MINOR"}] * report.MAX_ALARMS))
        self.assertIn("10000-alarm cap", " ".join(m["sections"]["data-gaps"]["notes"]))
        m = report.compute(bundle(appliance_alarms=[{"applianceId": "1.NE", "severity": "MINOR"}] * report.MAX_ALARMS))
        self.assertIn("10000-alarm cap", " ".join(m["sections"]["data-gaps"]["notes"]))

    def test_validator_allows_severity_names_and_fixed_terms(self):
        metrics = report.compute(bundle())  # avail-summary is amber
        ok = {"report": "availability", "sections": {"avail-summary": {"text": "A critical alarm and a warning alarm were raised; P95 over the last 24 hours stayed low on ECOS 9.6.2 and the last 7 days."}}}
        self.assertEqual(report.validate(metrics, ok), [])
        bad = {"report": "availability", "sections": {"avail-summary": {"text": "Reachability was 99 percent; there was an outage."}}}
        problems = " ".join(report.validate(metrics, bad))
        self.assertIn("bare number", problems)
        self.assertIn("implies red", problems)

    def test_path_quality_grades_each_tunnel_against_the_health_thresholds(self):
        paths = {"bondedTunnel_1": {"1.NE": {"alias": "to_hub_DEFAULT", "overlayid": "1", "SUM_POST_LOSS": 200, "SUM_WRX_PKTS": 99800, "AVG_LATENCY_AVG": 30, "AVG_JITTER": 2, "mos": 430}},
                 "tunnel_2": {"1.NE": {"alias": "to_hub_INET", "overlayid": "0", "SUM_POST_LOSS": 0, "SUM_WRX_PKTS": 100000, "AVG_LATENCY_AVG": 5, "AVG_JITTER": 1, "mos": 440}},
                 "tunnel_3": {"1.NE": {"alias": "to_hub_LTE", "overlayid": "0", "SUM_POST_LOSS": 5000, "SUM_WRX_PKTS": 95000, "AVG_LATENCY_AVG": 90, "AVG_JITTER": 30, "mos": 50}},
                 "bondedTunnel_4": {"1.NE": {"alias": "to_hub_GUEST", "overlayid": "2", "SUM_POST_LOSS": 3433, "SUM_WRX_PKTS": 0, "AVG_LATENCY_AVG": 5, "AVG_JITTER": 1, "mos": 440}}}
        b = bundle(health_threshold=THRESHOLDS, **{"paths:1.NE": paths})
        b["options"] = {"down_tunnels": "include"}
        m = report.compute(b)
        rows = {r["tunnel"]: (r["loss_pct"], r["latency_ms"], r["mos"], r["status"]) for r in m["sections"]["avail-paths"]["table"]}
        self.assertEqual(rows, {"to_hub_DEFAULT": (0.2, 30.0, 4.3, "amber"), "to_hub_INET": (0.0, 5.0, 4.4, "green"), "to_hub_LTE": (5.0, 90.0, 0.5, "red"),
                                "to_hub_GUEST": (None, 5.0, 4.4, "red")})  # no traffic but probes lost: a broken path, red, not "no data"
        self.assertEqual([r["tunnel"] for r in m["sections"]["avail-paths"]["table"]][0], "to_hub_LTE")  # worst first
        self.assertEqual({k: m["metrics"][k]["value"] for k in ("paths_measured", "paths_red", "paths_amber")}, {"paths_measured": 4, "paths_red": 2, "paths_amber": 1})
        self.assertEqual(m["sections"]["avail-paths"]["status"], "red")
        self.assertEqual(m["metrics"]["paths_idle_probe_loss"]["value"], 1)
        b = bundle(health_threshold=THRESHOLDS, **{"paths:1.NE": paths})
        b["options"] = {"down_tunnels": "separate"}
        m = report.compute(b)  # separate: listed apart and left out of the status
        self.assertNotIn("to_hub_GUEST", [r["tunnel"] for r in m["sections"]["avail-paths"]["table"]])
        self.assertIn("listed at the end of this section", " ".join(m["sections"]["avail-paths"]["notes"]))
        self.assertIn("1 idle tunnels losing probes excluded", report.render(m))
        silent = {"tunnel_9": {"1.NE": {"alias": "to_hub_SPARE", "overlayid": "0", "SUM_POST_LOSS": 0, "SUM_WRX_PKTS": 0, "AVG_LATENCY_AVG": 5, "AVG_JITTER": 1, "mos": 440}}}
        row = report.compute(bundle(health_threshold=THRESHOLDS, **{"paths:1.NE": silent}))["sections"]["avail-paths"]["table"][0]
        self.assertEqual((row["loss_pct"], row.get("note", ""), row["status"]), (None, "", "grey"))  # no packets and no probe loss: no data, not good
        m = report.compute(bundle(**{"paths:1.NE": paths}))  # no thresholds read: defaults, listed as a gap
        self.assertIn("healthThresholdConfig", " ".join(m["sections"]["data-gaps"]["notes"]))

    def test_banner_names_statistics_not_only_availability(self):
        m = report.compute(phase2_bundle("capacity"))
        m["stats_store_down"] = True
        self.assertIn("so statistics are missing", report.render(m))


class ReviewCollectTests(CollectTests):
    def answers(self):
        a = super().answers()
        a.update({"/stats/aggregate/interface": CapacityTests.TOTALS,
                  "/gms/stats/retention": {"interface": [{"granularity": "HOUR", "retention": 7 * 86400}, {"granularity": "HOUR", "retention": 3 * 86400}, {"granularity": "DAY", "retention": 93 * 86400}]}})
        return a

    def test_capacity_past_month_uses_daily_data_and_current_month_uses_hourly_retention(self):
        client = RoutedClient(self.answers())
        b = report.collect(self.server(client, get_only=False), "lab", "capacity", "2026-09", now=datetime(2026, 10, 23, tzinfo=timezone.utc))
        series = [c[2] for c in client.calls if c[1] == "/stats/timeseries/interface"]
        self.assertEqual({(q["granularity"], q["startTime"], q["endTime"]) for q in series}, {("day", 1788220800, 1790812799)})
        self.assertEqual(b["data"]["capacity_basis"]["granularity"], "day")
        client = RoutedClient(self.answers())
        report.collect(self.server(client, get_only=False), "lab", "capacity", "2026-10", now=datetime(2026, 10, 23, tzinfo=timezone.utc))
        q = [c[2] for c in client.calls if c[1] == "/stats/timeseries/interface"][0]
        self.assertEqual((q["granularity"], q["endTime"] - q["startTime"]), ("hour", 7 * 86400))  # the longer HOUR retention read from the Orchestrator

    def test_daily_basis_is_computed_per_day_and_labelled(self):
        daily = [{"tx_bytes": 1080000000000 * 0.5, "rx_bytes": 0, "max_bw_tx": 100000, "max_bw_rx": 100000}]  # half of 100 Mbps for a day
        m = report.compute(phase2_bundle("capacity", interface_totals=CapacityTests.TOTALS, capacity_basis={"granularity": "day", "retention_known": True},
                                         **{"hourly:1.NE:wan0": daily}))
        row = [r for r in m["sections"]["cap-links"]["table"] if r["interface"] == "wan0"][0]
        self.assertEqual(row["p95_out_pct"], 50.0)
        self.assertIn("daily averages", " ".join(m["sections"]["cap-links"]["notes"]))

    def test_nickname_case_and_dotenv_environment(self):
        client = RoutedClient(self.answers())
        report.collect(self.server(client, get_only=False), "Lab", "availability", "2026-09", now=datetime(2026, 10, 23, tzinfo=timezone.utc))
        self.assertTrue([c for c in client.calls if c[0] == "POST"])  # not skipped as get_only
        from unittest import mock
        with mock.patch.dict("os.environ", {"EDGECONNECT_DOTENV": "/x/ec.env"}), mock.patch.object(report.Server, "from_dotenv", side_effect=OSError("stop")) as loader, \
                mock.patch("sys.stderr"):
            self.assertEqual(report.main(["collect", "--orchestrator", "lab", "--report", "noc"]), 1)
        loader.assert_called_once_with("/x/ec.env")


class OptionTests(CollectTests):
    def test_choices_outside_the_list_are_rejected(self):
        from unittest import mock
        for bad in (["--target", "98"], ["--down-tunnels", "drop"], ["--period", "last-week"]):
            with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
                report.main(["collect", "--orchestrator", "lab", "--report", "availability"] + bad)
        with self.assertRaises(ValueError):
            report.collect(self.server(RoutedClient(self.answers()), get_only=True), "lab", "availability", target="95")
        with self.assertRaisesRegex(ValueError, "does not have: nowhere"):
            report.collect(self.server(RoutedClient(self.answers()), get_only=True), "lab", "availability", appliances=["branch-a", "nowhere"])

    def test_period_defaults_to_last_month_and_options_are_stored_and_printed(self):
        now = datetime(2026, 1, 10, tzinfo=timezone.utc)
        self.assertEqual((report.resolve_month("last-month", now), report.resolve_month("month-to-date", now)), ("2025-12", "2026-01"))
        b = report.collect(self.server(RoutedClient(self.answers()), get_only=True), "lab", "availability", appliances=["branch-a"], now=now, target="99.9")
        self.assertEqual(b["options"], {"period": "last-month", "month": "2025-12", "scope": ["branch-a"], "target": "99.9", "down_tunnels": "separate"})
        page = report.render(report.compute(b))
        self.assertIn("Report options: period: last-month (2025-12); scope: branch-a; availability target: 99.9%; down tunnels: separate", page)
        self.assertEqual(page.count("Report options:"), 2)  # under the title and in the footer

    def test_a_fixed_target_is_met_or_missed(self):
        b = bundle()  # fleet 99.75%
        b["options"] = {"target": "99.5"}
        self.assertEqual(report.compute(b)["metrics"]["fleet_reach_pct"]["status"], "green")
        b["options"] = {"target": "99.9"}
        self.assertEqual(report.compute(b)["metrics"]["fleet_reach_pct"]["status"], "red")


class ReviewRound2Tests(unittest.TestCase):
    def test_severity_words_without_alarm_after_them_are_not_status_words(self):
        metrics = report.compute(bundle())  # avail-alarms is amber (2 major)
        for text in ("{{m:alarms_major}} major and {{m:alarms_critical}} critical ones.",
                     "{{m:alarms_critical}} critical, {{m:alarms_major}} major and {{m:alarms_minor}} minor alarms, plus a warning."):
            self.assertEqual(report.validate(metrics, {"report": "availability", "sections": {"avail-alarms": {"text": text}}}), [], text)
        self.assertTrue(report.validate(metrics, {"report": "availability", "sections": {"avail-alarms": {"text": "There was an outage."}}}))

    def test_scoped_get_only_alarms_never_fall_back_to_network_wide_totals(self):
        summary = {"numOfCriticalAlarms": 9, "numOfMajorAlarms": 9, "numOfMinorAlarms": 9, "numOfWarningAlarms": 9}
        b = phase2_bundle("noc", alarm_summary=summary)
        b["options"] = {"scope": ["branch-a"]}
        m = report.compute(b)
        self.assertEqual((m["metrics"]["active_critical"]["value"], m["sections"]["noc-alarms"]["status"]), (None, "grey"))
        self.assertIn("network-wide", " ".join(m["sections"]["data-gaps"]["notes"]))
        self.assertEqual(report.compute(phase2_bundle("noc", alarm_summary=summary))["metrics"]["active_critical"]["value"], 9)  # scope all: the summary is right

    def test_noc_health_band_is_printed_as_the_reports_own_rule(self):
        m = report.compute(phase2_bundle("noc", health={"1.NE": [{"status": "HEALTHY", "time": NOW - 60}]}))
        self.assertIn("the report's own rule", " ".join(m["sections"]["noc-health"]["notes"]))

    def test_fixed_terms_are_only_the_report_windows(self):
        metrics = report.compute(bundle())
        bad = {"report": "availability", "sections": {"avail-summary": {"text": "The licence expires in 7 days."}}}
        self.assertIn("bare number", " ".join(report.validate(metrics, bad)))
        ok = {"report": "availability", "sections": {"avail-summary": {"text": "Over the last 7 days and the last 24 hours, P95 held."}}}
        self.assertEqual(report.validate(metrics, ok), [])

    def test_a_period_older_than_daily_retention_is_a_gap(self):
        b = bundle(retention={"tunnel": [{"granularity": "DAY", "retention": 31 * 86400}], "interface": [{"granularity": "DAY", "retention": 31 * 86400}]})
        b["period"].update(from_ms=(NOW - 60 * 86400) * 1000, now_s=NOW)
        self.assertIn("older than the 31 days of daily statistics", " ".join(report.compute(b)["sections"]["data-gaps"]["notes"]))
        b["period"].update(from_ms=(NOW - 10 * 86400) * 1000)
        self.assertNotIn("daily statistics", " ".join(report.compute(b)["sections"]["data-gaps"]["notes"]))


T0 = 1790000000000  # incident window start, ms
AUDIT = [{"id": 1, "queuedTime": T0 - 3600000, "user": "admin", "name": "Apply Appliance Template", "nepk": "1.NE", "completionStatus": True},
         {"id": 2, "queuedTime": T0 + 600000, "user": "admin", "name": "Segment Security Policy Changed", "nepk": "1.NE", "completionStatus": False, "result": "refused"},
         {"id": 3, "queuedTime": T0 + 900000, "user": "SYSTEM", "name": "Login HPE Aruba Networking EdgeConnect SD-WAN Orchestrator", "completionStatus": True},
         {"id": 4, "queuedTime": T0 - 2 * 86400000, "user": "old", "name": "Too early", "completionStatus": True}]
ALARMS = [{"id": 10, "applianceId": "1.NE", "severity": "CRITICAL", "name": "TUNNEL_DOWN", "description": "Tunnel down", "timeOccurredInMills": T0 + 60000, "clearedTimeInMills": T0 + 1260000},
          {"id": 11, "applianceId": "1.NE", "severity": "MAJOR", "name": "LINK", "description": "Link down", "timeOccurredInMills": T0 - 7200000},  # open since before
          {"id": 12, "applianceId": "2.NE", "severity": "MINOR", "name": "OLD", "description": "cleared before", "timeOccurredInMills": T0 - 7200000, "clearedTimeInMills": T0 - 3600000},
          {"id": 13, "applianceId": "1.NE", "severity": "CRITICAL", "name": "BAD_IP", "description": "raised days before, still open", "timeOccurredInMills": T0 - 3 * 86400000},
          {"id": 14, "applianceId": "1.NE", "severity": "MAJOR", "name": "STANDING", "description": "raised a month before, still open", "timeOccurredInMills": T0 - 30 * 86400000}]


class WindowClient(RoutedClient):
    """Answers /action and /alarm/appliance by time window, like the Orchestrator."""

    def request(self, method, path, **kwargs):
        q = kwargs.get("query") or {}
        if path == "/action":
            self.calls.append((method, path, q, None))
            rows = sorted([r for r in AUDIT if q["startTime"] <= r["queuedTime"] <= q["endTime"] and q.get("appliance") in (None, r.get("nepk"))], key=lambda r: -r["queuedTime"])
            return json.dumps(rows[:q["limit"]]).encode()  # newest first, cut at the limit
        if path == "/alarm/appliance":
            self.calls.append((method, path, q, kwargs.get("json_body")))
            if q.get("view") == "active":
                return json.dumps([a for a in ALARMS if not a.get("clearedTimeInMills")]).encode()
            return json.dumps([a for a in ALARMS if q["from"] <= a["timeOccurredInMills"] <= q["to"]]).encode()
        if path == "/alarm/correlatedAlarms":  # GET-only alarm list: closed ones carry no clear time
            self.calls.append((method, path, q, None))
            if q["view"] == "closed":
                return json.dumps([dict(a, clearedTimeInMills=None, clearedTime=None, closed=True) for a in ALARMS
                                   if a.get("clearedTimeInMills") and q["from"] <= a["timeOccurredInMills"] <= q["to"]]).encode()
            return json.dumps([dict(a, closed=False) for a in ALARMS if not a.get("clearedTimeInMills")]).encode()
        if path == "/stats/timeseries/availability/appliance":
            self.calls.append((method, path, q, None))
            return json.dumps({"data": [{"timestamp": T0 // 1000 + 60 * i, "samplecount": 1, "appliancereachability": 0 if i < 10 else 1} for i in range(60)]}).encode()
        return super().request(method, path, **kwargs)


class IncidentTests(CollectTests):
    def setUp(self):
        super().setUp()
        self.store = Path(self.tmp.name) / "history"

    def collect(self, report_name, get_only=False, **kwargs):
        client = WindowClient(self.answers())
        kwargs.setdefault("now", datetime.fromtimestamp(T0 / 1000 + 86400, timezone.utc))
        return client, report.collect(self.server(client, get_only=get_only), "lab", report_name, history_root=self.store, **kwargs)

    def test_incident_timeline_reachability_and_changes(self):
        start = datetime.fromtimestamp(T0 / 1000, timezone.utc)
        client, b = self.collect("incident", window=(start, datetime.fromtimestamp(T0 / 1000 + 3600, timezone.utc)))
        m = report.compute(b)
        timeline = m["sections"]["inc-timeline"]["table"]
        # raised in the window first, then those already open (even a month-old one, from the open-now read); the one cleared before is out
        self.assertEqual([r["alarm"] for r in timeline], ["TUNNEL_DOWN", "BAD_IP", "STANDING", "LINK"])  # worst severity first (persona review 2026-11-09)
        v = {k: m["metrics"][k]["value"] for k in ("inc_alarms", "inc_critical", "inc_open_at_end", "inc_median_clear_min", "inc_changes_before", "inc_changes_during", "inc_affected")}
        self.assertEqual(v, {"inc_alarms": 4, "inc_critical": 2, "inc_open_at_end": 3, "inc_median_clear_min": 20.0, "inc_changes_before": 1, "inc_changes_during": 2, "inc_affected": 1})
        self.assertEqual(m["sections"]["inc-appliances"]["table"][0]["reachable_pct"], 83.333)  # 10 of 60 minutes unreachable
        self.assertEqual(m["sections"]["inc-summary"]["status"], "red")
        self.assertIn("does not say whether any change caused", " ".join(m["sections"]["inc-changes"]["notes"]))
        paths = [c for c in client.calls if c[1] == "/stats/aggregate/tunnel"]
        self.assertEqual(paths[0][2]["granularity"], "minute")  # the window is inside a day of now
        self.assertIn("Report options: window:", report.render(m))
        self.assertFalse([g for g in m["sections"]["data-gaps"]["notes"] if "alarm archive" in g])  # the window is inside the Orchestrator's 7 days
        client, b = self.collect("incident", window=(start, datetime.fromtimestamp(T0 / 1000 + 3600, timezone.utc)), now=datetime.fromtimestamp(T0 / 1000 + 30 * 86400, timezone.utc))
        self.assertIn("alarm archive", " ".join(report.compute(b)["sections"]["data-gaps"]["notes"]))  # a month later, without an archive

    def test_a_full_audit_page_shows_what_was_read_and_names_the_rest_as_a_gap(self):
        from unittest import mock
        start = datetime.fromtimestamp(T0 / 1000, timezone.utc)
        with mock.patch.object(report, "AUDIT_PAGE", 2):
            client, b = self.collect("incident", window=(start, datetime.fromtimestamp(T0 / 1000 + 3600, timezone.utc)))
            m = report.compute(b)
        self.assertEqual([c[2]["limit"] for c in client.calls if c[1] == "/action"], [2])  # one live page, never stored
        self.assertEqual(len(m["sections"]["inc-changes"]["table"]), 2)
        # the full page reached back only to 10 minutes into the window: neither count is known, so neither is shown as a number
        self.assertEqual((m["metrics"]["inc_changes_before"]["value"], m["metrics"]["inc_changes_during"]["value"]), (None, None))
        with mock.patch.object(report, "AUDIT_PAGE", 3):  # this page reaches back before the window: "during" is complete
            _, b = self.collect("incident", window=(start, datetime.fromtimestamp(T0 / 1000 + 3600, timezone.utc)))
            m = report.compute(b)
        self.assertEqual((m["metrics"]["inc_changes_before"]["value"], m["metrics"]["inc_changes_during"]["value"]), (None, 2))
        self.assertIn("busy audit log", " ".join(m["sections"]["data-gaps"]["notes"]))
        self.assertIn("remote log receiver", " ".join(m["sections"]["data-gaps"]["notes"]))
        self.assertFalse((self.store / "lab" / "audit").exists())

    def test_get_only_incident_uses_the_correlated_alarm_list_and_scoped_audit_reads(self):
        start = datetime.fromtimestamp(T0 / 1000, timezone.utc)
        client, b = self.collect("incident", get_only=True, appliances=["branch-a"], window=(start, datetime.fromtimestamp(T0 / 1000 + 3600, timezone.utc)))
        self.assertFalse([c for c in client.calls if c[0] == "POST"])
        self.assertEqual({c[2]["view"] for c in client.calls if c[1] == "/alarm/correlatedAlarms"}, {"active", "closed"})
        self.assertEqual([c[2].get("appliance") for c in client.calls if c[1] == "/action"], ["1.NE"])  # one page per scoped appliance
        m = report.compute(b)
        rows = {r["alarm"]: r for r in m["sections"]["inc-timeline"]["table"]}
        self.assertEqual(set(rows), {"BAD_IP", "LINK", "TUNNEL_DOWN", "STANDING"})  # OLD was closed before the window: raised outside it, so left out
        self.assertEqual((rows["TUNNEL_DOWN"]["cleared"], rows["TUNNEL_DOWN"]["minutes_to_clear"]), ("closed, time not given", None))
        self.assertIsNone(m["metrics"]["inc_open_at_end"]["value"])  # closed correlated alarms carry no clear time
        self.assertIn("correlated alarm list", " ".join(m["sections"]["data-gaps"]["notes"]))
        self.assertEqual({r["action"] for r in m["sections"]["inc-changes"]["table"]}, {"Apply Appliance Template", "Segment Security Policy Changed"})

    def test_incident_limits_are_refused_or_named(self):
        start = datetime.fromtimestamp(T0 / 1000, timezone.utc)
        with self.assertRaisesRegex(ValueError, "at most 7 days"):
            self.collect("incident", window=(start, datetime.fromtimestamp(T0 / 1000 + 8 * 86400, timezone.utc)), now=datetime.fromtimestamp(T0 / 1000 + 9 * 86400, timezone.utc))
        from unittest import mock
        with mock.patch.object(report, "INCIDENT_MAX_APPLIANCES", 1):
            with self.assertRaisesRegex(ValueError, "at most 1"):
                self.collect("incident", appliances=["branch-a", "branch-b<script>"], window=(start, datetime.fromtimestamp(T0 / 1000 + 3600, timezone.utc)))
            client, b = self.collect("incident", window=(start - timedelta(days=1), datetime.fromtimestamp(T0 / 1000 + 3600, timezone.utc)))
            b["data"]["incident_dropped"] = 1
            self.assertIn("1 more appliances had alarms", " ".join(report.compute(b)["sections"]["data-gaps"]["notes"]))
        with self.assertRaisesRegex(ValueError, "no clear time"):
            self.collect("incident", get_only=True, alarm_id="10")  # closed in the GET list, which gives no clear time

    def test_median_time_to_clear(self):
        b = bundle(incident={"from_ms": T0, "to_ms": T0 + 3600000, "affected": []}, incident_alarms_stored=True,
                   incident_alarms=[{"id": i, "applianceId": "1.NE", "severity": "MAJOR", "timeOccurredInMills": T0, "clearedTimeInMills": T0 + m * 60000} for i, m in ((1, 10), (2, 30))])
        b["report"] = "incident"
        self.assertEqual(report.compute(b)["metrics"]["inc_median_clear_min"]["value"], 20.0)

    def test_incident_window_from_an_alarm_id_and_required_inputs(self):
        client, b = self.collect("incident", alarm_id="10")
        self.assertEqual((b["period"]["from_ms"], b["period"]["to_ms"]), (T0 + 60000 - 3600000, T0 + 1260000 + 3600000))
        with self.assertRaisesRegex(ValueError, "needs --from and --to"):
            self.collect("incident")
        with self.assertRaisesRegex(ValueError, "not in the Orchestrator"):
            self.collect("incident", alarm_id="999")

    def test_store_command(self):
        from unittest import mock
        client = WindowClient(self.answers())
        server = self.server(client, get_only=False)
        with mock.patch.object(report.Server, "from_dotenv", return_value=server), mock.patch("sys.stdout") as out:
            code = report.main(["store", "--orchestrator", "lab", "--history", str(self.store)])
        self.assertEqual(code, 0)
        cov = json.loads((self.store / "lab" / "coverage.json").read_text())["alarms"]
        self.assertEqual(len(cov), 1)
        self.assertAlmostEqual((cov[0][1] - cov[0][0]) / 86400000, 7, delta=0.01)  # the 7 days the Orchestrator keeps, all read
        self.assertFalse((self.store / "lab" / "audit").exists())  # the audit log is never stored
        self.assertIn("alarms", json.loads((self.store / "lab" / "coverage.json").read_text()))  # last 7 days read (none in the fixture are that recent)


class ReviewRound3Tests(unittest.TestCase):
    def test_number_words_are_figures(self):
        metrics = report.compute(bundle())
        for text in ("Two appliances lost five tunnels.", "Reachability was ninety percent.", "About half the sites."):
            problems = report.validate(metrics, {"report": "availability", "sections": {"avail-summary": {"text": text}}})
            self.assertIn("bare number", " ".join(problems), text)
        self.assertEqual(report.validate(metrics, {"report": "availability", "sections": {"avail-summary": {"text": "Someone noticed none of it."}}}), [])

    def test_licences_with_no_expiry_read_are_grey(self):
        m = report.compute(phase2_bundle("lifecycle", gms_license={}, portal_appliances={"data": [{"applianceId": "1.NE"}]}))
        self.assertEqual(m["sections"]["life-licences"]["status"], "grey")

    def test_template_cites_only_computed_metrics(self):
        b = bundle()
        b["report"] = "executive"
        m = report.compute(b)  # no path stats: paths_red is never computed
        cited = report.template(m)["sections"]["exec-availability"]["cite"]
        self.assertNotIn("paths_red", cited)
        self.assertTrue(all(c in m["metrics"] for s in report.template(m)["sections"].values() for c in s["cite"]))

    def test_loss_floor_scales_with_the_window(self):
        paths = {"t1": {"1.NE": {"alias": "busy", "overlayid": "1", "SUM_POST_LOSS": 1, "SUM_WRX_PKTS": 5000, "AVG_LATENCY_AVG": 5, "AVG_JITTER": 1, "mos": 440}}}
        hour = bundle(health_threshold=THRESHOLDS, **{"paths:1.NE": paths})
        hour["period"].update(from_ms=0, to_ms=3600000)
        row = report.compute(hour)["sections"]["avail-paths"]["table"][0]
        self.assertEqual((row.get("note", ""), row["loss_pct"]), ("", 0.02))  # 5,000 packets is plenty for an hour
        month = bundle(health_threshold=THRESHOLDS, **{"paths:1.NE": paths})
        month["period"].update(from_ms=0, to_ms=30 * 86400000)
        month["options"] = {"down_tunnels": "include"}
        self.assertEqual(report.compute(month)["sections"]["avail-paths"]["table"][0].get("note"), "no traffic, probes lost")

    def test_last_months_alarms_without_an_archive_are_not_zero(self):
        b = bundle(appliance_alarms=[], period_alarms_covered=False)
        m = report.compute(b)
        self.assertEqual((m["metrics"]["alarms_critical"]["value"], m["sections"]["avail-alarms"]["status"]), (None, "grey"))
        self.assertIn("alarm archive", " ".join(m["sections"]["data-gaps"]["notes"]))


class ReviewRound3CollectTests(CollectTests):
    def test_availability_reads_the_archive_for_older_alarms(self):
        root = Path(self.tmp.name) / "history"
        History(root, "lab").write("alarms", [{"id": 99, "applianceId": "1.NE", "severity": "CRITICAL", "timeOccurredInMills": 1788307200000}])  # 2026-09-02
        History(root, "lab").add_coverage("alarms", [[1788220800000, 1790812799000]])
        b = report.collect(self.server(RoutedClient(self.answers()), get_only=False), "lab", "availability", "2026-09", history_root=root,
                           now=datetime(2026, 10, 23, tzinfo=timezone.utc))
        m = report.compute(b)
        self.assertTrue(b["data"]["period_alarms_covered"])
        self.assertEqual(m["metrics"]["alarms_critical"]["value"], 1)  # the archived one, though the Orchestrator no longer has it

    def test_unknown_nickname_and_incident_flags_are_refused(self):
        with self.assertRaisesRegex(ValueError, "unknown Orchestrator"):
            report.collect(self.server(RoutedClient(self.answers()), get_only=False), "nope", "availability", "2026-09")
        from unittest import mock
        server = self.server(RoutedClient(self.answers()), get_only=False)
        with mock.patch.object(report.Server, "from_dotenv", return_value=server), mock.patch("sys.stderr") as err:
            self.assertEqual(report.main(["collect", "--orchestrator", "lab", "--report", "availability", "--alarm-id", "5"]), 1)
            self.assertEqual(report.main(["collect", "--orchestrator", "lab", "--report", "incident", "--alarm-id", "5", "--from", "2026-10-01T00:00", "--to", "2026-10-01T01:00"]), 1)
        self.assertIn("only for --report incident", "".join(str(c) for c in err.write.call_args_list))


class ReviewRound4Tests(unittest.TestCase):
    def incident(self, **data):
        b = bundle(incident={"from_ms": T0, "to_ms": T0 + 3600000, "affected": ["1.NE", "2.NE"]}, incident_alarms_stored=True, **data)
        b["report"] = "incident"
        return report.compute(b)

    def test_during_is_a_number_only_if_every_full_page_reached_back_before_the_window(self):
        audit = [{"id": i, "queuedTime": T0 + 60000 * i, "nepk": "1.NE"} for i in range(1, 4)]
        m = self.incident(incident_audit=audit, incident_audit_full=[{"appliance": "1.NE", "oldest": T0 - 3600000}, {"appliance": "2.NE", "oldest": T0 + 600000}])
        self.assertIsNone(m["metrics"]["inc_changes_during"]["value"])  # 2.NE's page stopped 10 minutes into the window
        m = self.incident(incident_audit=audit, incident_audit_full=[{"appliance": "1.NE", "oldest": T0 - 3600000}])
        self.assertEqual(m["metrics"]["inc_changes_during"]["value"], 3)

    def test_repeated_alarm_notes_appear_once(self):
        m = self.incident(incident_alarm_notes=["windows not read", "windows not read"])
        self.assertEqual(sum("windows not read" in g for g in m["sections"]["data-gaps"]["notes"]), 1)

    def test_plural_and_fractional_number_words(self):
        metrics = report.compute(bundle())
        for text in ("Thousands of alarms were raised.", "Traffic doubled.", "It tripled.", "Two halves."):
            self.assertIn("bare number", " ".join(report.validate(metrics, {"report": "availability", "sections": {"avail-summary": {"text": text}}})), text)
        # not figures: third-party tunnels and the last quarter are common EdgeConnect phrases
        self.assertEqual(report.validate(metrics, {"report": "availability", "sections": {"avail-summary": {"text": "Third-party tunnels were stable last quarter."}}}), [])

    def test_merged_archive_alarms_do_not_trip_the_cap_gap_and_expiry_counts_need_dates(self):
        m = report.compute(bundle(appliance_alarms=[{"applianceId": "1.NE", "severity": "MINOR"}] * 3, appliance_alarms_capped=False))
        self.assertNotIn("cap", " ".join(m["sections"]["data-gaps"]["notes"]))
        m = report.compute(phase2_bundle("lifecycle", gms_license={"daysToExpiration": 400}, portal_appliances={"data": [{"applianceId": "1.NE"}]}))
        self.assertIsNone(m["metrics"]["licences_expiring_90"]["value"])


class ReviewRound4CollectTests(CollectTests):
    def test_get_only_counts_cannot_use_the_archive_so_last_month_is_a_gap(self):
        root = Path(self.tmp.name) / "history"
        History(root, "lab").add_coverage("alarms", [[1788220800000, 1790812799000]])  # an archive that covers September
        b = report.collect(self.server(RoutedClient(self.answers()), get_only=True), "lab", "availability", "2026-09", history_root=root,
                           now=datetime(2026, 10, 23, tzinfo=timezone.utc))
        self.assertFalse(b["data"]["period_alarms_covered"])
        self.assertIsNone(report.compute(b)["metrics"]["alarms_critical"]["value"])


class CompleteResultsTests(unittest.TestCase):
    """Reports list every row the scope has (approved 2026-11-09): no worst-N cut in any table."""

    def test_every_table_lists_every_row(self):
        many = [{"nePk": "{}.NE".format(i), "hostName": "s{}".format(i), "state": 1} for i in range(30)]
        data = {"appliances": many}
        data.update({"overlay:{}.NE".format(i): {"1": [{"count": 100, "tunnel_state": i, "blackout": 0}]} for i in range(30)})
        data["appliance_alarms"] = [{"applianceId": "{}.NE".format(i), "severity": "MAJOR", "description": "d"} for i in range(30)] + [{"applianceId": "1.NE", "severity": "MINOR"}]
        m = report.compute(bundle(**data))
        self.assertEqual(len(m["sections"]["avail-tunnels"]["table"]), 31)  # 30 overlay rows + the fixture's underlay row
        self.assertEqual(len(m["sections"]["avail-alarms"]["table"]), 31)  # every alarm in the period, not the first 15 critical and major
        self.assertNotIn("not shown", json.dumps(m))

    def test_noc_lists_every_active_alarm_tunnel_down_and_site(self):
        many = [{"nePk": "{}.NE".format(i), "hostName": "s{}".format(i), "state": 2} for i in range(40)]
        tunnels = {"{}.NE".format(i): {"t": {"operStatus": "Down", "alias": "x"}} for i in range(40)}
        alarms = [{"applianceId": "{}.NE".format(i), "severity": "MINOR"} for i in range(40)]
        m = report.compute(phase2_bundle("noc", appliances=many, tunnels_physical=tunnels, tunnels_bonded={}, active_alarms=alarms))
        self.assertEqual([len(m["sections"][s]["table"]) for s in ("noc-alarms", "noc-tunnels", "noc-worst")], [40, 40, 40])

    def test_capacity_rows_are_all_listed(self):
        totals = [{"nePk": "1.NE", "INTERFACE": "wan{}".format(i), "TRAFFIC_TYPE": 4, "SUM_TX_BYTES": 1, "AVG_MAX_BW_TX": 1000, "AVG_MAX_BW_RX": 1000} for i in range(35)]
        m = report.compute(phase2_bundle("capacity", interface_totals=totals))
        self.assertEqual(len(m["sections"]["cap-links"]["table"]), 35)

    def test_idle_and_dead_tunnels_are_listed_apart_by_default(self):
        overlay = {"1": [{"count": 1000, "tunnel_state": 0, "blackout": 0, "brownout": 0},
                         {"count": 1000, "tunnel_state": 60000, "blackout": 60000, "brownout": 0, "label": "INET", "tunnelcount": 2}]}
        m = report.compute(bundle(**{"overlay:1.NE": overlay}))
        self.assertEqual(m["metrics"]["overlay_avail_pct"]["value"], 100.0)
        self.assertEqual(report.DEFAULT_OPTIONS["down_tunnels"], "separate")


class LayoutTests(unittest.TestCase):
    """The fixed page layout (docs/report-layout.md)."""

    def test_page_frame_order_and_status_with_icon_and_word(self):
        page = report.render(report.compute(bundle()))
        marks = ['class="rpt-head"', 'data-section-id="report-options"', 'data-section-id="verdict"', 'nav class="toc"', 'data-section-id="kpi-strip"',
                 'data-section-id="avail-summary"', "<footer>"]
        self.assertEqual([page.index(m) for m in marks], sorted(page.index(m) for m in marks))
        self.assertIn("<h1>Availability report, 2026-10: 5 areas need attention</h1>", page)  # summary, appliances, tunnels, transports, alarms  # the title is the message
        self.assertIn('<span class="pill warning"><span aria-hidden="true">!</span> Warning</span>', page)
        self.assertNotRegex(page, r"(?i)<script|<(link|img|iframe)\b|src=|https?://")

    def test_long_tables_move_whole_to_the_appendix(self):
        many = [{"nePk": "{}.NE".format(i), "hostName": "s{}".format(i), "state": 1} for i in range(60)]
        data = {"appliances": many}
        data.update({"reach:{}.NE".format(i): [{"samplecount": 100, "appliancereachability": 100 - i % 3}] for i in range(60)})
        page = report.render(report.compute(bundle(**data)))
        self.assertIn('<a href="#appendix-avail-appliances">all 60 rows in the appendix</a>', page)
        appendix = page[page.index('id="appendix-avail-appliances"'):]
        self.assertEqual(appendix.count("<tr>") - 1, 60)  # every row, header row aside

    def test_noc_health_is_a_status_grid_per_category(self):
        hours = HealthByCategoryTests.hours
        data = {"health:" + cat: {"1.NE": hours("HEALTHY" if cat != "MOS" else "MAJOR")} for cat in ("LOSS", "MOS")}
        page = report.render(report.compute(phase2_bundle("noc", **data)))
        self.assertIn('<span class="pill critical"><span aria-hidden="true">\u2715</span> 0%</span>', page)  # MOS, now a table cell (owner review 2026-11-09)
        self.assertIn('<span class="pill good"><span aria-hidden="true">\u2713</span> 100%</span>', page)  # loss


class CardTests(unittest.TestCase):
    """Possible causes and actions come only from cards.json, and only when their conditions hold on the metrics."""

    def test_clauses(self):
        metrics = {"a": {"value": 3, "status": "red"}, "b": {"value": 5, "status": None}, "n": {"value": None, "status": "grey"}}
        holds = lambda clause: report.clause_holds(clause, metrics)
        self.assertEqual([holds(["a", "<", 5]), holds(["a", "<", "b"]), holds(["a", ">=", 4]), holds(["a", "status", ["red"]]), holds(["n", ">", 0]), holds(["n", "==", None]),
                          holds(["missing", ">", 0])], [True, True, False, True, False, True, False])

    def test_mos_threshold_cause_and_action_appear_only_when_the_data_says_so(self):
        hours = HealthByCategoryTests.hours
        bad_mos = {"health:" + cat: {"1.NE": hours("MAJOR" if cat == "MOS" else "HEALTHY")} for cat in ("LOSS", "LATENCY", "JITTER", "MOS")}
        sec = report.compute(phase2_bundle("noc", **bad_mos))["sections"]["noc-health"]
        self.assertEqual(([c["id"] for c in sec["causes"]], [a["id"] for a in sec["actions"]]), (["mos_threshold"], ["review_health_thresholds"]))
        bad_loss = {"health:" + cat: {"1.NE": hours("MAJOR" if cat in ("MOS", "LOSS") else "HEALTHY")} for cat in ("LOSS", "LATENCY", "JITTER", "MOS")}
        sec = report.compute(phase2_bundle("noc", **bad_loss))["sections"]["noc-health"]
        self.assertEqual([c["id"] for c in sec["causes"]], ["path_loss"])  # loss is bad too: no longer just a MOS setting
        page = report.render(report.compute(phase2_bundle("noc", **bad_mos)))
        self.assertIn("<h3>Possible causes</h3>", page)
        self.assertIn("<h3>Recommended actions</h3>", page)

    def test_every_card_is_well_formed_and_names_real_sections(self):
        known = {sid for sections in report.SECTIONS.values() for sid, _ in sections}
        for sid, card in report.CARDS.items():
            self.assertIn(sid, known)
            for entry in card["causes"] + card["actions"]:
                self.assertTrue(entry["id"] and entry["text"] and isinstance(entry["when"], list) and entry["when"])
                for clause in entry["when"]:
                    self.assertIn(clause[1], ("<", "<=", ">", ">=", "==", "!=", "status"))

    def test_executive_sections_carry_the_actions_of_their_sources(self):
        m = report.compute(phase2_bundle("executive", active_alarms=[{"applianceId": "1.NE", "severity": "CRITICAL"}]))
        self.assertIn("triage_critical", [a["id"] for a in m["sections"]["exec-alarms"]["actions"]])


DNS_HEADER = ["LANTX_PKTS", "MIN_TIME", "IS_SOURCE", "DNS", "LANRX_PKTS", "FLOW_COUNT", "IPADDR", "CALC_DNS", "FLOWS_DELETED", "WANRX_BYTES", "WANTX_BYTES", "MAX_TIME",
              "SPLIT_TYPE", "COUNTRY", "WANRX_PKTS", "WANTX_PKTS", "NEPK", "SERVICE_ID", "COUNT", "LANRX_BYTES", "LANTX_BYTES", "FLOWS_CREATED"]
PORT_HEADER = ["LANTX_PKTS", "PORT", "MIN_TIME", "IS_SOURCE", "PROTOCOL", "LANRX_PKTS", "FLOW_COUNT", "FLOWS_DELETED", "IS_KNOWN", "WANRX_BYTES", "WANTX_BYTES", "MAX_TIME",
               "WANRX_PKTS", "WANTX_PKTS", "NEPK", "COUNT", "LANRX_BYTES", "LANTX_BYTES", "FLOWS_CREATED"]


def dns_row(ne, name, country, wan_tx, wan_rx):
    row = dict.fromkeys(DNS_HEADER, 0)
    row.update(NEPK=ne, DNS=name, CALC_DNS="", IPADDR="10.0.0.1", COUNTRY=country, WANTX_BYTES=wan_tx, WANRX_BYTES=wan_rx)
    return [row[h] for h in DNS_HEADER]


def port_row(ne, port, proto, wan_tx, wan_rx):
    row = dict.fromkeys(PORT_HEADER, 0)
    row.update(NEPK=ne, PORT=port, PROTOCOL=proto, WANTX_BYTES=wan_tx, WANRX_BYTES=wan_rx)
    return [row[h] for h in PORT_HEADER]


class TrafficTests(unittest.TestCase):
    """R4 Traffic and applications: what uses the WAN, summed over every appliance in scope."""

    def data(self):
        app = lambda ne, name, tx, rx: {"nePk": ne, "APPNAME": name, "SUM_WTX_BYTES": tx, "SUM_WRX_BYTES": rx}
        return {"apps:1.NE": [app("1.NE", "__total__", 900, 100), app("1.NE", "Zoom", 500, 100), app("1.NE", "Office365", 300, 0)],
                "apps:2.NE": [app("2.NE", "__total__", 1000, 0), app("2.NE", "Office365", 700, 0)],
                "apps_previous:1.NE": [app("1.NE", "__total__", 400, 100)], "apps_previous:2.NE": [app("2.NE", "__total__", 500, 0)],
                "talkers:1.NE": [{"1.NE": [{"SOURCE_IP": "10.1.1.1", "WANTX_BYTES": 70, "WANRX_BYTES": 30}]}],
                "dns:1.NE": [{"1.NE": [dns_row("1.NE", "example.com", "Germany", 60, 40), dns_row("1.NE", "", "Germany", 10, 0)]}, {"header": [DNS_HEADER]}],
                "ports:1.NE": [{"1.NE": [port_row("1.NE", 443, 6, 80, 20)]}, {"header": [PORT_HEADER]}]}

    def test_applications_are_summed_over_appliances_with_share_and_change(self):
        m = report.compute(phase2_bundle("traffic", **self.data()))
        apps = m["sections"]["traffic-apps"]["table"]
        self.assertEqual([(r["application"], r["wan_bytes"], r["share_pct"]) for r in apps], [("Office365", 1000, 50.0), ("Zoom", 600, 30.0)])
        self.assertEqual((m["metrics"]["wan_bytes_total"]["value"], m["metrics"]["wan_bytes_change_pct"]["value"]), (2000, 100.0))  # previous period 1,000
        self.assertEqual(m["sections"]["traffic-domains"]["table"][0]["domain"], "example.com")
        self.assertEqual(m["sections"]["traffic-countries"]["table"][0], {"country": "Germany", "wan_bytes": 110, "share_pct": 100.0})
        self.assertEqual(m["sections"]["traffic-ports"]["table"][0]["port"], "443/tcp")
        self.assertEqual(m["sections"]["traffic-talkers"]["table"][0], {"appliance": "branch-a", "source_ip": "10.1.1.1", "wan_bytes": 100})
        self.assertIn("capped at 100", " ".join(m["sections"]["traffic-talkers"]["notes"]))

    def test_application_data_shorter_than_the_period_is_a_gap(self):
        data = self.data()
        for row in data["apps:1.NE"] + data["apps:2.NE"]:
            row.update(MIN_TIMESTAMP=20 * 86400, MAX_TIMESTAMP=30 * 86400)  # only the last 10 days of a 30-day window
        b = phase2_bundle("traffic", **data)
        b["period"].update(from_ms=0, to_ms=30 * 86400000)
        m = report.compute(b)
        self.assertEqual(m["metrics"]["traffic_days_covered"]["value"], 10.0)  # first to last hourly bucket, plus that hour
        self.assertIn("covers only", " ".join(m["sections"]["data-gaps"]["notes"]))
        self.assertIsNone(m["metrics"]["wan_bytes_change_pct"]["value"])  # a part-period total is not compared

    def test_collect_reads_every_appliance_for_the_window_and_the_previous_one(self):
        client = RoutedClient({"/gms/versions": {}, "/appliance": APPLIANCES})
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "spec.json"
            spec.write_text(json.dumps(dict(SPEC, paths=dict(SPEC["paths"], **{p: {"get": {"summary": p}} for p in report.TRAFFIC_PATHS}))))
            orchestrator = Orchestrator("lab", Config(base_url="https://orch.example/gms/rest", api_key="KEY"), False, str(spec), client)
            b = report.collect(Server({"lab": orchestrator}, default="lab", log=lambda line: None), "lab", "traffic", now=datetime(2026, 9, 21, tzinfo=timezone.utc))
        apps = [c[2] for c in client.calls if c[1] == "/stats/aggregate/application2"]
        self.assertEqual([(q["nePk"], q["endTime"] - q["startTime"]) for q in apps], [("1.NE", 7 * 86400), ("2.NE", 7 * 86400), ("1.NE", 7 * 86400), ("2.NE", 7 * 86400)])
        self.assertEqual(apps[2]["endTime"], apps[0]["startTime"])  # the previous period ends where this one starts
        self.assertEqual(b["options"]["period"], "last-7-days")


class PathQualityTests(unittest.TestCase):
    """R3 Path quality: every active path worst first, FEC hiding loss, and transports compared."""

    def test_ranked_paths_fec_masking_and_transports(self):
        t = lambda alias, ov, pre, post, rx, lat: {"1.NE": {"alias": alias, "overlayid": ov, "SUM_PRE_LOSS": pre, "SUM_POST_LOSS": post, "SUM_WRX_PKTS": rx,
                                                            "AVG_LATENCY_AVG": lat, "AVG_JITTER": 1, "mos": 430}}
        paths = {"a": t("to_hub_INETA-INETA", "0", 3000, 10, 97000, 10), "b": t("to_hub_MPLS-MPLS", "0", 0, 0, 100000, 15),
                 "c": t("to_hub_INETB-INETB", "0", 0, 4000, 96000, 80), "d": t("to_hub_DEFAULT", "1", 0, 0, 100000, 12)}
        b = phase2_bundle("paths", health_threshold=THRESHOLDS, **{"paths:1.NE": paths})
        b["period"].update(from_ms=0, to_ms=7 * 86400000)
        m = report.compute(b)
        ranked = m["sections"]["paths-ranked"]["table"]
        self.assertEqual(ranked[0]["tunnel"], "to_hub_INETB-INETB")
        self.assertEqual(ranked[0]["pre_fec_loss_pct"], 0.0)
        self.assertEqual([r["tunnel"] for r in m["sections"]["paths-fec"]["table"]], ["to_hub_INETA-INETA"])  # 3% before FEC, 0.01% after
        self.assertEqual(m["metrics"]["paths_fec_masking"]["value"], 1)
        transports = {r["transport"]: r for r in m["sections"]["paths-transport"]["table"]}
        self.assertEqual(sorted(transports), ["INETA-INETA", "INETB-INETB", "MPLS-MPLS"])  # underlay paths only
        self.assertEqual(transports["INETB-INETB"]["outside_thresholds"], 1)
        self.assertIn("fec_masking", [c["id"] for c in m["sections"]["paths-fec"]["causes"]])

    def test_paths_defaults_to_the_last_7_days_hourly(self):
        self.assertEqual(report.DEFAULT_PERIOD["paths"], "last-7-days")


class CapacityPlanningTests(unittest.TestCase):
    """R5: per busy link, its peak hour, change against the previous period, and the applications behind it."""

    def test_peak_hour_change_and_drivers(self):
        load = lambda t: 99 if t // 3600 % 24 == 14 else 95 if 9 <= t // 3600 % 24 <= 13 else 10  # business hours busy, 14:00 busiest
        hours = [{"timestamp": NOW - 3600 * (h + 1), "tx_bytes": 45000000000 * load(NOW - 3600 * (h + 1)) / 100, "rx_bytes": 0,
                  "max_bw_tx": 100000, "max_bw_rx": 100000} for h in range(240)]
        previous = [dict(CapacityTests.TOTALS[0], SUM_TX_BYTES=CapacityTests.TOTALS[0]["SUM_TX_BYTES"] / 2)]
        app = lambda name, n: {"nePk": "1.NE", "APPNAME": name, "SUM_WTX_BYTES": n, "SUM_WRX_BYTES": 0}
        m = report.compute(phase2_bundle("capacity", interface_totals=CapacityTests.TOTALS, interface_totals_previous=previous,
                                         **{"hourly:1.NE:wan0": hours, "apps:1.NE": [app("__total__", 100), app("Backup", 60), app("Zoom", 30)]}))
        row = next(r for r in m["sections"]["cap-links"]["table"] if r["interface"] == "wan0")
        self.assertEqual(row["peak_hour_utc"], "14:00")
        self.assertEqual(row["avg_change_pts"], 50.0)  # 100% average now, 50% in the previous period
        self.assertEqual(row["top_applications"], "Backup 60%, Zoom 30%")

    def test_collect_reads_the_previous_period_and_each_appliances_applications(self):
        client = RoutedClient(dict(Phase2CollectTests.answers(Phase2CollectTests()), **{"/stats/aggregate/application2": []}))
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "spec.json"
            spec.write_text(json.dumps(dict(SPEC, paths=dict(SPEC["paths"], **{"/stats/aggregate/application2": {"get": {"summary": "a"}}}))))
            orchestrator = Orchestrator("lab", Config(base_url="https://orch.example/gms/rest", api_key="KEY"), False, str(spec), client)
            report.collect(Server({"lab": orchestrator}, default="lab", log=lambda line: None), "lab", "capacity", "2026-09", now=datetime(2026, 9, 21, tzinfo=timezone.utc))
        posts = [c[2] for c in client.calls if c[1] == "/stats/aggregate/interface"]
        self.assertEqual(len(posts), 2)
        self.assertEqual(posts[1]["endTime"], posts[0]["startTime"])  # the previous period, same length
        self.assertEqual(sorted(c[2]["nePk"] for c in client.calls if c[1] == "/stats/aggregate/application2"), ["1.NE", "2.NE"])


class SummaryReportTests(unittest.TestCase):
    """C1 executive and C2 operations: stitched from the other reports' sections, so their numbers always match."""

    def test_executive_adds_traffic_paths_and_one_action_list(self):
        data = TrafficTests().data()
        data["active_alarms"] = [{"applianceId": "1.NE", "severity": "CRITICAL"}]
        m = report.compute(phase2_bundle("executive", **data))
        self.assertEqual(report.EXEC_KPIS, ("fleet_reach_pct", "paths_ok_pct", "wan_bytes_total", "worst_p95_pct", "active_critical", "license_days_left"))
        self.assertEqual(m["metrics"]["wan_bytes_total"]["value"], 2000)  # the same figure the traffic report computes
        self.assertIn("exec-traffic", m["sections"])
        self.assertIn("exec-paths", m["sections"])
        actions = [a["id"] for a in m["sections"]["exec-actions"]["actions"]]
        self.assertIn("triage_critical", actions)
        self.assertEqual(len(actions), len(set(actions)))

    def test_operations_summary_stitches_noc_paths_and_capacity(self):
        self.assertEqual(report.PARTS["operations"], ("noc", "paths", "capacity"))
        self.assertEqual(report.DEFAULT_PERIOD["operations"], "last-7-days")
        m = report.compute(phase2_bundle("operations", active_alarms=[{"applianceId": "1.NE", "severity": "MAJOR"}]))
        self.assertEqual([sid for sid in m["sections"]], [sid for sid, _ in report.SECTIONS["operations"]])
        self.assertEqual(m["sections"]["ops-alarms"]["status"], "amber")


class MoreReportTests(unittest.TestCase):
    """R6 optimisation, R7 security, R8 change and alarm activity."""

    def test_optimisation_reduction_per_appliance(self):
        flows = {"OPTIMIZED_TRAFFIC": {"TCP_ACCELERATED": {"1.NE": {"nePk": "1.NE", "SUM_LRX_BYTES": 1000, "SUM_WTX_BYTES": 400, "SUM_WRX_BYTES": 100, "SUM_LTX_BYTES": 300}},
                                       "NON_TCP": {"1.NE": {"nePk": "1.NE", "SUM_LRX_BYTES": 0, "SUM_WTX_BYTES": 0, "SUM_WRX_BYTES": 0, "SUM_LTX_BYTES": 0}}}}
        m = report.compute(phase2_bundle("optimisation", **{"flows:1.NE": flows}))
        row = m["sections"]["opt-appliances"]["table"][0]
        self.assertEqual((row["appliance"], row["lan_bytes"], row["wan_bytes"], row["saved_bytes"], row["reduction_pct"]), ("branch-a", 1300, 500, 800, 61.538))
        self.assertEqual(m["metrics"]["opt_reduction_pct"]["value"], 61.538)

    def test_security_drops_per_zone_pair(self):
        rows = [{"nePk": "1.NE", "fromZone": "1", "toZone": "2", "flows_allowed": 90, "flows_dropped": 10, "policy_drop_pkts": 7, "routing_drop_pkts": 3}]
        m = report.compute(phase2_bundle("security", zones={"1": {"name": "TRUSTED"}, "2": {"name": "GUEST"}}, **{"security:1.NE": rows}))
        row = m["sections"]["sec-pairs"]["table"][0]
        self.assertEqual((row["from_zone"], row["to_zone"], row["flows_dropped"], row["dropped_pct"]), ("TRUSTED", "GUEST", 10, 10.0))
        self.assertEqual(m["metrics"]["sec_flows_dropped"]["value"], 10)

    def test_activity_changes_repeat_alarms_and_alarms_after_a_change(self):
        hour = 3600000
        audit = [{"id": 1, "user": "admin", "name": "Apply Appliance Template", "nepk": "1.NE", "queuedTime": 10 * hour, "completionStatus": True},
                 {"id": 2, "user": "admin", "name": "Reboot", "nepk": "1.NE", "queuedTime": 20 * hour, "completionStatus": False}]
        alarm = lambda i, t, sev="MAJOR", ne="1.NE", name="Tunnel down": {"id": i, "applianceId": ne, "severity": sev, "name": name, "timeOccurredInMills": t,
                                                                          "clearedTimeInMills": t + hour}
        alarms = [alarm(1, 10 * hour + 60000), alarm(2, 30 * hour), alarm(3, 40 * hour), alarm(4, 50 * hour, "CRITICAL", "2.NE", "Disk")]
        m = report.compute(phase2_bundle("activity", activity_audit=audit, activity_alarms=alarms))
        self.assertEqual((m["metrics"]["act_changes"]["value"], m["metrics"]["act_changes_failed"]["value"], m["metrics"]["act_alarms"]["value"]), (2, 1, 4))
        self.assertEqual([(r["change"], r["times"], r["failed"]) for r in m["sections"]["act-changes"]["table"]], [("Reboot", 1, 1), ("Apply Appliance Template", 1, 0)])
        self.assertEqual(m["sections"]["act-repeat"]["table"][0], {"appliance": "branch-a", "alarm": "Tunnel down", "times": 3})
        self.assertEqual([r["alarm"] for r in m["sections"]["act-after-change"]["table"]], ["Tunnel down"])  # raised within an hour of a change on the same appliance

    def test_activity_pages_back_through_a_full_audit_log(self):
        class Paged(RoutedClient):
            def request(self, method, path, **kwargs):
                if path == "/action":
                    self.calls.append((method, path, kwargs.get("query"), None))
                    until = kwargs["query"]["endTime"]
                    size = report.AUDIT_PAGE if sum(c[1] == "/action" for c in self.calls) < 3 else 5  # two full pages, then a short one
                    page = [{"id": until - i, "queuedTime": until - i, "user": "u", "name": "n", "nepk": "1.NE"} for i in range(size)]
                    return json.dumps(page).encode()
                return super().request(method, path, **kwargs)
        client = Paged({"/gms/versions": {}, "/appliance": APPLIANCES})
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "spec.json"
            spec.write_text(json.dumps(SPEC))
            orchestrator = Orchestrator("lab", Config(base_url="https://orch.example/gms/rest", api_key="KEY"), False, str(spec), client)
            b = report.collect(Server({"lab": orchestrator}, default="lab", log=lambda line: None), "lab", "activity", now=datetime(2026, 9, 21, tzinfo=timezone.utc),
                               history_root=Path(tmp) / "h")
        pages = [c[2] for c in client.calls if c[1] == "/action"]
        self.assertGreater(len(pages), 1)
        self.assertEqual(pages[1]["endTime"], pages[0]["endTime"] - report.AUDIT_PAGE)  # the next page ends just before the oldest entry read
        self.assertEqual((len(pages), len(b["data"]["activity_audit"])), (3, 2 * report.AUDIT_PAGE + 5))
        self.assertFalse(b["data"]["activity_audit_full"])

    def test_new_reports_default_to_the_last_7_days(self):
        self.assertEqual([report.DEFAULT_PERIOD[r] for r in ("optimisation", "security", "activity")], ["last-7-days"] * 3)


class AvailabilityReworkTests(unittest.TestCase):
    """Availability adds interfaces (WAN ports) and a hub / branch roll-up."""

    def test_interfaces_and_roles(self):
        apps = [dict(APPLIANCES[0], networkRole="1"), dict(APPLIANCES[1], networkRole="0")]
        ifaces = [{"nepk": "1.NE", "ifname": "wan0", "label": "INETA", "state": 600, "count": 1000}, {"nepk": "1.NE", "ifname": "lan0", "label": "none", "state": 0, "count": 1000}]
        b = bundle(appliances=apps, **{"ifavail:1.NE": ifaces})
        b["data"]["availability_threshold"]["interfaceAvailability"] = {"goodLimit": 99.0, "okLimit": 99.9}
        m = report.compute(b)
        rows = {r["interface"]: (r["availability_pct"], r["status"]) for r in m["sections"]["avail-interfaces"]["table"]}
        self.assertEqual(rows, {"wan0": (99.0, "amber"), "lan0": (100.0, "green")})  # 600 s down of 1,000 minutes
        ifaces.append({"nepk": "1.NE", "ifname": "lan1", "label": "none", "state": 59900, "count": 1000})  # up 0.2% of the period: an unused port
        m = report.compute(bundle(appliances=apps, **{"ifavail:1.NE": ifaces}))
        self.assertNotIn("lan1", [r["interface"] for r in m["sections"]["avail-interfaces"]["table"]])
        self.assertEqual(m["metrics"]["interfaces_unused"]["value"], 1)
        roles = {r["role"]: r["reachability_pct"] for r in m["sections"]["avail-roles"]["table"]}
        self.assertEqual(roles, {"hub": 99.5, "branch": 100.0})


class SiteAndCustomTests(unittest.TestCase):
    """C3 site report (one appliance, every area) and C4 custom bundle (the parts the user names)."""

    def test_custom_stitches_the_named_parts_in_order(self):
        b = phase2_bundle("custom", **TrafficTests().data())
        b["options"] = {"parts": ["traffic", "paths"]}
        m = report.compute(b)
        ids = [sid for sid, _ in m["section_list"]]
        self.assertEqual(ids[:2], ["traffic-summary", "traffic-apps"])
        self.assertIn("paths-ranked", ids)
        self.assertEqual(ids[-1], "data-gaps")
        self.assertEqual(ids.count("data-gaps"), 1)
        page = report.render(m)
        self.assertIn('data-section-id="paths-ranked"', page)
        self.assertEqual(report.template(m)["sections"].keys(), dict(m["section_list"]).keys())

    def test_site_needs_one_appliance_and_custom_needs_parts(self):
        client = RoutedClient({"/gms/versions": {}, "/appliance": APPLIANCES})
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "spec.json"
            spec.write_text(json.dumps(SPEC))
            server = Server({"lab": Orchestrator("lab", Config(base_url="https://orch.example/gms/rest", api_key="KEY"), False, str(spec), client)}, default="lab", log=lambda l: None)
            with self.assertRaises(ValueError):
                report.collect(server, "lab", "site", now=datetime(2026, 9, 21, tzinfo=timezone.utc))  # scope missing
            with self.assertRaises(ValueError):
                report.collect(server, "lab", "custom", now=datetime(2026, 9, 21, tzinfo=timezone.utc))  # parts missing
            b = report.collect(server, "lab", "site", appliances=["branch-a"], now=datetime(2026, 9, 21, tzinfo=timezone.utc), history_root=Path(tmp) / "h")
        self.assertEqual(b["options"]["parts"], list(report.PARTS["site"]))


class ConsistencyTests(unittest.TestCase):
    """What two models can differ on: only the summary sentences. Same data gives the same sections, numbers, statuses, causes and actions."""

    def test_two_narratives_change_only_the_summary_sentences(self):
        b = phase2_bundle("noc", **{"health:MOS": {"1.NE": HealthByCategoryTests.hours("MAJOR")}, "health:LOSS": {"1.NE": HealthByCategoryTests.hours("HEALTHY")}})
        m1, m2 = report.compute(json.loads(json.dumps(b))), report.compute(json.loads(json.dumps(b)))
        self.assertEqual(m1, m2)  # compute is deterministic
        one = {"report": "noc", "sections": {"noc-health": {"text": "MOS was rated good in {{m:health_mos_good_24h_pct}} of hours."}}}
        two = {"report": "noc", "sections": {"noc-health": {"text": "Only {{m:health_mos_good_24h_pct}} of hours had a good MOS rating."}}}
        strip = lambda page: re.sub(r'<p class="summary">.*?</p>', "", page)
        self.assertEqual(strip(report.render(m1, one)), strip(report.render(m2, two)))


class LayoutGapTests(unittest.TestCase):
    """Gaps from verification.md: bullet graph, line chart, follow-up links, number formats."""

    def test_bullet_graph_shows_value_target_and_bands(self):
        svg = layout.bullets("Availability against target", [("Appliance reachability", 99.5, 99.9, (99.0, 99.9))], 99.0, 100.0)
        self.assertIn("Appliance reachability: 99.500% (target 99.900%)", svg)
        self.assertEqual((svg.count('class="band'), svg.count('class="target"')), (3, 1))

    def test_line_chart_has_one_axis_a_legend_and_at_most_three_series(self):
        series = [("this", [("00", 1.0), ("01", 3.0)]), ("that", [("00", 2.0), ("01", 2.0)])]
        svg = layout.line("Load by hour", series, "%", threshold=80.0)
        self.assertEqual(svg.count("<polyline"), 2)
        self.assertIn("threshold 80", svg)
        self.assertIn('class="legend"', svg)
        with self.assertRaises(ValueError):
            layout.line("x", series * 2, "%")

    def test_series_with_different_hours_share_one_time_axis(self):
        svg = layout.line("t", [("a", [("01", 1.0), ("03", 1.0)]), ("b", [("02", 2.0), ("03", 2.0)])], "%")
        xs = [[p.split(",")[0] for p in m.split()] for m in re.findall(r'points="([^"]+)"', svg)]
        self.assertEqual(xs[0][1], xs[1][1])  # both "03" points sit at the same x
        self.assertNotEqual(xs[0][0], xs[1][0])  # "01" and "02" do not
        self.assertEqual(layout.line("t", [("one", [("01", 5.0)])], "%").count("<circle"), 1)  # a single point is still drawn

    def test_next_links_and_number_formats(self):
        page = report.render(report.compute(bundle()))
        self.assertIn('<nav class="next"', page)
        self.assertIn("<td class=\"n\">99.500</td>", page)  # availability to 3 decimals
        self.assertEqual(layout.table([{"share_pct": 1.23456}]).count("1.2<"), 1)  # other percentages to 1 decimal (loss keeps 2)


class NetworkHealthTests(unittest.TestCase):
    """R1 network health: noc, paths and the day's changes and alarms, plus a watch list of what is degraded but not failed."""

    def test_health_report_parts_period_and_watch_list(self):
        self.assertEqual((report.PARTS["health"], report.DEFAULT_PERIOD["health"]), (("noc", "paths", "activity"), "last-24-hours"))
        paths = {"t": {"1.NE": {"alias": "to_hub_INET", "overlayid": "0", "SUM_POST_LOSS": 50, "SUM_WRX_PKTS": 99950, "AVG_LATENCY_AVG": 30, "AVG_JITTER": 1, "mos": 430}}}
        b = phase2_bundle("health", health_threshold=THRESHOLDS, **{"paths:1.NE": paths})
        b["options"] = {"parts": list(report.PARTS["health"])}
        b["period"].update(from_ms=0, to_ms=86400000)
        m = report.compute(b)
        ids = [sid for sid, _ in m["section_list"]]
        self.assertEqual(ids[-2:], ["health-watch", "data-gaps"])
        self.assertIn("act-changes", ids)
        watch = m["sections"]["health-watch"]["table"]
        self.assertEqual([(r["what"], r["item"]) for r in watch], [("path between thresholds", "branch-a to_hub_INET")])  # 0.05% loss, 30 ms: amber, not red


COLS = ["TIMESTAMP", "WRX_BYTES", "WTX_BYTES", "POST_LOSS", "WRX_PKTS"]


class SectionGapTests(unittest.TestCase):
    """Sections from the API study that verification.md listed as missing."""

    def test_traffic_daily_trend_is_a_line(self):
        ts = lambda d: {"column_def": COLS, "data": [[86400 * d, 100, 50, 0, 0]]}
        trend = {"trend:1.NE": {"column_def": COLS, "data": [[0, 100, 50, 0, 0], [86400, 10, 0, 0, 0]]}, "trend:2.NE": ts(0)}
        b = phase2_bundle("traffic", **trend)
        b["period"].update(from_ms=0, to_ms=7 * 86400000)  # a week: one point per day
        chart = report.compute(b)["sections"]["traffic-summary"]["chart"]
        self.assertEqual((chart["kind"], chart["series"][0][1]), ("line", [["1970-01-01", 300], ["1970-01-02", 10]]))

    def test_worst_path_trends_and_dscp(self):
        trend = {"column_def": COLS, "data": [[3600, 0, 0, 10, 990], [7200, 0, 0, 0, 1000]]}
        dscp = {"ALL_TRAFFIC": {"46": {"1.NE": {"nePk": "1.NE", "DSCP": 46, "SUM_WTX_BYTES": 300, "SUM_WRX_BYTES": 100}},
                                "0": {"1.NE": {"nePk": "1.NE", "DSCP": 0, "SUM_WTX_BYTES": 500, "SUM_WRX_BYTES": 100}}}}
        b = phase2_bundle("paths", health_threshold=THRESHOLDS, path_trends=[{"appliance": "branch-a", "tunnel": "to_hub", "rows": trend}], **{"dscp:1.NE": dscp})
        m = report.compute(b)
        series = m["sections"]["paths-trend"]["chart"]["series"]
        self.assertEqual(series[0][0], "branch-a to_hub")
        self.assertEqual([round(v, 1) for _, v in series[0][1]], [1.0, 0.0])
        self.assertEqual(m["sections"]["paths-trend"]["status"], "amber")  # worst hour 1%: between the 0.1% and 1% loss limits
        spiky = {"column_def": COLS, "data": [[3600, 0, 0, 900, 100], [7200, 0, 0, 3, 7]]}  # 90% loss: red; 3 of 10 packets: too few to judge, left out
        m2 = report.compute(phase2_bundle("paths", health_threshold=THRESHOLDS, path_trends=[{"appliance": "a", "tunnel": "t", "rows": spiky}]))
        self.assertEqual(([round(v) for _, v in m2["sections"]["paths-trend"]["chart"]["series"][0][1]], m2["sections"]["paths-trend"]["status"]), ([90], "red"))
        self.assertEqual([(r["dscp"], r["share_pct"]) for r in m["sections"]["paths-dscp"]["table"]], [("0 (be)", 60.0), ("46 (ef)", 40.0)])

    def test_qos_drops_per_class(self):
        shaper = [{"trafficClass": 2, "direction": 0, "totalBytes": 1000, "qosDrops": 10, "otherDrops": 1}, {"trafficClass": 2, "direction": 0, "totalBytes": 1000, "qosDrops": 0, "otherDrops": 0}]
        m = report.compute(phase2_bundle("capacity", **{"shaper:1.NE": {"data": shaper}}))  # 10.0 wraps the rows in "data"
        self.assertEqual(m["sections"]["cap-qos"]["table"][0], {"appliance": "branch-a", "traffic_class": 2, "direction": "outbound", "bytes": 2000, "qos_drops": 10, "other_drops": 1})

    def test_optimisation_by_application_and_boost(self):
        app = {"nePk": "1.NE", "APPNAME": "CIFS", "SUM_LRX_BYTES": 800, "SUM_LTX_BYTES": 200, "SUM_WTX_BYTES": 300, "SUM_WRX_BYTES": 100}
        m = report.compute(phase2_bundle("optimisation", **{"apps:1.NE": [app]}))
        self.assertEqual(m["sections"]["opt-apps"]["table"][0], {"application": "CIFS", "lan_bytes": 1000, "wan_bytes": 400, "saved_bytes": 600, "reduction_pct": 60.0})
        self.assertEqual(m["sections"]["opt-boost"]["status"], "grey")

    def test_availability_per_transport_label_and_overlay_with_bullets(self):
        b = bundle(overlays=[{"id": 1, "name": "VOICE"}], **{"overlay:1.NE": {"1": [{"overlayid": 1, "count": 1000, "tunnel_state": 600, "blackout": 0, "brownout": 0}],
                                                                       "0": [{"overlayid": 0, "count": 1000, "tunnel_state": 0, "blackout": 0, "brownout": 0}]},
                                                     "underlay:1.NE": {"0": [{"overlayid": 0, "label": "INETA", "count": 1000, "tunnel_state": 0, "blackout": 0, "brownout": 0}]}})
        m = report.compute(b)
        rows = {(r["kind"], r["name"]): r["availability_pct"] for r in m["sections"]["avail-transport"]["table"]}
        self.assertEqual(rows, {("overlay", "VOICE"): 99.0, ("transport", "INETA"): 100.0})
        self.assertEqual(m["sections"]["avail-summary"]["chart"]["kind"], "bullets")


class OptionGapTests(unittest.TestCase):
    """Per-report options from the plan: traffic type, overlay, planning threshold."""

    def test_threshold_sets_the_planning_limit_and_is_printed(self):
        hourly = [{"tx_bytes": 45000000000 * 60 / 100, "rx_bytes": 0, "max_bw_tx": 100000, "max_bw_rx": 100000}] * 24  # 60% every hour
        b = phase2_bundle("capacity", interface_totals=CapacityTests.TOTALS, **{"hourly:1.NE:wan0": hourly})
        self.assertEqual(next(r for r in report.compute(b)["sections"]["cap-links"]["table"] if r["interface"] == "wan0")["status"], "green")
        b["options"] = {"threshold": 50.0}
        m = report.compute(b)
        self.assertEqual(next(r for r in m["sections"]["cap-links"]["table"] if r["interface"] == "wan0")["status"], "amber")
        self.assertIn("planning limit: 50.0", report.render(m))

    def test_bad_values_are_refused(self):
        client = RoutedClient({"/gms/versions": {}, "/appliance": APPLIANCES})
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "spec.json"
            spec.write_text(json.dumps(SPEC))
            server = Server({"lab": Orchestrator("lab", Config(base_url="https://orch.example/gms/rest", api_key="KEY"), False, str(spec), client)}, default="lab", log=lambda l: None)
            for kwargs in ({"traffic_type": "voice"}, {"threshold": 150.0}):
                with self.assertRaises(ValueError):
                    report.collect(server, "lab", "traffic", now=datetime(2026, 9, 21, tzinfo=timezone.utc), **kwargs)


GOLDEN = Path(__file__).with_name("golden")


class SnapshotTests(unittest.TestCase):
    """The layout is fixed: these pages must not change unless the golden files are updated on purpose (UPDATE_GOLDEN=1)."""

    def check(self, name, page):
        path = GOLDEN / (name + ".html")
        if os.environ.get("UPDATE_GOLDEN"):
            path.write_text(page, encoding="utf-8")
        self.assertEqual(page, path.read_text(encoding="utf-8"), "layout changed; if on purpose, rerun with UPDATE_GOLDEN=1 and review the diff")

    def test_availability_page(self):
        self.check("availability", report.render(report.compute(bundle())))

    def test_noc_page(self):
        data = {"health:" + c: {"1.NE": HealthByCategoryTests.hours("MAJOR" if c == "MOS" else "HEALTHY")} for c in ("LOSS", "MOS")}
        self.check("noc", report.render(report.compute(phase2_bundle("noc", active_alarms=[{"applianceId": "1.NE", "severity": "MAJOR", "description": "d"}], **data))))


class ThemeTests(unittest.TestCase):
    """Light, dark or the reader's system setting; long unbroken text never widens the page on a phone."""

    def test_theme_is_light_dark_or_auto(self):
        m = report.compute(bundle())
        self.assertIn('<html lang="en" data-theme="light">', report.render(m, theme="light"))
        self.assertIn('<html lang="en" data-theme="dark">', report.render(m, theme="dark"))
        self.assertIn('<html lang="en">', report.render(m))  # auto: follows the reader's system
        self.assertIn(':root[data-theme="dark"]{', report.render(m))
        with self.assertRaises(ValueError):
            report.render(m, theme="blue")

    def test_long_unbroken_text_wraps(self):
        self.assertIn("overflow-wrap:anywhere", layout.CSS.split("footer{")[1].split("}")[0])
        self.assertIn("svg.chart{min-width:640px}", layout.CSS)  # charts keep readable text on a phone and scroll inside their figure
        self.assertIn("figure{margin:8px 0;overflow-x:auto}", layout.CSS)


class ReadabilityTests(unittest.TestCase):
    """Owner review 2026-11-09: no paragraphs of names; tables with plain headers; health explained; key points as bullets."""

    def test_paths_listed_apart_are_a_table_not_a_paragraph(self):
        idle = {"t{}".format(i): {"1.NE": {"alias": "to_hub_{}".format(i), "overlayid": "1", "SUM_POST_LOSS": 50, "SUM_WRX_PKTS": 0, "AVG_LATENCY_AVG": 5, "AVG_JITTER": 1, "mos": 440}}
                for i in range(3)}
        b = phase2_bundle("paths", health_threshold=THRESHOLDS, **{"paths:1.NE": idle})
        sec = report.compute(b)["sections"]["paths-ranked"]
        self.assertEqual([r["tunnel"] for r in sec["apart"]["rows"]], ["to_hub_0", "to_hub_1", "to_hub_2"])
        self.assertFalse(any("to_hub_0" in n for n in sec["notes"]))  # names are in the table, not in a note
        page = report.render(report.compute(b))
        self.assertIn('<h3 class="apart">Listed apart: tunnels with no traffic that lost probes (3)</h3>', page)

    def test_headers_are_words_with_units(self):
        html_table = layout.table([{"loss_pct": 0.123, "latency_ms": 30.4, "wan_bytes": 10, "pre_fec_loss_pct": 1.0, "mos": 4.38}])
        for header in ("Loss %", "Latency (ms)", "WAN traffic", "Loss before FEC %", "MOS"):
            self.assertIn(">{}<".format(header), html_table)
        self.assertIn(">0.12<", html_table)  # loss to 2 decimals
        self.assertIn(">30<", html_table)  # milliseconds whole

    def test_health_is_a_table_that_explains_itself(self):
        data = {"health:" + c: {"1.NE": HealthByCategoryTests.hours("MAJOR" if c == "MOS" else "HEALTHY")} for c in ("ALARM", "LOSS", "MOS")}
        page = report.render(report.compute(phase2_bundle("noc", **data)))
        sec = page[page.index('id="noc-health"'):page.index('id="noc-tunnels"')]
        self.assertNotIn("<svg", sec)  # a table, not a grid
        self.assertIn("% of the last 24 hours that category was rated healthy", sec)
        self.assertIn("0% means it was never healthy", sec)
        self.assertIn('<span class="pill critical"><span aria-hidden="true">\u2715</span> 0%</span>', sec)

    def test_summary_sections_open_with_key_points(self):
        page = report.render(report.compute(phase2_bundle("noc", active_alarms=[{"applianceId": "1.NE", "severity": "CRITICAL"}])))
        sec = page[page.index('id="noc-summary"'):page.index('id="noc-appliances"')]
        self.assertIn("<h3>Key points</h3>", sec)
        self.assertIn("Active critical alarms: 1", sec)


class ReadabilityRound2Tests(unittest.TestCase):
    """Second pass on real seteam pages: long tables show their worst rows in place, health figures as a small table, a meaningful site list."""

    def test_long_tables_show_the_worst_rows_in_place_and_all_in_the_appendix(self):
        many = [{"nePk": "{}.NE".format(i), "hostName": "s{}".format(i), "state": 1} for i in range(60)]
        data = {"appliances": many}
        data.update({"reach:{}.NE".format(i): [{"samplecount": 100, "appliancereachability": 100 - i % 3}] for i in range(60)})
        page = report.render(report.compute(bundle(**data)))
        sec = page[page.index('id="avail-appliances"'):page.index('id="avail-roles"')]
        self.assertEqual(sec.count("<tr>") - 1, layout.SHOWN_ROWS)
        self.assertIn("Worst {} of 60 shown".format(layout.SHOWN_ROWS), sec)  # the table has a status column, so its order is worst first

    def test_health_figures_are_one_small_table(self):
        data = {"health:" + c: {"1.NE": HealthByCategoryTests.hours("MAJOR" if c == "MOS" else "HEALTHY")} for c in ("LOSS", "MOS")}
        m = report.compute(phase2_bundle("noc", **data))
        sec = m["sections"]["noc-health"]
        self.assertEqual(sec["metrics"], ["health_good_24h_pct", "health_good_7d_pct"])
        self.assertEqual([r["category"] for r in sec["chart"]["rows"]], ["Loss", "MOS"])

    def test_sites_needing_attention_ignore_a_category_that_is_bad_everywhere(self):
        data = {"health:" + c: {ne: HealthByCategoryTests.hours("MAJOR" if c == "MOS" else "HEALTHY") for ne in ("1.NE", "2.NE")} for c in ("LOSS", "LATENCY", "JITTER", "MOS")}
        m = report.compute(phase2_bundle("noc", appliances=[dict(a, state=1) for a in APPLIANCES], **data))
        self.assertEqual(m["sections"]["noc-worst"]["table"], [])  # MOS alone, everywhere: a setting, not two sites to visit

    def test_summary_shows_key_points_instead_of_the_same_figures_twice(self):
        page = report.render(report.compute(phase2_bundle("noc", active_alarms=[{"applianceId": "1.NE", "severity": "CRITICAL"}])))
        sec = page[page.index('id="noc-summary"'):page.index('id="noc-appliances"')]
        self.assertNotIn('class="stats"', sec)


class HealthByCategoryTests(unittest.TestCase):
    """POST /health read once per category, so one category that is always unhealthy cannot hide behind the combined status."""

    @staticmethod
    def hours(status, n=24):
        return [{"status": status, "time": NOW - 3600 * (h + 1)} for h in range(n)]

    def test_each_category_has_its_own_share_and_a_lone_bad_category_is_named(self):
        per = {"ALARM": "HEALTHY", "LOSS": "HEALTHY", "LATENCY": "HEALTHY", "JITTER": "HEALTHY", "MOS": "MAJOR", "BW_UTILIZATION": None}
        data = {"health:" + cat: {"1.NE": self.hours(s), "2.NE": self.hours(s)} for cat, s in per.items()}
        m = report.compute(phase2_bundle("noc", **data))
        v = lambda k: m["metrics"][k]["value"]
        self.assertEqual((v("health_loss_good_24h_pct"), v("health_mos_good_24h_pct"), v("health_good_24h_pct")), (100.0, 0.0, 100.0))  # MOS left out of the headline
        self.assertIsNone(v("health_bw_utilization_good_24h_pct"))  # no statuses at all: no data, not 0
        notes = " ".join(m["sections"]["noc-health"]["notes"])
        self.assertIn("MOS is unhealthy in most hours while loss, latency and jitter are healthy", notes)
        row = m["sections"]["noc-health"]["table"][0]
        self.assertEqual((row["appliance"], row["Loss"]["value"], row["MOS"]["value"], row["MOS"]["status"]), ("branch-a", 100.0, 0.0, "red"))

    def test_collect_reads_health_once_per_category(self):
        client = RoutedClient({"/gms/versions": {}, "/appliance": APPLIANCES})
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "spec.json"
            spec.write_text(json.dumps(SPEC))
            orchestrator = Orchestrator("lab", Config(base_url="https://orch.example/gms/rest", api_key="KEY"), False, str(spec), client)
            report.collect(Server({"lab": orchestrator}, default="lab", log=lambda line: None), "lab", "noc", now=datetime(2026, 9, 21, tzinfo=timezone.utc))
        self.assertEqual([c[3]["verticals"] for c in client.calls if c[1] == "/health"], [[v] for v in report.HEALTH_VERTICALS])


class PersonaReviewTests(unittest.TestCase):
    """Fifteen independent readers, one per report (2026-11-09): what misled them."""

    def path(self, alias, received, lost, latency=5, mos=440):
        return {"alias": alias, "overlayid": "1", "SUM_POST_LOSS": lost, "SUM_PRE_LOSS": lost, "SUM_WRX_PKTS": received, "AVG_LATENCY_AVG": latency, "AVG_JITTER": 1, "mos": mos}

    def test_the_title_counts_the_areas_it_lists(self):
        b = phase2_bundle("operations", active_alarms=[{"applianceId": "1.NE", "severity": "CRITICAL"}])
        m = report.compute(b)
        listed = m["headline"]["text"].split("Attention needed in ", 1)[1].rstrip(".").split(", ")
        title = re.search(r"<title>[^<]*: (\d+) areas? need", report.render(m)).group(1)
        self.assertEqual(int(title), len(listed))

    def test_data_gaps_name_the_appliances_that_returned_nothing(self):
        b = phase2_bundle("security", **{"security:1.NE": [{"nePk": "1.NE", "fromZone": "1", "toZone": "2", "flows_allowed": 1, "flows_dropped": 0}]})
        del b["data"]["reach:2.NE"]
        sec = report.compute(b)["sections"]["data-gaps"]
        self.assertIn("1 of 2 appliances returned no data for this report, so the figures leave them out: branch-b<script>", " ".join(sec["notes"]))
        self.assertNotEqual(sec["status"], "green")

    def test_figures_have_thousands_separators_and_plural_units_read_right(self):
        self.assertEqual(report._fmt({"value": 522164, "unit": "flows"}), "522,164 flows")
        self.assertEqual(report._fmt({"value": 1234.5, "unit": "%"}), "1,234.50%")
        self.assertEqual(report._fmt({"value": 1, "unit": "advisories"}), "1 advisory")

    def test_health_headline_leaves_out_a_category_rated_bad_by_its_threshold_setting(self):
        per = {"ALARM": "MAJOR", "LOSS": "HEALTHY", "LATENCY": "HEALTHY", "JITTER": "HEALTHY", "MOS": "MAJOR"}  # seteam: alarms open most hours too
        data = {"health:" + c: {"1.NE": HealthByCategoryTests.hours(s)} for c, s in per.items()}
        data["health:ALARM"]["1.NE"][:12] = HealthByCategoryTests.hours("HEALTHY", 12)
        m = report.compute(phase2_bundle("noc", **data))
        head = m["metrics"]["health_good_24h_pct"]
        self.assertEqual((head["value"], head["status"]), (50.0, "red"))  # the open alarms still count; MOS does not
        self.assertIn("MOS left out", head["label"])
        self.assertEqual(m["metrics"]["health_mos_good_24h_pct"]["value"], 0.0)  # still shown in its own row

    def test_paths_without_loss_data_are_no_data_and_every_graded_row_says_why(self):
        paths = {"a": {"1.NE": self.path("to_a", 0, 0)}, "b": {"1.NE": self.path("to_b", 50000, 0, mos=127)}, "c": {"1.NE": self.path("to_c", 50000, 0)}}
        m = report.compute(phase2_bundle("paths", health_threshold=THRESHOLDS, **{"paths:1.NE": paths}))
        rows = {r["tunnel"]: r for r in m["sections"]["paths-ranked"]["table"]}
        self.assertEqual(rows["to_a"]["status"], "grey")
        self.assertEqual(rows["to_b"]["why"], "MOS 1.27")
        self.assertEqual(rows["to_c"]["why"], "")
        self.assertEqual(m["metrics"]["paths_ok_pct"]["value"], 50.0)  # of the 2 rows with data, not of 3
        self.assertEqual(m["metrics"]["paths_no_data"]["value"], 1)

    def test_watch_list_says_no_data_not_none(self):
        sections = {"paths-ranked": {"table": [{"appliance": "x", "tunnel": "t", "loss_pct": None, "latency_ms": 30.0, "status": "amber"}]}}
        rows = report._watch_list({"metric": lambda *a, **k: a[0]}, sections)["table"]
        self.assertEqual(rows[0]["detail"], "loss no data, latency 30 ms")

    def test_noc_alarms_oldest_first_within_severity_and_overlays_before_underlay(self):
        alarms = [{"applianceId": "1.NE", "severity": "CRITICAL", "timeOccurredInMills": t} for t in (3 * 10 ** 12, 1 * 10 ** 12)]
        tunnels = {"1.NE": {"p": {"alias": "phys", "operStatus": "Down"}}}
        m = report.compute(phase2_bundle("noc", active_alarms=alarms, tunnels_physical=tunnels, tunnels_bonded={"1.NE": {"b": {"alias": "bond", "operStatus": "Down - In progress"}}}))
        since = [r["since"] for r in m["sections"]["noc-alarms"]["table"]]
        self.assertEqual(since, sorted(since))
        self.assertEqual([r["kind"] for r in m["sections"]["noc-tunnels"]["table"]], ["bonded", "physical"])
        self.assertIn("Down - In progress", " ".join(m["sections"]["noc-tunnels"]["notes"]))

    def test_a_zone_pair_whose_every_flow_is_dropped_is_a_warning(self):
        rows = [{"nePk": "1.NE", "fromZone": "3", "toZone": "0", "flows_allowed": 0, "flows_dropped": 50},
                {"nePk": "1.NE", "fromZone": "3", "toZone": "3", "flows_allowed": 90, "flows_dropped": 10}]
        m = report.compute(phase2_bundle("security", zones={"3": {"name": "TRUSTED"}}, **{"security:1.NE": rows}))
        sec = m["sections"]["sec-pairs"]
        self.assertEqual(sec["status"], "amber")
        self.assertEqual([(r["to_zone"], r["status"]) for r in sec["table"]], [("Default (zone 0)", "amber"), ("TRUSTED", "green")])
        self.assertNotIn("nothing needs attention", report.render(m))

    def test_activity_alarm_types_take_the_worst_severity_and_changes_show_a_failure_rate(self):
        audit = [{"user": "u", "name": "Push", "nepk": "1.NE", "queuedTime": 1, "completionStatus": False}, {"user": "u", "name": "Push", "nepk": "1.NE", "queuedTime": 2, "completionStatus": True}]
        m = report.compute(phase2_bundle("activity", activity_audit=audit, activity_alarms=[{"applianceId": "1.NE", "severity": "CRITICAL", "name": "Disk"}]))
        self.assertEqual(m["sections"]["act-alarms"]["status"], "red")
        self.assertEqual(m["sections"]["act-changes"]["table"][0]["failed_pct"], 50.0)
        self.assertIn("pairs", m["metrics"]["act_repeat"]["label"])

    def test_incident_shows_critical_alarms_first_and_failed_changes_are_a_warning(self):
        alarms = [{"id": 1, "applianceId": "1.NE", "severity": "WARNING", "timeOccurredInMills": T0 + 1000, "clearedTimeInMills": T0 + 61000},
                  {"id": 2, "applianceId": "1.NE", "severity": "CRITICAL", "timeOccurredInMills": T0 + 5000}]
        audit = [{"queuedTime": T0 + 10, "name": "Apply template", "nepk": "1.NE", "user": "u", "completionStatus": False}]
        b = bundle(incident={"from_ms": T0, "to_ms": T0 + 3600000, "affected": ["1.NE"]}, incident_alarms_stored=True, incident_alarms=alarms, incident_audit=audit)
        b["report"] = "incident"
        m = report.compute(b)
        self.assertEqual([r["severity"] for r in m["sections"]["inc-timeline"]["table"]], ["critical", "warning"])
        self.assertEqual(m["sections"]["inc-changes"]["status"], "amber")
        self.assertEqual(m["sections"]["inc-appliances"]["table"][0]["status"], "red")  # a critical alarm on it, whatever its reachability
        self.assertIn("cleared alarms only", m["metrics"]["inc_median_clear_min"]["label"])
        self.assertNotIn("--scope", " ".join(m["sections"]["inc-appliances"]["notes"]))

    def test_boost_columns_are_words_not_api_fields(self):
        boost = [{"configured": 25000.0, "nePk": "1.NE", "MAX_TIMESTAMP": NOW, "MIN_TIMESTAMP": NOW - 86400, "boost": 0, "boost_bytes": 2000.0, "seconds_not_boosted": 5}]
        row = report.compute(phase2_bundle("optimisation", **{"boost:1.NE": boost}))["sections"]["opt-boost"]["table"][0]
        self.assertEqual(list(row), ["appliance", "boost_configured_kbps", "boosted_bytes", "seconds_not_boosted"])

    def test_capacity_notes_say_what_the_order_is(self):
        m = report.compute(phase2_bundle("capacity"))
        notes = " ".join(m["sections"]["cap-links"]["notes"] + m["sections"]["cap-qos"]["notes"])
        self.assertNotIn("ranked by average", notes)
        self.assertNotIn("Direction 0", notes)

    def test_lifecycle_rows_carry_a_status_and_old_trains_come_first(self):
        backups = {"backup:1.NE": [{"backupTime": NOW - 40 * 86400}], "backup:2.NE": [{"backupTime": NOW - 86400}]}
        m = report.compute(phase2_bundle("lifecycle", gms_license={"daysToExpiration": 500}, portal_appliances={"data": []}, **backups))
        self.assertEqual([(r["appliance"], r["status"]) for r in m["sections"]["life-backups"]["table"]], [("branch-a", "amber"), ("branch-b<script>", "green")])
        self.assertEqual([r["ecos"] for r in m["sections"]["life-inventory"]["table"]], ["9.6.2.1_1", "9.7.1.0_1"])
        self.assertIn("appliance licence expiry is not checked", " ".join(m["sections"]["data-gaps"]["notes"]))

    def test_report_period_is_dates_and_noc_options_do_not_name_an_unused_period(self):
        b = phase2_bundle("security")
        b["period"].update(month="last-7-days", from_ms=(NOW - 7 * 86400) * 1000, to_ms=NOW * 1000)
        page = report.render(report.compute(b))
        self.assertIn("2026-09-14 to 2026-09-21 UTC", page)
        self.assertNotIn("period: last-month", report.options_line(report.compute(phase2_bundle("noc"))))

    def test_percent_line_chart_stops_at_100(self):
        svg = layout.line("loss", [["p", [["a", 99.9], ["b", 60.0]]]], "%")
        self.assertNotIn(">125<", svg)
        self.assertIn(">100<", svg)


if __name__ == "__main__":
    unittest.main()
