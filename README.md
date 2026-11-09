# edgeconnect-mcp

[![test](https://github.com/mirwasay/edgeconnect-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/mirwasay/edgeconnect-mcp/actions/workflows/test.yml)
[![release](https://img.shields.io/github/v/release/mirwasay/edgeconnect-mcp)](https://github.com/mirwasay/edgeconnect-mcp/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![python](https://img.shields.io/badge/python-3.9%2B-blue)](pyproject.toml)

**Let Claude, or any other MCP client, read and safely change an HPE Aruba EdgeConnect SD-WAN Orchestrator through its REST API.**

![Claude Code answers three questions through edgeconnect-mcp: which appliances are unreachable, a report on flows for the last 24 hours, and all YouTube traffic flows, listing the API calls it made for each](docs/demo.gif)

<sub>A real Claude Code session against Orchestrator 9.7.1 through edgeconnect-mcp v0.2.1, reads only. Claude's answers are shown as given.</sub>

You ask in plain language ("which appliances on the lab are unreachable?") instead of clicking through the Orchestrator UI or hand-writing REST calls. The assistant finds the right one of the Orchestrator's ~1,200 API operations and calls it. MCP (Model Context Protocol) is the standard way AI assistants call external tools; this server gives them six generic tools that cover the whole REST API on 9.7 / 10.0, by reading the API spec the Orchestrator itself serves.

- **Read-only unless you opt in**, per Orchestrator, with a blocklist of high-risk writes on top, and every write needs a second, confirmed call.
- **Secrets never reach the assistant.** Keys, passwords, PSKs and SNMP community strings come back redacted and are restored only when written back to where they came from.
- **Every call is audited** to a local JSON-lines log, and optionally to syslog and SQLite.
- **No dependencies.** Pure Python 3.9+ standard library. Runs over stdio, locally, over SSH or in a container, or as an HTTP endpoint behind an HTTPS proxy.
- **Current MCP spec.** Speaks MCP 2026-07-28 (stateless, `server/discover`) and still answers older clients that open with `initialize` (2025-11-25 back to 2024-11-05).
- **Comes with a guide skill** that tells the assistant which official docs and tested operations to use for each feature, and a **report skill** that turns Orchestrator data into one of 15 reports, from a monthly availability report and a NOC digest to path quality, WAN traffic and an executive summary (one HTML file; code computes every number).
- **Tested on a real Orchestrator.** Run end to end against Orchestrator 9.7.1 with five EC-V appliances (ECOS 9.6 and 9.7), including two-step writes, the audit outputs and HTTPS through Caddy and Nginx Proxy Manager.

> Independent project, not affiliated with or supported by HPE. Provided as is, without warranty: you are responsible for every change made through it, by you or by an assistant you connect. See [NOTICE](NOTICE).

It reads the same `.env` format as [edgeconnect-orchestrator-automation](https://github.com/mirwasay/edgeconnect-orchestrator-automation), so one `.env` can serve both. For bulk firewall and object changes, use that project's CSV workflows instead: they add drift checks, readback and rollback that raw `api_write` calls do not.

## Tools

| Tool | What it does |
|---|---|
| `list_orchestrators` | Configured nicknames and hosts, and per Orchestrator whether writes, passthrough writes, two-step confirmation and the read-only POSTs (`read_posts_enabled`) are on. Never shows keys. |
| `find_operations` | Keyword search over the Orchestrator's own API spec. |
| `describe_operation` | Parameters and request-body schema for one operation. |
| `api_get` | Any documented GET. |
| `api_read_post` | Only the three read-only POST queries the API has no GET for: `/alarm/appliance` (appliance alarms), `/stats/aggregate/interface` (interface totals) and `/health` (hourly health). Allowed with writes off, without confirmation, on the read rate limit, and audited as `POST`. Refused where `<nickname>_mcp_get_only=true`. |
| `api_write` | Any documented POST, PUT, PATCH or DELETE, only on Orchestrators with writes enabled. Refused where `<nickname>_mcp_get_only=true`, even with writes on. |

Paths are relative to `/gms/rest`, for example `/appliance` or `/gms/versions`. Responses are truncated to `max_chars` (default 60,000) so one call cannot flood the conversation.

## What a write looks like

With writes enabled, the first `api_write` call changes nothing. This is the server's reply, copied from the 2026-10-19 run on the 9.7.1 lab (only the Orchestrator nickname is changed):

```json
{
  "status": "confirmation_required",
  "confirmation": "dde95bf9cb793cbf",
  "expires_in_seconds": 600,
  "change": {
    "method": "POST",
    "path": "/ipObjects/addressGroup",
    "query": null,
    "body": {
      "name": "ztest_ag_live",
      "type": "AG",
      "rules": [{"includedIPs": ["198.51.100.0/24"], "excludedIPs": [], "includedGroups": [], "comment": "ztest live two-step"}]
    },
    "orchestrator": "lab",
    "operation": "Create or update an ACL address group"
  },
  "next": "Nothing was sent. Show the user this exact change. Only after they approve, call api_write again with the same orchestrator, method, path, query and body, plus confirmation set to this code. Any difference needs a new code."
}
```

The assistant shows you that change. Only after your yes does it repeat the call with the code, and only then does the Orchestrator receive it. Reads come back with secrets already replaced: in the same run, `GET /appliance` returned each appliance's password as `"<REDACTED:…>"`.

## The EdgeConnect toolkit

**Install this server** and its two skills (macOS and Linux; needs git, Python 3.9 or later and, for the skills and adding the MCP server to agents, Node.js 18 or later):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mirwasay/edgeconnect-mcp/main/install.sh)
```

**Install all three** instead (the `edgeconnect-auto` CLI, the `edgeconnect-preconfig` command, this server and their skills): `install-all.sh` asks which repositories to install. The same file is in all three repositories, and `install.sh` is `install-all.sh` with this repository already picked.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mirwasay/edgeconnect-mcp/main/install-all.sh)
```

Three repositories that work together:

| Repository | What it does | Agent skill |
|---|---|---|
| [edgeconnect-orchestrator-automation](https://github.com/mirwasay/edgeconnect-orchestrator-automation) | `edgeconnect-auto` CLI: deploys and removes firewall policies, zones, address, service and application groups, application definitions and template-group ACLs from reviewed CSVs, with a dry run, a typed `APPLY` and readback verification. | `managing-edgeconnect-firewall-and-objects` |
| [edgeconnect-preconfig](https://github.com/mirwasay/edgeconnect-preconfig) | `edgeconnect-preconfig` command: turns an existing appliance into a Jinja2 + CSV preconfiguration template, then builds, validates and, with `upload --approve`, uploads one preconfig per site. | `building-edgeconnect-preconfig-templates` |
| [edgeconnect-mcp](https://github.com/mirwasay/edgeconnect-mcp) (this repository) | MCP server that lets Claude or any MCP client read, and with your approval change, an Orchestrator through its REST API, plus the `edgeconnect-mcp report` command. | `edgeconnect-guide`, `edgeconnect-report` |

Run either script again to update. `install-all.sh` asks a few questions, then does everything else:

1. **Which repositories**: a table of the three, with what each does and the skill it installs; type numbers separated by commas (for example `1,3`) or `all` (the default).
2. **The MCP server** (only if you pick 3): run it locally (stdio) for your agents, or in Docker over HTTPS, which you install by hand with the [MCP install guide](https://github.com/mirwasay/edgeconnect-mcp/blob/main/docs/install.md), or not at all.
3. **Which agents**, once, from a table of 20 (Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, OpenCode, Kilo Code, Kiro CLI, Zed, Windsurf, Cline, Goose, Antigravity, Devin, Roo Code, Continue, Amp, Claude Desktop, and any agent that reads `.agents/skills`). Every picked skill is installed for them, also when it was already installed, and the local MCP server is added to them: through [`add-mcp`](https://www.npmjs.com/package/add-mcp) (without auto-approving tool calls), through `devin mcp add` for Devin, or as a printed config to paste for agents neither covers. Before adding the server it asks to continue, because an existing server named `edgeconnect` in those agents is replaced; with `--yes` it adds the server only when you also pass `--mcp stdio`. It prints each agent's MCP settings file as it goes.
4. **The install folder** (default: `$EDGECONNECT_HOME` if set, else the folder you run it from, or `~/edgeconnect` from your home folder).
5. **Where the skills and the MCP server go**, one answer for both: only that folder (the default) or your user account (`~`). Agents that keep MCP servers only for the whole user account (Windsurf, Cline, Goose, Antigravity, Claude Desktop) are asked about one by one when you chose the folder: yes adds the server user-wide for that agent, no skips it. With `--yes` they are skipped, and the last screen lists the command to add each one.

Everything lands in the one folder, from `main`: the repositories, for 1 and 2 a Python environment and the `edgeconnect-auto` (1) and `edgeconnect-preconfig` (2) commands in `~/.local/bin`, for a local MCP server its launcher `<folder>/bin/edgeconnect-mcp`, and one shared `.env`. The last screen shows how to fill in `.env` for what you picked: the Orchestrator lines, the API key, a self-signed certificate, `EC_VALIDATORS` for preconfig and MCP writes. It also writes `AGENTS.md` (which tool an agent should use for which task, and what this folder has installed) and a `CLAUDE.md` that points to it, so start your agent there; an `AGENTS.md` that the installer wrote and you never edited is kept up to date on every run, and one you have edited is never overwritten (the new text goes to `AGENTS.md.new`). Run it again to update. Options for answering without prompts: `--repos 1,3` (or `all`), `--mcp stdio|docker|no`, `--agents 1,2,15` (numbers or names such as `claude-code,codex`), `--dir PATH`, `--skills folder|home`, `--yes`.

Picking 3 in `install-all.sh` (or running this repository's `install.sh`) installs both of this repository's skills, `edgeconnect-guide` and `edgeconnect-report` (it installs every folder under `skills/`), and, if you choose local, the stdio server for your agents; a Docker server is installed by hand, as [Install](#install) below covers. Its launcher `<folder>/bin/edgeconnect-mcp` also runs the reports: `<folder>/bin/edgeconnect-mcp report ...`.

## Install

You need Python 3.9 or later (Linux, macOS or Windows) and an Orchestrator REST API key. HPE's [API Key](https://arubanetworking.hpe.com/techdocs/sdwan/docs/orch/orchestrator/server/api-key/) page shows how to create one; give it Read-Only permission unless you plan to turn writes on. The `npx` commands need Node.js 18 or later.

### 1. Add your Orchestrator

```bash
curl -fsSL --create-dirs -o ~/.edgeconnect-mcp/.env https://raw.githubusercontent.com/mirwasay/edgeconnect-mcp/main/.env.example
chmod 600 ~/.edgeconnect-mcp/.env
```

Open `~/.edgeconnect-mcp/.env` and replace the two placeholders. That is all the server needs; the rest of the file is optional and explained in [Configuration](#configuration).

```dotenv
orch_1=lab
lab_base_url=https://<ORCHESTRATOR_FQDN_OR_IP>
lab_api_key=<API_KEY>
```

On Windows, save [.env.example](.env.example) as `%USERPROFILE%\.edgeconnect-mcp\.env` instead.

### 2. Install

**Claude Code** gets the server and both skills in one go:

```bash
claude plugin marketplace add mirwasay/edgeconnect-mcp && claude plugin install edgeconnect@edgeconnect-mcp
```

**Any other MCP client** (Claude Desktop, Codex, OpenCode, VS Code, Cursor, Windsurf, Devin): the server command is

```bash
npx -y github:mirwasay/edgeconnect-mcp
```

[docs/clients.md](docs/clients.md) has the ready-made config for each client. Then add the [guide](#guide-skill) and [report](#report-skill) skills; it asks which agents to add them to:

```bash
npx skills add mirwasay/edgeconnect-mcp
```

### 3. Check it

Restart your client and ask "list my EdgeConnect orchestrators". That calls `list_orchestrators`, which needs no network, and should return this, with your address as `host`:

```json
[{"name": "lab", "host": "192.0.2.10", "writes_enabled": false, "passthrough_writes_enabled": false,
  "write_confirmation": true, "read_posts_enabled": true, "high_risk_allowed": [], "default": true}]
```

Then ask "show the appliances on lab". That one reaches the Orchestrator, so a wrong address, key or certificate shows up there.

The [install guide](docs/install.md) walks through every route the same way, step by step: plugin, npx, uvx, pipx, a clone and Docker, each with its skills command, the report command for each route, plus updating and pinning a release. These commands install the latest code on `main`, which only changes through pull requests that pass CI.

## Guide skill

`skills/edgeconnect-guide/` is a skill that tells an assistant where to look before it calls these tools. It is an index, not a copy of the docs:

- **Cards:** for each feature, a card with the official doc pages, a few key facts and the operations that touch it.
- **Playbooks:** for common jobs, such as adding a BGP neighbor or a segment, a playbook that reads current state before writing and says how to roll back.

The playbooks are for reference only. Every operation the skill names passed in a real run on Orchestrator 9.7.1 between 2026-10-16 and 2026-10-20 (listed in `tested-operations.tsv`). Steps that could not be tested were left out, or point to the Orchestrator UI.

## Report skill

`skills/edgeconnect-report/` builds 15 reports, all with the same layout: a headline with an overall status, a verdict naming the areas that need attention, headline figures, then numbered sections with key points, possible causes, recommended actions and a table.

| Report | For | What it covers |
|---|---|---|
| `availability` | service owner | monthly service level: appliance reachability, tunnel and interface availability, transports, path quality |
| `noc` | NOC on shift | what is broken now: unreachable appliances, active alarms, health, tunnels down, sites needing attention (last 24 hours and 7 days) |
| `capacity` | network planner | WAN links by P95 utilisation against a planning limit |
| `lifecycle` | platform owner | software versions, licences, backups and known security advisories |
| `incident` | incident lead | one window of at most 7 days: alarms, affected sites, and changes in it and the 24 hours before (from the audit log, `GET /action`) |
| `executive` | management | a one-page summary across the other reports |
| `traffic` | network engineer | what uses the WAN: change against the previous period, applications by share, top talkers, domains, countries, ports and traffic classes |
| `paths` | network engineer | every active path ranked worst first, loss hidden by FEC, transports compared, worst paths by hour |
| `operations` | team lead | weekly summary: appliance state, active alarms, health by category, tunnels down, worst paths, busiest WAN links, one list of recommended actions |
| `optimisation` | network engineer | data reduction by appliance (optimised traffic: LAN bytes against WAN bytes) |
| `security` | security team | every zone pair with flows allowed and dropped, policy and routing drops |
| `activity` | change manager | changes from the audit log, alarms by type, repeating alarms, alarms within an hour of a change |
| `site` | site owner | one appliance: state, alarms, health, tunnels, paths, WAN links, traffic and changes (needs `--scope` with one appliance) |
| `custom` | anyone | the sections you pick (needs `--parts`) |
| `health` | NOC | daily health check: NOC sections, every path, the day's changes and alarms, and a watch list of what is degraded but not yet failed |

<p>
<img src="docs/images/report-executive-light.png" alt="Executive summary report: overall Critical status, seven areas needing attention, headline figures for appliance reachability, path quality, WAN traffic, utilisation, alarms and licence expiry" width="49%">
<img src="docs/images/report-noc-dark.png" alt="NOC digest in the dark theme: unreachable appliances, active critical and major alarms, tunnels down and sites needing attention" width="49%">
</p>
<p>
<img src="docs/images/report-paths-table-light.png" alt="Path quality report table ranking every active tunnel worst first, with loss before and after FEC, latency, jitter, MOS, status and the reason" width="69%">
<img src="docs/images/report-executive-light-phone.png" alt="Executive summary on a phone-width screen" width="29%">
</p>

<sub>Rendered from a real Orchestrator 10.0 with 66 appliances. Appliance, site, user and Orchestrator names and IP addresses were replaced before rendering.</sub>

Code does the reading and the maths; the assistant only writes the prose, and a validator rejects prose that types a number or contradicts a computed status. A consistency check (`report.consistency`, run by the tests on every report) makes sure no two places on one page disagree: the verdict names exactly the sections flagged in the index, every count matches its table, every total matches the sum of its rows (or shows no data when a part is missing), and no missing data is shown as Good:

```bash
edgeconnect-mcp report collect --orchestrator lab --report availability --period last-month --out rep
edgeconnect-mcp report compute rep/bundle.json        # writes rep/metrics.json
edgeconnect-mcp report template rep/metrics.json      # sections, statuses and metric ids for the prose
edgeconnect-mcp report validate rep/metrics.json rep/narrative.json
edgeconnect-mcp report render rep/metrics.json rep/narrative.json --out rep/report.html
```

`collect` takes only these options:

| Option | Values |
|---|---|
| `--report` | `availability`, `noc`, `capacity`, `lifecycle`, `incident`, `executive`, `traffic`, `paths`, `operations`, `optimisation`, `security`, `activity`, `site` (needs `--scope` with one appliance), `custom` (needs `--parts`), `health` |
| `--traffic-type` | traffic: `all_traffic` (default), `optimized_traffic`, `pass_through_shaped`, `pass_through_unshaped` |
| `--overlay` | paths: one overlay id (default: every overlay) |
| `--threshold` | capacity: planning limit in % (default: the Orchestrator's bwUtilization limits) |
| `--period` | `last-month` (default) or `month-to-date`; or `--month YYYY-MM`; for `traffic`, `paths`, `operations`, `optimisation`, `security` and `activity`, `last-7-days` (their default) or `last-24-hours` |
| `--scope` | `all` (default), or comma-separated nePks or host names |
| `--target` | `orchestrator` (default: its configured thresholds), `99.5`, `99.9` or `99.99` |
| `--down-tunnels` | `separate` (default: listed apart and left out of the figures) or `include` |
| `--top` | capacity: only the N busiest WAN links get an hourly P95 read (default: every link) |
| `--from`, `--to` or `--alarm-id` | incident only, and required for it: an ISO window (UTC unless it says otherwise), or one alarm |
| `--history` | the alarm archive (default `~/.edgeconnect-mcp/history`) |
| `--dotenv` | the settings file (default `$EDGECONNECT_DOTENV`, else `~/.edgeconnect-mcp/.env`, else `./.env`) |

`collect` uses the server's own code and `.env`, so the allowlist, redaction, rate limits, audit log and `get_only` apply; on a GET-only Orchestrator it uses GET alternatives and lists what it could not fetch. `render` checks the narrative again and refuses one that fails. The HTML is one file with inline CSS and SVG, no scripts, and prints on A4. Security advisories have no API, so they come from a dated list in `src/edgeconnect_mcp/advisories.py`, and the report says how old it is.

The Orchestrator keeps 7 days of alarms. `edgeconnect-mcp report store --orchestrator lab` keeps them longer, in `~/.edgeconnect-mcp/history/<nickname>/` (or `--history PATH`), for the availability and incident reports. Only alarms are stored: stats are read live, and the Orchestrator's audit log is not stored (a busy one logs thousands of entries an hour); for a full audit trail, send it to a remote log receiver. Nothing is scheduled for you: run `store` daily from cron or launchd.

`report` comes first, or right after `--dotenv <file>`, which `collect` and `store` then use (that is how the installer's `<folder>/bin/edgeconnect-mcp report ...` works). Where `edgeconnect-mcp` is not on PATH, use `npx -y github:mirwasay/edgeconnect-mcp report ...`, or in a clone `PYTHONPATH=src python3 -m edgeconnect_mcp report ...`.

## Safety model

- **Read-only by default.** `api_write` is refused unless `.env` has `<nickname>_mcp_writes=true` for that Orchestrator. Turn it on only for lab Orchestrators, or deliberately.
- **Three read-only POSTs, and nothing else.** `api_read_post` accepts exactly `POST /alarm/appliance`, `POST /stats/aggregate/interface` and `POST /health` (the `READ_POSTS` list in `server.py`); every other POST stays a write. They need no write settings and no confirmation, count against the read rate limit, and are audited with method `POST`. `<nickname>_mcp_get_only=true` turns them off for an Orchestrator; `list_orchestrators` shows this as `read_posts_enabled`.
- **GET-only means GET-only.** `<nickname>_mcp_get_only=true` also refuses every `api_write`, even with `<nickname>_mcp_writes=true`, so only GETs reach that Orchestrator; `list_orchestrators` then shows `writes_enabled` and `passthrough_writes_enabled` false.
- **Raw passthroughs need a second opt-in.** `/appliance/rest` and `/broadcastCli` forward any request to an appliance's own API or CLI, so the spec cannot limit what they change. Writes through them also need `<nickname>_mcp_passthrough=true`.
- **Spec allowlist.** Every call must match a method and path in the spec the Orchestrator serves (`/gms/rest/apiDocs`, the same one Support > REST APIs shows). Undocumented paths, `..`, encoded separators and anything that would leave `/gms/rest` are rejected.
- **Separate read and write tools.** `api_write` is marked destructive, so MCP clients ask before each call; reads can be auto-approved.
- **Two-step writes, on by default.** The first `api_write` call sends nothing: it returns the exact change and a one-time code. The assistant shows you the change and, only after your yes, repeats the identical call with the code. A code works once, for 10 minutes, for that exact request and for the client it was issued to. Set `<nickname>_mcp_confirm_writes=false` to turn it off for an Orchestrator, for example for trusted unattended automation.
- **High-risk blocklist.** Even with writes on, whole categories of dangerous writes are refused. See [below](#high-risk-blocklist).
- **Secret redaction.** API keys are only sent as the `X-Auth-Token` header, and secrets in responses are replaced with restorable tokens. See [below](#secret-redaction).
- **Rate limits per Orchestrator.** Reads (GETs and the three read-only POSTs) default to 10 per second and writes to 2 per second, each with a burst of twice that. Over the limit, calls wait rather than fail, so scripts slow down instead of breaking.
- **Audit trail.** Every tool call is appended as one JSON line to `~/.edgeconnect-mcp/audit.jsonl` (file 0600, folder 0700).
  - Each record has the UTC timestamp and weekday, session and call id, client address, tool, Orchestrator, method, path, what the operation does (its API summary), redacted query, outcome, error, duration and response size. Writes also record the step (`awaiting_confirmation`, `confirmed` or `executed`) and the request body; `api_read_post` calls record method `POST` and their body. The reads `report collect` and `report store` make go to the same log.
  - Secrets never reach it: bodies hold `<REDACTED:…>` tokens, and anything typed in clear under a secret-named key is masked.
  - Optionally the same records also go to a syslog server (`mcp_audit_syslog`) and a SQLite database (`mcp_audit_sqlite`).
  - In HTTP mode, requests turned away for a wrong token, client address or origin are logged too (`tool` is `http_refused`, with the client address, the proxy it came through as `peer`, and the reason, such as `missing access token` or `wrong access token`; never the token).
  - Every write is also logged to stderr (the MCP client's server log).
- **Untrusted results.** API results carry a note that their text is data, not instructions, and the server instructions say the same. Invisible and direction-changing characters (zero-width, bidi overrides, Unicode tag characters) are shown as `\uXXXX` JSON escapes, so hidden text is visible while the value still decodes exactly.
- **Strict TLS.** Certificates are verified and redirects are refused, so the API key can't follow a redirect to another host or to plain HTTP. A self-signed lab Orchestrator is supported by pinning its certificate (`<nickname>_tls_sha256`) or trusting a private CA (`<nickname>_ca_bundle`), never by turning verification off.
- **No network listener by default.** The server uses stdio unless you pass `--http`. HTTP listens on 127.0.0.1 unless `mcp_http_listen` says otherwise (the container image sets 0.0.0.0). Every request needs the token and is checked against the address allowlist on its own; requests run in parallel, up to 8 at once, and more get a 503 to retry.

### High-risk blocklist

These writes are refused unless `<nickname>_mcp_allow_high_risk` names their category (comma-separated, or `all`):

| Category | Covers |
|---|---|
| `auth` | Users, roles, RBAC, remote auth (TACACS, RADIUS, JWT), API keys, sessions |
| `certificates` | Certs, SSL/TLS, ciphers, EST and end-entity profiles, HTTPS |
| `licensing` | Licensing |
| `backup_restore` | Backup and restore |
| `upgrade` | Upgrades, ECOS image management |
| `reboot` | Reboot, shutdown, restart, factory reset |
| `orchestrator_ha` | Orchestrator HA, including failover |
| `appliance_lifecycle` | Add, delete, approve/deny/revoke, change password, EdgeHA, hostname, SSE connector, passthrough DELETE |
| `cloud_deployment` | AWS, Azure and GCP resources |
| `provisioning` | Preconfiguration apply, appliance and RMA wizards, ZTP, portal and support-case calls, registration, account keys |
| `orchestrator_admin` | Session timeout, REST API config, advanced properties and settings, SMTP and email actions, host OS settings, debug files, DB partitions |
| `identity_events` | ClearPass login/logout events |
| `cli` | `broadcastCli`, tcpdump, shell |
| `ip_allowlist` | IP allowlist |
| `traffic_disruptive` | Network memory erase, flow reset, DHCP config reset |

Punctuation is ignored when matching (`edge-ha` = `edgeha`), and passthrough writes are also checked against their `url`. Plain lookups stay allowed in the certificate, licensing, upgrade, auth and backup areas: an operation whose last path segment starts with a lookup word such as `validate`, `check`, `parse`, `verify`, `lookup`, `list`, `get`, `preview` or `test` (or ends in `connectivity`), or one whose summary starts with validate, verify, check, parse, test connect or get. In the provisioning area only the path name counts.

To see exactly what the list refuses on one Orchestrator:

```bash
npx -y github:mirwasay/edgeconnect-mcp --list-high-risk lab
```

### Secret redaction

String values under keys such as `apiKey`, `password`, `token`, `presharedKey`, `authKey`, `privateKey`, `accountKey`, `licenseKey` and `rocommunity`, and any PEM private key, come back as `<REDACTED:…>` tokens. Redaction goes by field name. The names were checked against every property in the 9.7.1 API spec that is described as a password, secret, key, community string or credential; a test covers a list of them, but it does not read the spec itself, so a field added in a later release can slip through. Flags and numbers (`passwordMinLen`, `csrfProtection`) stay readable.

Write a token back unchanged and the server puts the real value in, so read-modify-write of BGP, OSPF, overlays or tunnels round-trips exactly. A token is only restored under the same key it was read from, on the same API path or a parent or child of it (for appliance passthrough, the same `url`), on the same Orchestrator, during the same server run. Anything else is refused: a plain `<REDACTED>`, a token moved into a readable field or another feature's secret field, or a token from another Orchestrator or an earlier run. So a secret can never be overwritten with a placeholder or copied somewhere it could leak.

## Configuration

All settings live in `.env` ([`.env.example`](.env.example) has every key). Never commit it. Each Orchestrator gets a numbered slot and a nickname, and the nickname prefixes its settings:

```dotenv
orch_1=lab
lab_base_url=https://192.0.2.10
lab_api_key=<API_KEY>
lab_mcp_writes=true
lab_tls_sha256=<SHA-256 fingerprint>
```

| Key | Default | Meaning |
|---|---|---|
| `orch_<n>` | | Nickname for Orchestrator slot `n` |
| `<nickname>_base_url` | | `https://` address of the Orchestrator |
| `<nickname>_api_key` | | REST API key |
| `<nickname>_api_key_header` | `X-Auth-Token` | Header the key is sent in |
| `<nickname>_tls_sha256` | | Pin a self-signed certificate by its SHA-256 fingerprint |
| `<nickname>_ca_bundle` | | Private CA file for certificate verification |
| `<nickname>_mcp_writes` | off | `true` allows `api_write` |
| `<nickname>_mcp_passthrough` | off | `true` also allows writes through `/appliance/rest` and `/broadcastCli` |
| `<nickname>_mcp_confirm_writes` | on | `false` turns off two-step writes for that Orchestrator |
| `<nickname>_mcp_get_only` | off | `true` refuses `api_read_post` and `api_write` (even with `_mcp_writes=true`), so only GETs reach that Orchestrator (for keys that must only see GETs) |
| `<nickname>_mcp_allow_high_risk` | none | Blocklist categories to allow, comma-separated, or `all` |
| `<nickname>_mcp_read_rate` | `10` | Reads per second, `0` = no limit |
| `<nickname>_mcp_write_rate` | `2` | Writes per second, `0` = no limit |
| `<nickname>_openapi` | download | Path to a saved `apiDocs.json` instead of downloading the spec on first use |
| `orch_default` | | Orchestrator used when a tool call names none |
| `mcp_audit_log` | `~/.edgeconnect-mcp/audit.jsonl` | Audit log path, or `off` |
| `mcp_audit_syslog` | none | Also send audit records to syslog: `/dev/log`, `udp://host:514` or `tcp://host:514` |
| `mcp_audit_sqlite` | none | Also write audit records to this SQLite database |

HTTP mode has its own keys (`mcp_http_token`, `mcp_http_allowed_clients`, `mcp_http_trusted_proxies`, `mcp_http_listen` and more); see [docs/remote-access.md](docs/remote-access.md#http-mode).

Get a certificate fingerprint to pin (check it on the Orchestrator console or another trusted path first):

```bash
openssl s_client -connect 192.0.2.10:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

## Remote access

Plain HTTP never crosses the network. [docs/remote-access.md](docs/remote-access.md) covers:

- **Over SSH:** the client starts the server over SSH, with one locked-down key per access level.
- **HTTP mode:** a token, a client allowlist and trusted proxies, all set in `.env`.
- **Caddy:** HTTPS in front of a server running directly on the machine.
- **Container:** stdio with `docker run -i`, or HTTP mode with `compose.yaml` published on the host's 127.0.0.1.
- **Nginx Proxy Manager:** HTTPS in front of the server container, on a shared Docker network.

## Orchestrator API notes

Quirks found while driving a 9.7.1 Orchestrator through this server, such as which features have no Orchestrator write operation and which writes replace a whole collection, are in [docs/api-notes.md](docs/api-notes.md).

## Development

Run the tests from the repository root (they use only the standard library):

```bash
.venv/bin/python -m unittest discover -s tests
```

The tests read `./.env` if one exists, so move your real `.env` out of the repository root first, or the run fails on its Orchestrators.

## Contributing

Bug reports, Orchestrator API quirks and fixes are welcome: open an [issue](https://github.com/mirwasay/edgeconnect-mcp/issues), or see [CONTRIBUTING.md](CONTRIBUTING.md) before sending a pull request.

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for the trademark and no-affiliation notice.
