#!/usr/bin/env bash
# Install or update the EdgeConnect toolkit from main (a re-run puts every clone on main), in one folder (macOS and Linux): you pick
# the repositories (the edgeconnect-auto CLI, the edgeconnect-preconfig CLI, the MCP server's guide and report skills) and each
# one's agent skill, plus, if you want it, the MCP server run locally (stdio) for the agents you
# choose. The same file ships in edgeconnect-orchestrator-automation, edgeconnect-preconfig and
# edgeconnect-mcp. A Docker (HTTPS) MCP server is installed by hand from the edgeconnect-mcp guide.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/mirwasay/edgeconnect-preconfig/main/install-all.sh)
#
# install.sh in each repository installs only that repository (this script with --repos fixed).
#
# Run it again to update: repositories are pulled, skills are reinstalled for the agents you choose,
# and .env, an edited AGENTS.md and commands it did not write are never overwritten.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install-all.sh [--repos LIST] [--mcp stdio|docker|no] [--agents LIST] [--dir PATH]
                [--skills home|folder] [--yes]

  --repos LIST       repositories to install, by number: 1,2,3 or "all" (default: all)
                     1) edgeconnect-orchestrator-automation  2) edgeconnect-preconfig
                     3) edgeconnect-mcp (guide and report skills, and the server if --mcp stdio)
  --mcp stdio        with 3: also run the MCP server locally for your agents (default)
  --mcp docker       with 3: you run it in Docker over HTTPS; print the install guide link
  --mcp no           with 3: the skills only
  --dir PATH         install folder (default: the current folder, or ~/edgeconnect when run
                     from your home folder, or $EDGECONNECT_HOME)
  --skills folder    1) skills and MCP server only in the install folder (default)
  --skills home      2) skills and MCP server for your user account (~), in every project
  --agents LIST      agents for the skills and the MCP server, asked once: numbers from the
                     agent table or names (claude-code,codex,cursor,...), comma-separated
                     (default: 1, Claude Code). Every picked skill is (re)installed for them.
  --yes              accept the defaults without asking
EOF
}

ROOT_GIVEN="${EDGECONNECT_HOME:-}"
PICK=""
MCP=""
MCP_EXPLICIT=0
SCOPE=""
AGENTS=""
ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repos) PICK="${2:?--repos needs a list such as 1,3 or all}"; shift 2 ;;
    --mcp) MCP="${2:?--mcp needs stdio, docker or no}"; MCP_EXPLICIT=1; shift 2 ;;
    --mcp-agents) AGENTS="${2:?--mcp-agents needs a list}"; shift 2 ;;  # 1.2.7 name, kept as an alias of --agents
    --dir) ROOT_GIVEN="${2:?--dir needs a path}"; shift 2 ;;
    --skills) SCOPE="${2:?--skills needs home or folder}"; shift 2 ;;
    --agents) AGENTS="${2:?--agents needs a list}"; shift 2 ;;
    --refresh-skills) shift ;;  # no longer needed: skills are always installed for the agents you choose
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

BIN="$HOME/.local/bin"
export NPM_CONFIG_UPDATE_NOTIFIER=false  # keep npx output to what this script prints
MARK="# edgeconnect setup.sh"  # kept as it was: it marks the commands this script wrote under its old name too

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
HAVE_TTY=0
{ : </dev/tty; } 2>/dev/null && HAVE_TTY=1
ask() {  # question, default -> answer (the default when --yes or no terminal)
  local answer=""
  if [ "$ASSUME_YES" -eq 0 ] && [ "$HAVE_TTY" -eq 1 ]; then
    printf '%s [%s]: ' "$1" "$2" >/dev/tty
    IFS= read -r answer </dev/tty || answer=""
  fi
  printf '%s' "${answer:-$2}"
}

if [ -z "$PICK" ] && [ "$ASSUME_YES" -eq 0 ] && [ "$HAVE_TTY" -eq 1 ]; then
  cat >/dev/tty <<'EOF'

Which repositories do you want to install?

+---+--------------------------------------------+-----------------------------+
| # | Repository                                 | What it does                |
+---+--------------------------------------------+-----------------------------+
| 1 | edgeconnect-orchestrator-automation        | edgeconnect-auto command:   |
|   |                                            | bulk firewall policies,     |
|   | Skill:                                     | address/service groups,     |
|   | managing-edgeconnect-firewall-and-objects  | application definitions     |
+---+--------------------------------------------+-----------------------------+
| 2 | edgeconnect-preconfig                      | edgeconnect-preconfig       |
|   |                                            | command: build a template   |
|   | Skill:                                     | and CSV from an appliance,  |
|   | building-edgeconnect-preconfig-templates   | validate, upload            |
+---+--------------------------------------------+-----------------------------+
| 3 | edgeconnect-mcp                            | Guide and report skills,    |
|   |                                            | and the MCP server if you   |
|   | Skills:                                    | want it: local (stdio)      |
|   | edgeconnect-guide, edgeconnect-report      | here, or Docker by hand     |
+---+--------------------------------------------+-----------------------------+

EOF
  PICK="$(ask 'Type numbers separated by commas (e.g. 1,3), or "all"' "all")"
fi
REPOS=""
set -f  # answers such as * must not expand to file names (until the agent answer is read)
for n in $(printf '%s' "${PICK:-all}" | tr 'A-Z,' 'a-z '); do
  case "$n" in
    all) names="edgeconnect-orchestrator-automation edgeconnect-preconfig edgeconnect-mcp" ;;
    1) names="edgeconnect-orchestrator-automation" ;;
    2) names="edgeconnect-preconfig" ;;
    3) names="edgeconnect-mcp" ;;
    *) die "choose numbers from 1 to 3 separated by commas, or all; not $n" ;;
  esac
  for name in $names; do
    case " $REPOS " in *" $name "*) ;; *) REPOS="${REPOS:+$REPOS }$name" ;; esac
  done
done
[ -n "$REPOS" ] || die "choose at least one repository"
picked() { case " $REPOS " in *" $1 "*) return 0 ;; esac; return 1; }
NEED_PYTHON=0
if picked edgeconnect-orchestrator-automation || picked edgeconnect-preconfig; then NEED_PYTHON=1; fi
echo "Installing: $REPOS"

MCP_GUIDE="https://github.com/mirwasay/edgeconnect-mcp/blob/main/docs/install.md"
MCP_MODE=no
if picked edgeconnect-mcp; then
  if [ -z "$MCP" ]; then
    if [ "$ASSUME_YES" -eq 0 ] && [ "$HAVE_TTY" -eq 1 ]; then
      printf '\nInstall the MCP server too?\n  1) Yes, local (stdio) for your agents   (default)\n  2) No, I run it in Docker over HTTPS\n  3) No\n' >/dev/tty
    fi
    MCP="$(ask "Choose 1, 2 or 3" "1")"
  fi
  case "$MCP" in
    1|stdio|local|yes) MCP_MODE=stdio ;;
    2|docker|https|http) MCP_MODE=docker ;;
    3|no|none) MCP_MODE=no ;;
    *) die "choose 1 (local stdio), 2 (Docker over HTTPS) or 3 (no), not $MCP" ;;
  esac
fi
if [ -n "$MCP" ] && ! picked edgeconnect-mcp; then
  case "$MCP" in 3|no|none) ;; *) die "--mcp $MCP needs repository 3 (edgeconnect-mcp) in the pick" ;; esac
fi

# One agent question for every skill and the MCP server. Columns: number|name|skills agent|MCP route|MCP agent
# MCP route: folder = add-mcp in this folder or user-wide; user = add-mcp user-wide only; devin = devin mcp add;
# paste = no installer, the config is printed; - = no MCP. Skills agent - = the agent has no skills.
AGENT_TABLE='1|Claude Code|claude-code|folder|claude-code
2|Codex|codex|folder|codex
3|Cursor|cursor|folder|cursor
4|GitHub Copilot in VS Code|github-copilot|folder|vscode
5|GitHub Copilot CLI|github-copilot|folder|github-copilot-cli
6|Gemini CLI|gemini-cli|folder|gemini-cli
7|OpenCode|opencode|folder|opencode
8|Kilo Code|kilo|folder|kilo-code
9|Kiro CLI|kiro-cli|folder|kiro-cli
10|Zed|zed|folder|zed
11|Windsurf|windsurf|user|windsurf
12|Cline|cline|user|cline
13|Goose|goose|user|goose
14|Antigravity|antigravity|user|antigravity
15|Devin|devin|devin|devin
16|Roo Code|roo|paste|-
17|Continue|continue|paste|-
18|Amp|amp|paste|-
19|Claude Desktop|-|user|claude-desktop
20|Other agents that read .agents/skills|universal|paste|-'
if [ -z "$AGENTS" ] && [ "$ASSUME_YES" -eq 0 ] && [ "$HAVE_TTY" -eq 1 ]; then
  {
    printf '\nWhich agents should get the skills%s? (asked once, used for everything)\n\n' "$( [ "$MCP_MODE" = stdio ] && echo ' and the MCP server')"
    line='+----+-------------------------------------------+--------+-----------------------------+'
    echo "$line"; printf '| %-2s | %-41s | %-6s | %-27s |\n' '#' 'Agent' 'Skills' 'MCP server'; echo "$line"
    printf '%s\n' "$AGENT_TABLE" | while IFS='|' read -r num name skill route _; do
      case "$route" in folder) mcp="this folder or user-wide" ;; user) mcp="user-wide only" ;; devin) mcp="devin mcp add" ;; paste) mcp="config printed to paste" ;; *) mcp="-" ;; esac
      printf '| %-2s | %-41s | %-6s | %-27s |\n' "$num" "$name" "$( [ "$skill" = - ] && echo no || echo yes)" "$mcp"
    done
    echo "$line"; echo
  } >/dev/tty
  AGENTS="$(ask 'Type numbers separated by commas (e.g. 1,2,15), or "all"' "1")"
fi
SKILL_AGENTS=""; MCP_FOLDER=""; MCP_USER=""; MCP_DEVIN=0; MCP_PASTE=""; AGENT_NAMES=""
add_word() { case " $(eval echo \"\$$1\") " in *" $2 "*) ;; *) eval "$1=\"\${$1:+\$$1 }$2\"" ;; esac; }
for token in $(printf '%s' "${AGENTS:-1}" | tr 'A-Z,' 'a-z '); do
  [ "$token" = all ] && token="$(printf '%s\n' "$AGENT_TABLE" | cut -d'|' -f1 | tr '\n' ' ')"
  for t in $token; do
    case "$t" in -*) die "unknown agent $t: use numbers from the table (1-20) or agent names such as claude-code,codex" ;; esac
    row="$(printf '%s\n' "$AGENT_TABLE" | awk -F'|' -v t="$t" '$1 == t || $3 == t || $5 == t { print; exit }')"
    if [ -z "$row" ]; then
      case "$t" in *[!0-9]*) ;; *) die "unknown agent $t: use numbers from the table (1-20) or agent names such as claude-code,codex" ;; esac
      case "$t" in *[!a-z0-9-]*|""|-*) die "unknown agent $t: use numbers from the table (1-20) or agent names such as claude-code,codex" ;; esac
      row="0|$t|$t|paste|-"  # another agent the skills installer knows; its MCP config is printed
    fi
    IFS='|' read -r _ name skill route mcp <<EOF
$row
EOF
    add_word AGENT_NAMES "$(printf '%s' "$name" | tr ' ' '_')"
    [ "$skill" != - ] && add_word SKILL_AGENTS "$skill"
    case "$route" in
      folder) add_word MCP_FOLDER "$mcp" ;;
      user) add_word MCP_USER "$mcp" ;;
      devin) MCP_DEVIN=1 ;;
      paste) add_word MCP_PASTE "$(printf '%s' "$name" | tr ' ' '_')" ;;
    esac
  done
done
set +f
echo "Agents: $(printf '%s' "$AGENT_NAMES" | sed 's/ /, /g' | tr '_' ' ')"

command -v git >/dev/null || die "git is required"
PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys, venv; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
    PYTHON="$candidate"; break
  fi
done
if [ -z "$PYTHON" ] && { [ "$NEED_PYTHON" -eq 1 ] || [ "$MCP_MODE" = stdio ]; }; then
  die "Python 3.9 or later with the venv module is required (on Debian/Ubuntu: apt install python3-venv)"
fi

if [ -n "$ROOT_GIVEN" ]; then
  ROOT="$ROOT_GIVEN"
elif [ "$PWD" != "$HOME" ]; then
  ROOT="$PWD"  # "this folder": where the user ran the script
else
  ROOT="$HOME/edgeconnect"
fi
ROOT="$(ask "Install folder" "$ROOT")"
case "$ROOT" in "~"|"~/"*) ROOT="$HOME${ROOT#\~}" ;; esac
mkdir -p "$ROOT" && ROOT="$(cd "$ROOT" && pwd)" || die "cannot use the folder $ROOT"
if [ -z "$SCOPE" ]; then
  if [ "$ASSUME_YES" -eq 0 ] && [ "$HAVE_TTY" -eq 1 ]; then
    what="the skills"; [ "$MCP_MODE" = stdio ] && what="the skills and the MCP server"
    printf '\nWhere should %s go?\n  1) Only in this folder: %s   (default)\n  2) Your user account (~), in every project\n' "$what" "$ROOT" >/dev/tty
  fi
  SCOPE="$(ask "Choose 1 or 2" "1")"
fi
case "$SCOPE" in
  1|folder|project|dir|same) SCOPE=folder ;;
  2|home|global|"~"|"~/") SCOPE=home ;;
  *) die "choose 1 (this folder) or 2 (your user account), not $SCOPE" ;;
esac
PRECONFIG_SCRIPTS="$ROOT/edgeconnect-preconfig/toolkit/scripts"

# A re-run leaves every clean clone on main, pulled from GitHub. A clone with uncommitted edits, or detached on a commit
# main does not have, is left alone so no edit or commit is lost; a branch it was on is kept.
update_clone() {
  if [ -n "$(git -C "$ROOT/$1" status --porcelain --untracked-files=no)" ]; then
    echo "$1: already cloned, has local changes, not updated (commit or discard them, then run again)"
    return 0
  fi
  git -C "$ROOT/$1" fetch -q origin main || die "$1: could not fetch main (not on GitHub, or no network)"
  branch=$(git -C "$ROOT/$1" symbolic-ref --short -q HEAD) || branch=""
  if [ -z "$branch" ] && ! git -C "$ROOT/$1" merge-base --is-ancestor HEAD origin/main; then
    echo "$1: already cloned, not on a branch (detached at $(git -C "$ROOT/$1" rev-parse --short HEAD), a commit main does not have), not updated (put it on a branch, then run again)"
    return 0
  fi
  if [ "$branch" != "main" ]; then
    if git -C "$ROOT/$1" show-ref --verify -q refs/heads/main; then
      git -C "$ROOT/$1" checkout -q main -- || die "$1: could not switch to main"
    else
      git -C "$ROOT/$1" checkout -q -b main --track origin/main || die "$1: could not switch to main"
    fi
    echo "$1: switched ${branch:-detached HEAD} to main"
  fi
  git -C "$ROOT/$1" pull -q --ff-only origin main || die "$1: could not update main (diverged from GitHub's main, or no network)"
  echo "$1: already cloned, updated main to $(git -C "$ROOT/$1" rev-parse --short HEAD)"
}

say "Repositories (main) in $ROOT"
mkdir -p "$ROOT"
for repo in $REPOS; do
  if [ -d "$ROOT/$repo/.git" ]; then
    update_clone "$repo"
  else
    git clone -q "https://github.com/mirwasay/$repo.git" "$ROOT/$repo" || die "$repo: clone failed; check your network access to github.com and run again"
    echo "$repo: cloned at $(git -C "$ROOT/$repo" rev-parse --short HEAD)"
  fi
done

if [ "$NEED_PYTHON" -eq 1 ]; then
say "Python environment in $ROOT/.venv"
if [ -x "$ROOT/.venv/bin/python" ]; then echo "already present"; else "$PYTHON" -m venv "$ROOT/.venv"; fi
# The pip that ships with an older Python (21.x on macOS 3.9) cannot install the CLI in editable mode.
"$ROOT/.venv/bin/python" -m pip install -q --disable-pip-version-check --upgrade pip
if picked edgeconnect-orchestrator-automation; then
  "$ROOT/.venv/bin/python" -m pip install -q --disable-pip-version-check -e "$ROOT/edgeconnect-orchestrator-automation"
  echo "edgeconnect-auto $("$ROOT/.venv/bin/python" -c 'import edgeconnect_automation as e; print(e.__version__)') installed"
fi
if picked edgeconnect-preconfig; then
  # before 1.3.0 the scripts lived only in the skill folder (a clone left on such an old commit, e.g. with local changes)
  [ -d "$PRECONFIG_SCRIPTS" ] || PRECONFIG_SCRIPTS="$ROOT/edgeconnect-preconfig/skills/building-edgeconnect-preconfig-templates/scripts"
  "$ROOT/.venv/bin/python" -m pip install -q --disable-pip-version-check -r "$ROOT/edgeconnect-preconfig/requirements.txt"
  echo "preconfig scripts $(cat "$PRECONFIG_SCRIPTS/../VERSION" 2>/dev/null || echo "(no VERSION file)"): Jinja2 and PyYAML installed"
fi
fi  # NEED_PYTHON

if [ "$NEED_PYTHON" -eq 1 ] || [ "$MCP_MODE" = stdio ]; then

say "Shared settings in $ROOT/.env"
if [ -e "$ROOT/.env" ]; then
  echo "already exists, kept unchanged"
else
  (umask 077; cat > "$ROOT/.env" <<'EOF'
# Shared by edgeconnect-auto, edgeconnect-preconfig and the local MCP server. Never commit or share this file.
# One slot per Orchestrator; the nickname is what you pass to --orchestrator.
orch_1=lab
lab_base_url=https://<ORCHESTRATOR_FQDN_OR_IP>
lab_api_key=<API_KEY>

# More Orchestrators:
# orch_2=main
# main_base_url=https://<ORCHESTRATOR_FQDN_OR_IP>
# main_api_key=<API_KEY>

# Format: one KEY=value per line, no inline comments ("value # note" is all value), base URLs https:// only.
# Nicknames: letters, digits and _ (not "orch" or orch_...). Pick the default with orch_default=<nickname>.
# Optional per nickname: <nickname>_ca_bundle=/full/path/ca.pem (private CA, no ~),
#   <nickname>_api_key_header=X-Auth-Token (the default),
#   <nickname>_tls_sha256=<64 hex digits, colons allowed> (self-signed certificate; pins that host only)
# Preconfig: Orchestrators allowed for /validate, exact nicknames, comma-separated. None if unset.
# EC_VALIDATORS=lab
# MCP server, per nickname. On only for true, 1 or yes; anything else, including "on", is off.
#   <nickname>_mcp_writes=true      allow api_write (two-step confirmation unless _mcp_confirm_writes=false)
#   <nickname>_mcp_get_only=true    GETs only: refuses the three read-only POSTs (alarms, interface totals,
#                                   health) and every api_write
# Every key, its default and accepted values: .env.example in each repository
#   https://github.com/mirwasay/edgeconnect-mcp/blob/main/.env.example
#   https://github.com/mirwasay/edgeconnect-orchestrator-automation/blob/main/.env.example
#   https://github.com/mirwasay/edgeconnect-preconfig/blob/main/.env.example
EOF
  )
  echo "created: replace the placeholders before the first run"
fi
chmod 600 "$ROOT/.env"

say "Commands"
install_command() {  # name [folder, default $BIN]; wrapper body on stdin. Never replaces a command this script did not write.
  local target="${2:-$BIN}/$1" body
  mkdir -p "${2:-$BIN}"
  body="$(cat)"
  if [ -e "$target" ] && ! grep -qF "$MARK" "$target"; then
    echo "$1: $target exists and was not written by this script; left unchanged"
    return
  fi
  local state="installed"
  [ -e "$target" ] && state="already installed, refreshed"
  printf '#!/bin/sh\n%s\n%s\n' "$MARK" "$body" > "$target"
  chmod 755 "$target"
  echo "$1: $state ($target)"
}
if picked edgeconnect-orchestrator-automation; then
install_command edgeconnect-auto <<EOF
exec "$ROOT/.venv/bin/edgeconnect-auto" --dotenv "$ROOT/.env" "\$@"
EOF
fi
if picked edgeconnect-preconfig; then
install_command edgeconnect-preconfig <<EOF
# Usage: edgeconnect-preconfig COMMAND [options]: list, build, variables, compare, validate, upload, or a stage name (--help lists them)
EC_DOTENV="\${EC_DOTENV:-$ROOT/.env}" exec "$ROOT/.venv/bin/python" "$PRECONFIG_SCRIPTS/cli.py" "\$@"
EOF
fi
if [ "$MCP_MODE" = stdio ]; then
  # The server needs only the standard library: the toolkit's Python when there is one, else the system one.
  if [ -x "$ROOT/.venv/bin/python" ]; then MCP_PY="$ROOT/.venv/bin/python"; else MCP_PY="$(command -v "$PYTHON")"; fi
# In the install folder, not ~/.local/bin: each folder's agents start that folder's server and .env.
install_command edgeconnect-mcp "$ROOT/bin" <<EOF
# Runs the EdgeConnect MCP server (stdio) from $ROOT/edgeconnect-mcp with the shared .env.
PYTHONPATH="$ROOT/edgeconnect-mcp/src\${PYTHONPATH:+:\$PYTHONPATH}" exec "$MCP_PY" -m edgeconnect_mcp --dotenv "\${EDGECONNECT_DOTENV:-$ROOT/.env}" "\$@"
EOF
fi
if [ "$NEED_PYTHON" -eq 1 ]; then
  case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "$BIN is not on your PATH; add this line to your shell profile: export PATH=\"$BIN:\$PATH\"" ;;
  esac
fi
fi  # .env and commands

if [ "$SCOPE" = home ]; then
  say "Agent skills for your user (~/)"
  SCOPE_FLAG="-g"; SKILLS_CWD="$HOME"
else
  say "Agent skills inside $ROOT"
  SCOPE_FLAG=""; SKILLS_CWD="$ROOT"
fi
HAVE_NPX=0; command -v npx >/dev/null && HAVE_NPX=1
if [ -z "$SKILL_AGENTS" ]; then
  echo "none of the agents you picked takes skills"
elif [ "$HAVE_NPX" -eq 0 ]; then
  echo "Node.js 18 or later is needed to install the skills; after installing it, run install-all.sh again"
else
  # shellcheck disable=SC2046  # one -a per agent
  AGENT_FLAGS="$(printf -- '-a %s ' $SKILL_AGENTS)"
  for repo in $REPOS; do
    for skill_dir in "$ROOT/$repo"/skills/*/; do
      skill="$(basename "$skill_dir")"
      # Installed or not, every picked skill goes to every chosen agent: that also updates it from main.
      # shellcheck disable=SC2086
      (cd "$SKILLS_CWD" && npx -y skills add "$ROOT/$repo" -s "$skill" $SCOPE_FLAG $AGENT_FLAGS -y >/dev/null) || die "$skill: the skills installer failed"
      echo "$skill: installed for $SKILL_AGENTS"
    done
  done
fi

if [ "$MCP_MODE" = docker ]; then
  say "MCP server"
  echo "You run it in Docker over HTTPS: install it manually with the repo guide: $MCP_GUIDE"
elif [ "$MCP_MODE" = stdio ]; then
  MCP_CMD="$ROOT/bin/edgeconnect-mcp"
  if [ "$SCOPE" = home ]; then say "MCP server for your agents, in every project"; else say "MCP server for your agents, in $ROOT"; fi
  CAN_ASK=0; [ "$ASSUME_YES" -eq 0 ] && [ "$HAVE_TTY" -eq 1 ] && CAN_ASK=1
  MCP_LATER=""  # one command per line, shown on the last screen
  ADDED_USER_WIDE=0
  later() { MCP_LATER="${MCP_LATER}  $1
"; }
  label() { printf '%s\n' "$AGENT_TABLE" | awk -F'|' -v id="$1" '$5 == id { print $2; exit }'; }
  # add-mcp reports "✓ <Agent>: <config file>" per agent; show those lines
  report() { "$PYTHON" -c 'import re, sys
for m in re.finditer(r"\u2713 ([^\u2502\n]+)", re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", sys.stdin.read())): print("  " + m.group(1).strip())'; }
  add_mcp() {  # scope flag ("" or -g), agents...
    local flag="$1" out; shift
    # No --auto-approve: the agents still ask before each MCP tool call.
    # shellcheck disable=SC2046
    out="$(cd "$ROOT" && npx -y add-mcp "$MCP_CMD" -n edgeconnect $flag $(printf -- '-a %s ' "$@") -y 2>&1)" || { printf '%s\n' "$out" | tail -5; die "add-mcp failed for $*"; }
    printf '%s' "$out" | report
    if [ "$flag" = -g ]; then ADDED_USER_WIDE=1; fi
  }
  if [ "$SCOPE" = home ]; then for a in $MCP_FOLDER; do add_word MCP_USER "$a"; done; MCP_FOLDER=""; fi
  if [ -n "$MCP_FOLDER$MCP_USER" ] && [ "$HAVE_NPX" -eq 0 ]; then
    echo "Node.js 18 or later is needed to add the MCP server to your agents; after installing it, run install-all.sh again"
  elif [ -n "$MCP_FOLDER$MCP_USER" ] && [ "$CAN_ASK" -eq 0 ] && [ "$MCP_EXPLICIT" -eq 0 ]; then
    # add-mcp replaces an existing "edgeconnect" entry (for example a Docker/HTTPS one): without a person to ask, only on --mcp stdio
    echo "Not added to your agents without asking, since an existing edgeconnect entry would be replaced; run install-all.sh with --mcp stdio to add it (the commands to add it yourself are on the last screen)"
    for a in $MCP_FOLDER; do later "npx -y add-mcp \"$MCP_CMD\" -n edgeconnect -a $a          # $(label "$a"), this folder (run in $ROOT)"; done
    for a in $MCP_USER; do later "npx -y add-mcp \"$MCP_CMD\" -n edgeconnect -g -a $a       # $(label "$a"), user-wide"; done
  elif [ -n "$MCP_FOLDER$MCP_USER" ]; then
    echo "An existing MCP server named edgeconnect in these agents is replaced by this folder's server ($MCP_CMD)."
    go=Y; [ "$CAN_ASK" -eq 1 ] && go="$(ask "Continue" "Y")"
    case "$go" in
      [Nn]*)
        echo "skipped"
        for a in $MCP_FOLDER; do later "npx -y add-mcp \"$MCP_CMD\" -n edgeconnect -a $a          # $(label "$a"), this folder (run in $ROOT)"; done
        for a in $MCP_USER; do later "npx -y add-mcp \"$MCP_CMD\" -n edgeconnect -g -a $a       # $(label "$a"), user-wide"; done ;;
      *)
        if [ -n "$MCP_FOLDER" ]; then
          echo "Added for this folder (some agents, such as Claude Code, ask you once to approve it):"
          # shellcheck disable=SC2086
          add_mcp "" $MCP_FOLDER
        fi
        if [ "$SCOPE" = home ]; then
          if [ -n "$MCP_USER" ]; then
            echo "Added for your user account, in every project:"
            # shellcheck disable=SC2086
            add_mcp -g $MCP_USER
          fi
        else
          # "This folder" was chosen: an agent that keeps MCP servers only user-wide needs its own yes.
          for a in $MCP_USER; do
            if [ "$CAN_ASK" -eq 1 ]; then
              yn="$(ask "$(label "$a") keeps MCP servers only for your whole user account. Add edgeconnect user-wide (y/n)" "n")"
            else
              yn=N
            fi
            case "$yn" in
              [Yy]*) add_mcp -g "$a" ;;
              *) echo "$(label "$a"): skipped (user-wide only)"; later "npx -y add-mcp \"$MCP_CMD\" -n edgeconnect -g -a $a       # $(label "$a"), user-wide only" ;;
            esac
          done
        fi ;;
    esac
  fi
  if [ "$MCP_DEVIN" -eq 1 ]; then
    DEVIN_SCOPE=local; [ "$SCOPE" = home ] && DEVIN_SCOPE=user
    if ! command -v devin >/dev/null; then
      echo "Devin: the devin command is not installed; after installing it, run in $ROOT: devin mcp add -s $DEVIN_SCOPE edgeconnect -- $MCP_CMD"
    else
      DEVIN_OWN_OTHER=0
      DEVIN_OWN="$ROOT/.devin/mcp_config.local.json"; [ "$SCOPE" = home ] && DEVIN_OWN="$HOME/.config/devin/mcp_config.json"
      if [ -f "$DEVIN_OWN" ] && grep -q '"edgeconnect"' "$DEVIN_OWN" && grep -qF "\"$MCP_CMD\"" "$DEVIN_OWN"; then
        echo "Devin: already has edgeconnect in $DEVIN_OWN"
      elif [ -f "$DEVIN_OWN" ] && grep -q '"edgeconnect"' "$DEVIN_OWN"; then
        DEVIN_OWN_OTHER=1
        echo "Devin: $DEVIN_OWN has an edgeconnect entry that runs another server, left unchanged; to switch it to this folder's:"
        echo "  devin mcp remove -s $DEVIN_SCOPE edgeconnect && devin mcp add -s $DEVIN_SCOPE edgeconnect -- \"$MCP_CMD\"   (in $ROOT)"
      elif (cd "$ROOT" && devin mcp add -s "$DEVIN_SCOPE" edgeconnect -- "$MCP_CMD" >/dev/null 2>&1); then
        echo "Devin: added ($DEVIN_OWN)"
      else
        echo "Devin: devin mcp add failed; run it yourself in $ROOT: devin mcp add -s $DEVIN_SCOPE edgeconnect -- $MCP_CMD"
      fi
      # Devin also reads other agents' MCP files (.mcp.json, Windsurf's...): show the entry it resolves.
      seen="$(cd "$ROOT" && devin mcp get edgeconnect 2>/dev/null | sed -n 's/^ *Command: //p' | head -1)"
      if [ -n "$seen" ] && [ "$seen" != "$MCP_CMD" ] && [ "$DEVIN_OWN_OTHER" -eq 0 ]; then
        echo "  note: Devin resolves edgeconnect to $seen, from another agent's settings; remove that entry if Devin should use this folder's server"
      fi
    fi
  fi
  if [ -n "$MCP_PASTE" ]; then
    echo "$(printf '%s' "$MCP_PASTE" | sed 's/ /, /g' | tr '_' ' '): no installer for these; add this to the agent's MCP settings (where most agents keep them: https://github.com/mirwasay/edgeconnect-mcp/blob/main/docs/clients.md):"
    printf '  {"mcpServers": {"edgeconnect": {"command": "%s"}}}\n' "$MCP_CMD"
  fi
  if [ "$ADDED_USER_WIDE" -eq 1 ] || { [ "$MCP_DEVIN" -eq 1 ] && [ "$SCOPE" = home ]; }; then
    echo "User-wide entries run the server from $ROOT: moving or deleting that folder breaks them (run install-all.sh again from the new place)."
  fi
fi

say "Agent instructions in $ROOT"
# AGENTS.md routes an agent started in this folder to the right tool; CLAUDE.md points Claude Code at it.
# A file you have edited is never overwritten: a newer version is written beside it as AGENTS.md.new.
# Written straight to a file, not through "$(cat <<EOF)": bash 3.2 (macOS) misparses an apostrophe in a heredoc inside $( ).
AGENTS_NEW="$ROOT/.AGENTS.md.setup"
cat > "$AGENTS_NEW" <<'EOF'
# EdgeConnect tools: which one to use, and how

You are working with HPE Aruba EdgeConnect SD-WAN through an Orchestrator. Three tools exist; "Installed here" at the end of this file says which ones this folder has. Choose the tool first, using the table below, then follow that tool's skill. This file only routes and sets the answer style; it never replaces a skill's safety rules, so do not restate or relax them.

## How these tools are used

These tools are run by a person. You help by writing the CSV files and the exact commands; the person pastes and runs them in their own terminal and sends you the output.

- You may run read-only steps yourself when you can (validate, plan, dry run, report collection, MCP reads). You never run an `edgeconnect-auto` write (`APPLY`) or an MCP write. Preconfig uploads follow the preconfig skill's own flow: only after the user approves its table, with `--approve`.
- For every operation you run or propose, show the exact command in its own code block, ready to paste, even when you run it yourself (for an MCP call, the tool and request). Show only the command lines, not the files you prepared; for an edit to a CSV, name the file and the cells you changed, then show the command that uses it.
- Give each command as one block the person can paste as it is, with the Orchestrator named and the folder it must run from. The `edgeconnect-auto` and `edgeconnect-preconfig` commands already find the shared `.env`, so no `--dotenv` is needed.
- For a write, say what to check on the prompt before typing `APPLY` (the Orchestrator name and the list of changes), and ask them to paste the run summary back so you can read it and offer a read back.
- If the person asks you to "just do it" for an `edgeconnect-auto` write, still hand over the command; the typed approval is theirs.

## Step 1: pick the tool

Find the first row that matches what the user wants.

| If the user wants to... | Use | Skill to read first |
|---|---|---|
| create, change or delete **firewall policies** (global or inter-segment), **zones**, **address groups**, **service groups**, **application definitions**, **application groups**, **AppExpress Monitor** entries, or **template-group ACLs**, especially in bulk from a list or spreadsheet | **`edgeconnect-auto`** (command line) | `managing-edgeconnect-firewall-and-objects` |
| build a **preconfig template** and CSV from a working appliance, choose the per-site settings, or **validate or upload preconfigs** | **`edgeconnect-preconfig <command>`** (command line: `list`, `build`, `variables`, `compare`, `validate`, `upload`) | `building-edgeconnect-preconfig-templates` |
| a **report**: monthly availability or service level, NOC digest, WAN capacity, lifecycle and licences, a major incident, an executive summary, WAN traffic and top talkers, path quality, a weekly operations summary, optimisation, security (zone-pair flows and drops), change activity, one site, a daily health check, or a custom report | **`edgeconnect-mcp report`** (command line: `bin/edgeconnect-mcp report` in this folder when the MCP server is installed here, otherwise `PYTHONPATH=edgeconnect-mcp/src python3 -m edgeconnect_mcp --dotenv .env report`) | `edgeconnect-report` |
| look something up, list or explain things, troubleshoot, check status or alarms, **read back** what a change did, or do any other Orchestrator task that is not in the rows above | **MCP server** (tools `list_orchestrators`, `find_operations`, `describe_operation`, `api_get`, `api_read_post`, `api_write`) | `edgeconnect-guide` |

If a request fits two rows, use the upper one: it has the stronger approval step. If it fits none, or you are unsure which tool owns an object, say so in one line and ask; do not guess.

Examples: "add 200 application definitions from this sheet" -> `edgeconnect-auto`. "allow segment A to reach segment B on TCP 443" -> `edgeconnect-auto`. "build a preconfig for this branch appliance" -> `edgeconnect-preconfig`. "give me last month's availability report" -> `edgeconnect-mcp report`. "show last week's top talkers" -> `edgeconnect-mcp report`. "which appliances are unreachable?" -> MCP. "did that firewall change take effect?" -> MCP read back.

## Step 2: follow the tool's approval flow

Each tool has its own way of making sure a person approves a write. Never skip or imitate it.

- **`edgeconnect-auto`:** you write the CSV and run the read-only checks (validate, plan, dry run). The user alone performs the write by typing `APPLY` in their own terminal. You never type it, never ask the user to paste it into chat, and never get around it.
- **`edgeconnect-preconfig`:** `list`, `build`, `variables`, `compare` and `validate` only read from the Orchestrator (GET) or write local files. `upload` shows what it would upload and uploads nothing unless the user explicitly approves, and then only with `--approve`, as the preconfig skill describes. The toolkit never applies a preconfig to an appliance.
- **`edgeconnect-mcp report`:** reads only (GETs, plus the three read-only POSTs unless the Orchestrator is GET-only) and writes local files. Ask the report options the skill lists once, with their defaults, before collecting.
- **MCP:** reads are free (`api_get`, and `api_read_post` for the three read-only POSTs). The first `api_write` call changes nothing: it returns the exact change and a one-time confirmation code. Show that change to the user. Only after they say yes, repeat the identical call with the code. If the server refuses a write, tell the user and stop; do not look for another way in.

## Rules

1. Objects owned by `edgeconnect-auto` or `edgeconnect-preconfig` (see Step 1) are never written with the MCP `api_write` tool, even if it would work.
2. Name the Orchestrator in every command: `--orchestrator <nickname>` for `edgeconnect-auto` and the preconfig scripts, the `orchestrator` argument for MCP. Never rely on a default. If the user has not said which one, ask. `list_orchestrators` (MCP) shows the configured nicknames.
3. After any write by `edgeconnect-auto` or `edgeconnect-preconfig`, offer an MCP read back and report what it actually returned, not only "verified".
4. Do not start an MCP write while an `edgeconnect-auto` run on the same objects is in progress.
5. Never edit `.env` files, API keys, TLS pins or certificate settings. Tell the user the exact line to add and let them add it. Never print or repeat a secret.
6. A more specific instruction from the user in chat wins over this file, but never over a skill's safety rule or a tool's approval step.

## This folder

- `.env`: the one settings file shared by `edgeconnect-auto`, `edgeconnect-preconfig` and the local MCP server (Orchestrator nicknames, URLs, API keys, TLS pins). They all find it by themselves, so run them from any folder.
- `edgeconnect-orchestrator-automation/` and `edgeconnect-preconfig/`, when installed: the tools' source, kept current by `install-all.sh` (or this repository's `install.sh`). Read them, do not edit them.
- Keep your own CSVs, reports and captures in a separate work folder, not in the tool folders. Never commit them or `.env`.
- `edgeconnect-mcp/`, if it was picked: its guide and report skills and, when "Installed here" lists it, the MCP server that your agent starts through `bin/edgeconnect-mcp` with the shared `.env`. Otherwise the MCP server runs separately (for example in Docker). If its tools are not available, say so and continue with the other two; do not try to install or start it.

## How to answer

- Lead with the answer or the result, then the evidence.
- Say which tool you will use, in one line, before you use it.
- Before anything that writes, show the exact command or change and what it affects, then wait for the user.
- Say "verified" only after a read back shows it. If you could not check something, say so.
- End with what you did not check or are unsure about.
- Keep replies short. Ask one question at a time, and only when a wrong guess would change what traffic or configuration is affected.
- If a command fails, show the message as printed and the fix it suggests. Do not retry with different flags to get past a check.
EOF
# Listed from what the folder holds, so a later run that picks fewer repositories keeps the earlier ones.
LIST_AUTO='- `edgeconnect-auto` and the skill `managing-edgeconnect-firewall-and-objects` (edgeconnect-orchestrator-automation)'
LIST_PRECONFIG='- `edgeconnect-preconfig` and the skill `building-edgeconnect-preconfig-templates` (edgeconnect-preconfig)'
LIST_MCP='- the skills `edgeconnect-guide` and `edgeconnect-report` for the MCP server (edgeconnect-mcp); the server itself runs separately'
LIST_MCP_LOCAL='- the skills `edgeconnect-guide` and `edgeconnect-report`, and the MCP server and `report` command, run locally by `bin/edgeconnect-mcp` with the shared `.env` (edgeconnect-mcp)'
LIST_END='A tool not listed here is not installed in this folder: do not run its commands. If the user needs it, tell them to run install-all.sh again and pick it.'
LIST_END_OLD='A tool not listed here is not installed in this folder: do not run its commands. If the user needs it, tell them to run setup.sh again and pick it.'  # written before the rename
{
  printf '\n## Installed here\n\n'
  if [ -d "$ROOT/edgeconnect-orchestrator-automation/.git" ]; then printf '%s\n' "$LIST_AUTO"; fi
  if [ -d "$ROOT/edgeconnect-preconfig/.git" ]; then printf '%s\n' "$LIST_PRECONFIG"; fi
  if [ -d "$ROOT/edgeconnect-mcp/.git" ]; then
    if [ -x "$ROOT/bin/edgeconnect-mcp" ]; then printf '%s\n' "$LIST_MCP_LOCAL"; else printf '%s\n' "$LIST_MCP"; fi
  fi
  printf '\n%s\n' "$LIST_END"
} >> "$AGENTS_NEW"
section() { sed -n '/^## Installed here$/,/^A tool not listed here is not installed/p' "$1"; }
rest() { sed '/^## Installed here$/,/^A tool not listed here is not installed/d' "$1"; }
LIST_LINES="$ROOT/.AGENTS.md.lines"
# Lines earlier releases generated count as generated too, so an unedited AGENTS.md from them is still updated.
LIST_MCP_OLD='- the skill `edgeconnect-guide` for the MCP server (edgeconnect-mcp); the server itself runs separately'
LIST_MCP_LOCAL_OLD='- the skill `edgeconnect-guide` and the MCP server, run locally by `bin/edgeconnect-mcp` with the shared `.env` (edgeconnect-mcp)'
printf '%s\n' '## Installed here' '' "$LIST_AUTO" "$LIST_PRECONFIG" "$LIST_MCP" "$LIST_MCP_LOCAL" "$LIST_MCP_OLD" "$LIST_MCP_LOCAL_OLD" "$LIST_END" "$LIST_END_OLD" > "$LIST_LINES"
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }
# Fingerprint of the text outside the Installed here list, trailing blank lines dropped.
fingerprint() { rest "$1" | awk '{ line[NR] = $0 } END { n = NR; while (n > 0 && line[n] == "") n--; for (i = 1; i <= n; i++) print line[i] }' | sha256; }
# AGENTS.md texts that earlier releases of setup.sh wrote (before AGENTS_FP below existed).
KNOWN_AGENTS_TEXTS="0ab42174b4cf385ceda3b355d0f47a17277fee38842a08aef9010ef79d603159 1d736025f4b2f176247013d1a21efc60d01851596657f2bee3f5fbcd3cb6a686 4aa567c1933f907c0d62e360a54f3a5505dc50c6297da8698c7cd6af679361e0 508ded02efd387681fec558c354597faefe2a66bddff9d8ded0e930940c3c08d 91e8635704a868498ede09fcca9de24a1b43f1ba5b0b5d98252b85c596ff6d75 f65809fa0aa63b086709daefbea7dcb555b6909cce5880c3f2d83e3c7b0f275d"
AGENTS_FP="$ROOT/.AGENTS.md.setup-sha256"  # fingerprint of the AGENTS.md this script last wrote
untouched() {  # AGENTS.md is a text this script (or setup.sh before the rename) wrote, and its Installed here list holds only generated lines
  local fp; fp="$(fingerprint "$ROOT/AGENTS.md")"
  case " $KNOWN_AGENTS_TEXTS $(cat "$AGENTS_FP" 2>/dev/null) $(fingerprint "$AGENTS_NEW") " in *" $fp "*) ;; *) return 1 ;; esac
  ! section "$ROOT/AGENTS.md" | grep -qvxF -f "$LIST_LINES"
}
OURS=1
if [ ! -e "$ROOT/AGENTS.md" ]; then
  mv "$AGENTS_NEW" "$ROOT/AGENTS.md"
  echo "AGENTS.md: created"
elif cmp -s "$AGENTS_NEW" "$ROOT/AGENTS.md"; then
  rm -f "$AGENTS_NEW"
  echo "AGENTS.md: already present, up to date"
elif untouched; then
  mv "$AGENTS_NEW" "$ROOT/AGENTS.md"  # this script wrote it and nobody edited it since: keep it current
  echo "AGENTS.md: updated (you had not edited it)"
else
  OURS=0
  mv "$AGENTS_NEW" "$ROOT/AGENTS.md.new"
  echo "AGENTS.md: you have edited it, so it is kept unchanged; the current version is in AGENTS.md.new (compare them, then merge or replace)"
fi
rm -f "$LIST_LINES"
if [ "$OURS" -eq 1 ]; then
  fingerprint "$ROOT/AGENTS.md" > "$AGENTS_FP"  # what this script's AGENTS.md looks like, for the next run
  if [ -e "$ROOT/AGENTS.md.new" ] && cmp -s "$ROOT/AGENTS.md.new" "$ROOT/AGENTS.md"; then rm -f "$ROOT/AGENTS.md.new"; fi  # left over, now applied
fi
if [ ! -e "$ROOT/CLAUDE.md" ]; then
  printf '@AGENTS.md\n' > "$ROOT/CLAUDE.md"
  echo "CLAUDE.md: created (points to AGENTS.md)"
elif grep -qF '@AGENTS.md' "$ROOT/CLAUDE.md"; then
  echo "CLAUDE.md: already present"
else
  echo "CLAUDE.md: already exists, kept unchanged; add the line @AGENTS.md to it so Claude Code reads AGENTS.md"
fi

say "Done: $REPOS"
if [ "$NEED_PYTHON" -eq 1 ] || [ "$MCP_MODE" = stdio ]; then
  cat <<EOF

Next: fill in $ROOT/.env, the one settings file for everything you installed.
  Open it:   open -e "$ROOT/.env"   (macOS)    or    nano "$ROOT/.env"

  For each Orchestrator, three lines. The nickname (here "lab") is what you type after
  --orchestrator, and what your agent names:
    orch_1=lab
    lab_base_url=https://<Orchestrator address>
    lab_api_key=<REST API key>
  A second Orchestrator gets orch_2=<nickname> and its own two lines.

  API key: create one in Orchestrator, as HPE's API Key page shows:
    https://arubanetworking.hpe.com/techdocs/sdwan/docs/orch/orchestrator/server/api-key/
    Read-Only is enough for reads; writes need a key that may write.
  Self-signed certificate: add lab_tls_sha256=<fingerprint>. Get the fingerprint, and check it
    on the Orchestrator itself:
    openssl s_client -connect <Orchestrator address>:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
  Private CA instead: lab_ca_bundle=/path/to/ca.pem
EOF
  if picked edgeconnect-preconfig; then cat <<'EOF'

  Preconfig: name the Orchestrators that may check rendered files with /validate, a lab one:
    EC_VALIDATORS=lab
EOF
  fi
  if [ "$MCP_MODE" = stdio ]; then cat <<'EOF'

  MCP server: read-only until you allow writes for an Orchestrator:
    lab_mcp_writes=true
  Writes stay two-step (the agent shows the change and asks first). Every option:
    https://github.com/mirwasay/edgeconnect-mcp#configuration
EOF
  fi
  echo
  echo "Then check:"
  if picked edgeconnect-orchestrator-automation; then echo "  edgeconnect-auto --orchestrator lab discovery"; fi
  if picked edgeconnect-preconfig; then echo "  edgeconnect-preconfig list --orchestrator lab"; fi
  if [ "$MCP_MODE" = stdio ]; then echo "  restart your agents and ask: list my EdgeConnect orchestrators"; echo "  $ROOT/bin/edgeconnect-mcp report --help"; fi
fi
if [ -n "${MCP_LATER:-}" ]; then
  echo
  echo "MCP server not added to these agents yet; to add it, run:"
  printf '%s' "$MCP_LATER"
fi
echo
echo "Start your agent in $ROOT (it reads AGENTS.md there), and restart it so it loads the skills and MCP servers."
if [ "$MCP_MODE" = stdio ]; then
  echo "MCP server: runs locally from $ROOT/bin/edgeconnect-mcp, started by your agents."
elif [ "$MCP_MODE" = docker ]; then
  echo "MCP server: you run it in Docker over HTTPS. Set it up by hand with the repo guide: $MCP_GUIDE"
elif picked edgeconnect-mcp; then
  echo "MCP server: not installed (you chose No). To run it here later, run install-all.sh again and answer 1 at \"Install the MCP server too?\"; if it runs in Docker, answer 2."
else
  echo "MCP server: not part of this install. Run install-all.sh again and pick 3 for its skills and, if you want, the server."
fi
