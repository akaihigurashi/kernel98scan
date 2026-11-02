"""
kernel98scan.py - find Linux hosts that may be exposed to CVE-2026-98432, the
use-after-free in the kernel's IPv4 TCP handshake (SYNs carrying IP options).
Part of shouldipanic.ch.

CVE-2026-98432 is in the KERNEL, and the fix is invisible on the wire: a patched
and an unpatched host answer a normal connection identically. So from outside
this scanner can only read the Linux distribution from the web-server banner and
tell you whether that distribution has released a fixed kernel yet:

  POSSIBLY VULNERABLE  the banner shows a distribution with NO released kernel
                       fix (Ubuntu, RHEL and its rebuilds today), or one that has a
                       fix, which you have to install and reboot into
  UNKNOWN              the banner doesn't reveal the distribution, or a CDN/proxy answers

A banner describes the web server's packages, not necessarily the kernel (think
containers, reverse proxies), so --on-host on the server is the final word: it
reads the running kernel and its changelog.

For each IP/host the engine runs its normal port scan, vhost discovery and a
single GET "/" per endpoint. Nothing else is sent. --ip-options (command line
only, opt-in) adds ONE connection whose SYN carries a Record-Route IP option to
see whether such packets reach the host. That is the packet shape the bug is
reached through, so only use it on your own hosts; a single connect can't win
the race the bug needs.
Only scan systems you are authorized to check.

Usage (results are printed to the terminal):
    python3 kernel98scan.py --on-host                  # real verdict for THIS machine
    python3 kernel98scan.py 203.0.113.10               # 20 web ports + vhost discovery
    python3 kernel98scan.py 198.51.100.0/24            # whole IP range
    python3 kernel98scan.py host.example.ch            # a specific host
    python3 kernel98scan.py 203.0.113.10 --ip-options  # + do IP-options packets get through?
    python3 kernel98scan.py 203.0.113.10 -d            # debug: requests, matches

Targets can be IPs, CIDR ranges, hostnames, URLs, or a file with one per line.

Status:
    POSSIBLY VULNERABLE  Linux distribution visible: no fixed kernel yet, or fixed kernel available
    UNKNOWN              distribution not visible / proxied
    NOT LINUX            the banner identifies a non-Linux server (Windows/IIS)
    SNI ONLY             HTTPS server that only answers for its hostnames; see vhost results
    NOT HTTP             open port, but not a web server (shown with -a)
    ERROR                host not reachable / no open port (shown with -a)
"""
# check module for panic-core: everything specific to kernel98scan.
# panic-core/bundle.py turns this file plus the engine into kernel98scan.py.
from engine import *  # noqa: F401,F403  # bundle: strip

NAME = "kernel98scan"
VERSION = "1.0.0"
DESCRIPTION = "Find Linux hosts that may be exposed to CVE-2026-98432 (kernel IPv4 TCP use-after-free)."
# This scanner keys on the OS the web server reveals, not on a product.
TARGETS = {"Linux distribution"}
BUILTIN_LABEL = "distro rules"
APPS_LABEL = "OS"
COLUMNS = ["target", "final_url", "http_status", "verdict", "distro", "os",
           "server", "evidence"]

BANNER = r"""
    __                        ______  ____
   / /_____  _________  ___  / / __ \( __ ) ___  ______________ _____
  / //_/ _ \/ ___/ __ \/ _ \/ / /_/ / __  |/ _ \/ ___/ ___/ __ `/ __ \
 / ,< /  __/ /  / / / /  __/ /\__, / /_/ /  __(__  ) /__/ /_/ / / / /
/_/|_|\___/_/  /_/ /_/\___/_//____/\____/\___/____/\___/\__,_/_/ /_/
"""
BANNER_COLOR = "35"
BANNER_TAGS = ["CVE-2026-98432  ::  Linux kernel IPv4 TCP use-after-free",
               "banner distro ID  ::  vendor fix status  ::  on-host kernel check"]

CVE = "CVE-2026-98432"

# --- distro fix status ------------------------------------------------------
# True  = the distribution has released a fixed kernel for its supported releases
# False = NO released fix yet
# None  = mixed (some releases/kernels fixed, others not)
# Update with each vendor release, rebuild, commit. Sources: vendor trackers.
FIX_STATUS_DATE = "2026-11-02"
FIX_STATUS = {
    "Debian": True,     # DSA-6568-1 (13: 6.12.113-1), DLA-4841-1 / DLA-4850-1 (12: 6.1.190-1)
    "Ubuntu": False,    # 22.04-26.10 fix in progress, 16.04-20.04 no fix announced
    "RHEL": False,      # RHEL 8/9/10 deferred; AlmaLinux fixes only in testing (30 Oct)
    "Oracle": None,     # UEK fixed 16 Oct (ELSA-2026-500397/8/9), RHCK not
    "SUSE": None,       # SLES 16 / 15 SP4-SP6 fixed, SLES 15 SP7 in progress
    "openSUSE": None,   # Leap 16.0 fixed, older Leap unclear
    "Amazon": None,     # AL2023 kernel6.18/6.12 fixed, default AL2023 kernel and AL2 pending
}

# (distro, where, regex). The engine already captured headers; we read the
# vendor's OWN build tag out of the Server header. A capture group, if any,
# is the distro's release hint - not used for the verdict, only shown.
FINGERPRINTS = [
    ("RHEL", "header", r"^server:[^\n]*\b(?:red\s?hat|rhel|centos|rocky|almalinux|cloudlinux)\b"),
    ("RHEL", "header", r"^server:[^\n]*\.el(\d)\b"),
    ("Oracle", "header", r"^server:[^\n]*\.ol(\d)\b"),
    ("Amazon", "header", r"^server:[^\n]*\bamzn(\d)?\b"),
    ("SUSE", "header", r"^server:[^\n]*\b(?:suse|sles)\b"),
    ("openSUSE", "header", r"^server:[^\n]*\bopensuse\b"),
    ("Ubuntu", "header", r"^server:[^\n]*\bubuntu\b"),
    ("Ubuntu", "header", r"^server:[^\n]*[-~+.](?:\d+)?ubuntu"),
    ("Debian", "header", r"^server:[^\n]*\bdebian\b"),
    ("Debian", "header", r"^server:[^\n]*\+deb(\d+)u"),
    # Non-Linux markers: let us say "NOT LINUX" instead of guessing.
    ("Windows", "header", r"^server:[^\n]*\b(?:microsoft-iis|microsoft-httpapi)\b"),
]
IMPLIES = {}

DISTROS = ["RHEL", "Ubuntu", "Oracle", "Amazon", "SUSE", "openSUSE", "Debian"]
NON_LINUX = {"Windows"}

# Markers that mean a CDN/LB answers, not the origin -> banner says nothing.
PROXY_RX = re.compile(
    r"\b(?:cloudflare|akamaighost|akamai|fastly|varnish|cloudfront|sucuri|"
    r"incapsula|bigip|awselb|google frontend|gws|envoy)\b", re.I)

# --ip-options (CLI only): Record Route with an empty buffer, no routing requested.
# type 0x07 (RR), len 39, pointer 4, then zero bytes.
IP_OPT_RECORD_ROUTE = bytes([0x07, 39, 4]) + bytes(36)


def builtin_count():
    return len({t for t, _, _ in FINGERPRINTS if t not in NON_LINUX})


def fix_status(distro):
    """True / False / None, see FIX_STATUS."""
    return FIX_STATUS.get(distro)


# --------------------------------------------------------------------------
# distro detection from fingerprints
# --------------------------------------------------------------------------
def distro_found(info):
    """Return (distro or '', non_linux bool, via-evidence)."""
    for t in info["techs"]:
        if t in NON_LINUX:
            return "", True, t
    for d in DISTROS:
        if d in info["techs"]:
            return d, False, d
    return "", False, ""


# --------------------------------------------------------------------------
# IP-options reachability probe (command line only, opt-in with --ip-options)
# --------------------------------------------------------------------------
def probe(info):
    """
    One control connect (no options) and one test connect (Record Route) to the
    pinned IP on the final port. Result: 'reach' (options get through),
    'filtered' (control ok, options time out / reset), 'noport', or
    'unsupported' (this OS refused IP_OPTIONS). A SINGLE connect each - no
    floods, no retransmits, nothing that approaches the race.
    """
    log, timeout = info["log"], info["timeout"]
    ips = sorted(info.get("server_ips") or [])
    final = info.get("final", "")
    host = (urlparse(final).hostname or "").strip("[]") if final else ""
    ip = ips[0] if ips else host
    port = urlparse(final).port or (443 if final.startswith("https") else 80)
    if not ip:
        info["probe"] = {"result": "noport"}
        return

    log("  probe: TCP connect to %s:%s, plain then with a Record-Route IP option" % (ip, port))
    try:
        with socket.create_connection((ip, port), timeout):
            pass
    except OSError:
        info["probe"] = {"result": "noport"}
        info["evidence"].append("probe:noport")
        log("  probe: control connect failed")
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, IP_OPT_RECORD_ROUTE)
        except OSError:
            info["probe"] = {"result": "unsupported"}
            info["evidence"].append("probe:unsupported")
            log("  probe: this client OS refused IP_OPTIONS")
            return
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            result = "reach"
        except socket.timeout:
            result = "filtered"
        except OSError:
            result = "filtered"
    finally:
        s.close()
    info["probe"] = {"result": result, "ip": ip, "port": port}
    info["evidence"].append("probe:%s" % result)
    log("  probe: %s" % result)


# --------------------------------------------------------------------------
# verdict
# --------------------------------------------------------------------------
def verdict(info):
    """(verdict, distro, os-list) for the result row. Never VULNERABLE or PATCHED:
    the kernel itself can't be seen from outside."""
    distro, non_linux, via = distro_found(info)
    if non_linux:
        return "NOT LINUX", "", [via]
    if not distro or PROXY_RX.search(info.get("server") or ""):
        return "UNKNOWN", distro, [distro] if distro else []
    info["fix"] = fix_status(distro)
    return "POSSIBLY VULNERABLE", distro, [distro]


def count_key(v):
    return v


def verdict_style(row):
    """(rank, colour, status, reason) for the result list."""
    v, distro = row[3], row[4]
    if v == "POSSIBLY VULNERABLE":
        fx = fix_status(distro)
        if fx is False:
            return 18, "yellow", v, "%s: no fixed kernel released yet" % distro
        if fx is True:
            return 22, "yellow", v, "%s: fixed kernel out, check it's installed and booted" % distro
        return 20, "yellow", v, "%s: fixed for some releases, check yours" % distro
    if v == "UNKNOWN":
        if distro:
            return 45, "plain", v, "%s behind a proxy/CDN" % distro
        return 48, "plain", v, "distribution not visible"
    if v == "NOT LINUX":
        return 55, "plain", v, "not a Linux host"
    return None


EXAMPLES = """examples:
  kernel98scan.py --on-host                          real verdict for THIS machine
  kernel98scan.py 203.0.113.10                       20 web ports + every vhost on the IP
  kernel98scan.py 198.51.100.0/24 --names domains.txt a whole range + your own hostnames
  kernel98scan.py 203.0.113.10 --ip-options          + do IP-options packets reach the host?

status: POSSIBLY VULNERABLE (Linux distribution visible: no fix yet / fix available) -
UNKNOWN (not visible / proxied) - NOT LINUX

From outside only the distribution is visible, never the kernel. --on-host is the final word.
"""


def add_arguments(ap):
    g = ap.add_argument_group("CVE-2026-98432 options")
    g.add_argument("--on-host", action="store_true",
                   help="ignore targets and run the on-host kernel check for %s on THIS machine "
                        "(reads uname -r, the package changelog, pending reboot and mitigations)" % CVE)


    g.add_argument("--ip-options", action="store_true",
                   help="also open ONE connection whose SYN carries a Record-Route IP option, to see "
                        "whether such packets reach the host (the path the bug needs). Only on your "
                        "own hosts; a single connect can't trigger the bug")


def options_from_args(a):
    if getattr(a, "on_host", False):
        raise SystemExit(run_on_host())
    if a.ip_options:
        print("IP-options test: on (one Record-Route connect per endpoint)", file=sys.stderr, flush=True)
        return {"probe": True}
    return {}


# ---------------------------------------------------------------------------
# web page (web.py): assessment shown to visitors
# ---------------------------------------------------------------------------
CONSENT_VERSION = "2026-11-02.2"

WHERE = {"header": "Server header"}

FIXED_TABLE = [   # (software, versions, note, distro) - keep in step with FIX_STATUS
    ("Debian 13 / 12", "6.12.113-1 / 6.1.190-1", "fixed (DSA-6568-1, DLA-4841-1); needs security.debian.org", "Debian"),
    ("Ubuntu 22.04 to 26.10", "", "fix in progress, not released yet", "Ubuntu"),
    ("Ubuntu 16.04 to 20.04", "", "no fix announced", "Ubuntu"),
    ("RHEL 8 / 9 / 10, Rocky", "", "fix deferred by Red Hat", "RHEL"),
    ("AlmaLinux 8 / 9 / 10", "", "fixed kernels in the testing repository only", "RHEL"),
    ("Oracle Linux UEK", "", "fixed 16 Oct (ELSA-2026-500397/8/9); RHCK not yet", "Oracle"),
    ("SLES 16 / 15 SP4-SP6, Leap 16", "", "fixed; SLES 15 SP7 in progress", "SUSE"),
    ("Amazon Linux 2023", "", "kernel6.18 / kernel6.12 fixed; default kernel and AL2 pending", "Amazon"),
    ("Upstream stable", "5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10", "", ""),
]

MITIGATION = ("Until a fixed kernel runs, drop IPv4 TCP packets that carry IP options before they reach "
              "the kernel, e.g. nftables: nft add table ip cve98432; nft add chain ip cve98432 pre "
              "'{ type filter hook prerouting priority -300; }'; nft add rule ip cve98432 pre meta "
              "l4proto tcp ip hdrlength != 5 drop. Turn off MPTCP where you don't need it "
              "(sysctl net.mptcp.enabled=0): the reported exploit goes through it.")
STEPS_NOFIX = [MITIGATION,
               "Install your distribution's fixed kernel as soon as it ships, then reboot into it.",
               "Run kernel98scan --on-host on the server for a real verdict."]
STEPS_FIX = ["Install the fixed kernel from your distribution's security updates and REBOOT: a fixed "
             "kernel that isn't running doesn't protect you. Check with uname -r.",
             "Run kernel98scan --on-host on the server: it reads the running kernel and its changelog.",
             MITIGATION]

NOTE_GENERAL = ("The banner describes the web server's packages, not necessarily the kernel: behind a "
                "reverse proxy or inside a container the kernel belongs to another machine. Run "
                "%s --on-host on the server for the final word." % NAME)


def web_options(data):
    return {}                    # the web page never sends the IP-options connect


def web_result(host, ip, row, info, friendly_evidence):
    _, final, status, verdict_, distro, oslist, server, evidence = row
    result = {"host": host, "ip": ip, "final_url": final, "http_status": status,
              "reachable": verdict_ not in ("ERROR", "SNI ONLY"), "verdict": verdict_,
              "server": server, "distro": distro, "os": [], "evidence": [],
              "fixed": [], "steps": [], "probe": None, "note": NOTE_GENERAL, "error": ""}
    if verdict_ == "ERROR":
        result["error"] = evidence
    if verdict_ == "SNI ONLY":
        result["error"] = "The server refused the HTTPS connection for this hostname."
    if not result["reachable"] or not info:
        result["status"] = {"level": "unknown", "title": "Not reachable",
                            "text": "We couldn't reach this host."}
        return result

    result["os"] = [t for t in oslist.split(", ") if t]
    result["evidence"] = friendly_evidence(", ".join(x for x in info["evidence"]
                                                      if not x.startswith("probe:")))
    proxied = bool(PROXY_RX.search(server or ""))

    if verdict_ == "NOT LINUX":
        result["status"] = {"level": "good", "title": "Not a Linux host",
                            "text": "This server looks like %s, so the Linux kernel bug %s doesn't "
                                    "apply to it." % (oslist or "a non-Linux system", CVE)}
        return result

    result["fixed"] = [{"software": s_, "versions": v, "note": n, "found": bool(d and d == distro)}
                       for s_, v, n, d in FIXED_TABLE]
    if verdict_ == "POSSIBLY VULNERABLE":
        fx = fix_status(distro)
        if fx is False:
            txt = ("This server shows %s, and %s has not released a fixed kernel for %s yet. If the "
                   "kernel on this machine is %s's, it can't be patched right now: block IP-options "
                   "packets at the firewall until the fix is out." % (distro, distro, CVE, distro))
            result["steps"] = STEPS_NOFIX
            title = "Possibly vulnerable: no fix yet"
        elif fx is True:
            txt = ("This server shows %s, which has released a fixed kernel. Whether it's installed "
                   "and running can't be seen from outside: update and reboot, then check with "
                   "uname -r or --on-host." % distro)
            result["steps"] = STEPS_FIX
            title = "Possibly vulnerable: fix available"
        else:
            txt = ("This server shows %s. Some %s releases have a fixed kernel, others don't yet. "
                   "Check your release in the table below." % (distro, distro))
            result["steps"] = STEPS_FIX
            title = "Possibly vulnerable: check your release"
        result["status"] = {"level": "warn", "title": title, "text": txt}
        return result

    # UNKNOWN
    if proxied:
        txt = ("A proxy or CDN answers for this host, so its banner says nothing about the server "
               "behind it. Check the kernel on that server itself.")
    else:
        txt = ("This host doesn't reveal its operating system, so its kernel can't be judged from "
               "outside. Every Linux kernel from 4.4 on is affected until it's updated: check "
               "on the host.")
    result["status"] = {"level": "unknown", "title": "Can't tell from outside", "text": txt}
    result["steps"] = ["Run kernel98scan --on-host on the server for a real verdict.", MITIGATION]
    return result


def web_timeout_result(host, ip):
    return {"host": host, "ip": ip, "reachable": False, "verdict": "ERROR", "distro": "", "os": [],
            "error": "The host took too long to respond.", "evidence": [], "fixed": [], "steps": [],
            "probe": None, "note": NOTE_GENERAL,
            "status": {"level": "unknown", "title": "Not reachable",
                       "text": "The host took too long to respond."}}


def audit_fields(result):
    outcome = result.get("verdict", "ERROR").lower().replace(" ", "-")
    if outcome in ("error", "sni-only"):
        outcome = "unreachable"
    return {"outcome": outcome, "distro": result.get("distro", ""),
            "probe": (result.get("probe") or {}).get("result")}


# ---------------------------------------------------------------------------
# on-host check (kernel98scan --on-host): the only path that gives a real
# vulnerable / mitigated / fixed verdict. Reads the running kernel; never
# triggers the bug.
# ---------------------------------------------------------------------------
FIX_COMMIT_HINTS = ("CVE-2026-98432",)          # distro changelogs name the CVE
UPSTREAM_FIXED = {(5, 10): "5.10.272", (5, 15): "5.15.223", (6, 1): "6.1.190", (6, 6): "6.6.159",
                  (6, 12): "6.12.113", (6, 18): "6.18.56", (7, 2): "7.2.10"}


def _sh(cmd):
    import subprocess
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return ""


def run_on_host():
    import os
    running = _sh(["uname", "-r"])
    osr = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, val = line.rstrip().split("=", 1)
                    osr[k] = val.strip('"')
    except OSError:
        pass
    is_pve = bool(_sh(["sh", "-c", "command -v pveversion"])) or os.path.exists("/etc/pve")

    def parse(v):
        m = re.match(r"(\d+)\.(\d+)\.(\d+)", v or "")
        return tuple(int(x) for x in m.groups()) if m else None

    # changelog is authoritative: catches backports whose version looks old
    changelog_fix = False
    if os.path.exists("/usr/bin/dpkg"):
        for cand in ("linux-image-%s" % running,
                     "proxmox-kernel-" + ".".join(running.split(".")[:2])):
            cl = _sh(["sh", "-c",
                      "zcat -f /usr/share/doc/%s/changelog* 2>/dev/null | head -n 400" % cand])
            if any(h in cl for h in FIX_COMMIT_HINTS):
                changelog_fix = True
                break
    elif os.path.exists("/usr/bin/rpm"):
        cl = _sh(["rpm", "-q", "--changelog", "kernel"])
        changelog_fix = any(h in cl for h in FIX_COMMIT_HINTS)

    # reboot pending: newest installed kernel newer than the running one
    newest = _sh(["sh", "-c",
                  "ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|.*/vmlinuz-||' | sort -V | tail -1"])
    pending = bool(newest and newest != running) or os.path.exists("/var/run/reboot-required")

    def sysctl(key):
        try:
            with open("/proc/sys/" + key.replace(".", "/")) as f:
                return f.read().strip()
        except OSError:
            return None
    mptcp = sysctl("net.mptcp.enabled")
    tmr = sysctl("net.ipv4.tcp_migrate_req")

    # decide
    level, title, text = "unknown", "Unknown", ""
    if changelog_fix and not pending:
        level, title = "good", "Fixed and booted"
        text = "The running kernel's changelog references the %s fix and no newer kernel is installed." % CVE
    elif changelog_fix and pending:
        level, title = "warn", "Fixed kernel installed but not booted"
        text = "A kernel whose changelog references the %s fix is installed, but %s is running and %s " \
               "is on disk. Reboot into it." % (CVE, running, newest)
    else:
        pv = parse(running)
        decided = False
        # plain upstream numbering only (Debian keeps it); vendor kernels (Ubuntu 6.8.0-149,
        # RHEL 5.14.0-687, Proxmox) backport fixes onto old numbers: only the changelog counts
        upstream_like = bool(re.match(r"\d+\.\d+\.\d+(?:-\d+)?(?:-(?:amd64|arm64|cloud-amd64|generic))?$",
                                      running)) and not is_pve
        if pv and upstream_like:
            for (maj, mnr), fixed in UPSTREAM_FIXED.items():
                if pv[0] == maj and pv[1] == mnr and pv >= parse(fixed):
                    level, title = "good", "Kernel at or above the fixed version"
                    text = "Running %s, at or above the %d.%d branch fix %s." % (running, maj, mnr, fixed)
                    decided = True
                    break
        if not decided:
            level, title = "bad", "Vulnerable - no fix evidence"
            text = "Running %s and nothing shows the %s fix is in it. Install your distribution's " \
                   "fixed kernel and reboot. If there is none yet, drop IPv4 TCP packets with IP " \
                   "options at the firewall (nftables: meta l4proto tcp ip hdrlength != 5 drop)" \
                   "%s." % (running, CVE, " and turn off MPTCP (net.mptcp.enabled=0)" if mptcp == "1" else "")

    badge = {"bad": "[!] VULNERABLE", "warn": "[?] CHECK", "good": "[+] FIXED",
             "unknown": "[-] UNKNOWN"}.get(level, "[-] UNKNOWN")
    print("%s  %s" % (badge, CVE))
    print("  %s" % title)
    print("  %s" % text)
    print()
    print("  running kernel : %s" % running)
    print("  os-release     : %s %s" % (osr.get("ID", "?"), osr.get("VERSION_ID", "")))
    print("  proxmox        : %s" % is_pve)
    print("  changelog fix  : %s" % changelog_fix)
    print("  reboot pending : %s" % pending)
    print("  mptcp enabled  : %s   (the reported exploit uses MPTCP listeners; check: ss -Mlnp)" % mptcp)
    print("  tcp_migrate_req: %s   (should be 0)" % tmr)
    return {"bad": 2, "warn": 1, "good": 0}.get(level, 3)
