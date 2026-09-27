#!/usr/bin/env python3
"""Scan the local machine for installed software and print name + version.

Cross-platform (Windows, macOS, Linux), stdlib only, no third-party deps.

"Software", not packages: this looks for the things a user would recognize as
an installed application (Windows Control Panel entries, macOS .app bundles,
Linux desktop launchers) rather than every OS/library package. On Linux there
is no such registry, so a desktop launcher's version is resolved through the
package that owns its executable as a targeted, single-app lookup, not a bulk
package-manager dump; a bulk "manually installed packages" listing is still
available, but only opt-in via --include-packages.
"""

from __future__ import annotations

import argparse
import difflib
import getpass
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__


@dataclass
class App:
    name: str
    version: str
    publisher: str
    source: str
    location: str


# --------------------------------------------------------------------------
# Windows: the registry's Uninstall keys are exactly what Control Panel /
# "Apps & features" reads from, so this is the standard installed-software
# list, not a package manager dump.
# --------------------------------------------------------------------------
def scan_windows(verbose: bool = False) -> list[App]:
    import winreg

    hives = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    seen: dict[str, App] = {}
    for hive, path in hives:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
            except OSError:
                continue
            with subkey:
                def get(field: str) -> str:
                    try:
                        return str(winreg.QueryValueEx(subkey, field)[0]).strip()
                    except OSError:
                        return ""

                name = get("DisplayName")
                if not name:
                    continue
                # SystemComponent=1 marks a hidden runtime/update entry, not
                # something a user would call "installed software" (matches
                # what Control Panel itself hides).
                try:
                    is_system_component = winreg.QueryValueEx(subkey, "SystemComponent")[0]
                except OSError:
                    is_system_component = 0
                if is_system_component:
                    continue
                if get("ParentKeyName") or get("ReleaseType") in ("Update", "Hotfix", "Security Update"):
                    continue

                version = get("DisplayVersion") or "-"
                publisher = get("Publisher") or "-"
                location = get("InstallLocation") or get("InstallSource") or "-"
                key_id = f"{name}|{version}"
                if key_id in seen:
                    continue
                seen[key_id] = App(name=name, version=version, publisher=publisher,
                                    source="registry", location=location)
    if verbose:
        print(f"[scan] windows: {len(seen)} entries from registry Uninstall keys", file=sys.stderr)
    return list(seen.values())


# --------------------------------------------------------------------------
# macOS: .app bundles under /Applications, ~/Applications, and
# /System/Applications carry their own version in Info.plist. This is the
# same source Finder/"About This App" reads, not a package receipt dump.
# --------------------------------------------------------------------------
def scan_macos(verbose: bool = False) -> list[App]:
    import plistlib

    search_dirs = [
        Path("/Applications"),
        Path("/System/Applications"),
        Path.home() / "Applications",
    ]
    apps: list[App] = []
    scanned = 0
    for base in search_dirs:
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            if entry.suffix != ".app":
                continue
            scanned += 1
            plist_path = entry / "Contents" / "Info.plist"
            name = entry.stem
            version = "-"
            publisher = "-"
            if plist_path.is_file():
                try:
                    with open(plist_path, "rb") as f:
                        info = plistlib.load(f)
                    name = info.get("CFBundleName") or info.get("CFBundleDisplayName") or name
                    version = (info.get("CFBundleShortVersionString")
                               or info.get("CFBundleVersion") or "-")
                    bundle_id = info.get("CFBundleIdentifier", "")
                    if bundle_id.count(".") >= 1:
                        publisher = bundle_id.split(".")[1] if bundle_id.startswith("com.") else bundle_id.split(".")[0]
                except (OSError, ValueError, plistlib.InvalidFileException):
                    pass
            apps.append(App(name=name, version=str(version), publisher=publisher,
                             source="app-bundle", location=str(entry)))
    if verbose:
        print(f"[scan] macos: {scanned} .app bundles under {len(search_dirs)} directories", file=sys.stderr)
    return apps


# --------------------------------------------------------------------------
# Linux: no OS-wide "installed software" registry, so desktop launcher
# entries (what an app menu shows) stand in for it. Version comes from the
# single package that owns the launcher's own executable, a one-app lookup,
# never a bulk package-manager dump.
# --------------------------------------------------------------------------
def _parse_desktop_entry(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    in_main_section = False
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return fields
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_main_section = stripped == "[Desktop Entry]"
            continue
        if not in_main_section or not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        if key not in fields:  # first occurrence wins (locale variants come after)
            fields[key] = value.strip()
    return fields


def _resolve_binary(exec_line: str) -> str | None:
    if not exec_line:
        return None
    # Strip desktop-entry field codes (%f, %U, ...) and quoting, keep argv[0].
    token = exec_line.split()[0] if exec_line.split() else ""
    token = token.strip('"')
    if not token:
        return None
    if os.path.isabs(token):
        return token if os.path.exists(token) else None
    return shutil.which(token)


def _run(cmd: list[str], timeout: float = 2.0) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _package_version_for_binary(binary: str) -> tuple[str, str]:
    """Best-effort (version, publisher/package) for the package owning `binary`."""
    resolved = binary
    try:
        resolved = os.path.realpath(binary)
    except OSError:
        pass

    if shutil.which("dpkg"):
        owner = _run(["dpkg", "-S", resolved])
        pkg = owner.split(":")[0].strip() if ":" in owner.split("\n")[0] else ""
        if pkg:
            ver = _run(["dpkg-query", "-W", "-f=${Version}", pkg])
            if ver:
                return ver, pkg
    if shutil.which("rpm"):
        pkg = _run(["rpm", "-qf", "--qf", "%{NAME}", resolved])
        if pkg and "not owned" not in pkg and "is not owned" not in pkg:
            ver = _run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg])
            if ver:
                return ver, pkg
    if shutil.which("pacman"):
        owner = _run(["pacman", "-Qo", resolved])
        # "<path> is owned by <pkg> <version>"
        parts = owner.split(" is owned by ")
        if len(parts) == 2:
            pkg_ver = parts[1].strip().split()
            if len(pkg_ver) == 2:
                return pkg_ver[1], pkg_ver[0]
    return "-", "-"


def scan_linux(verbose: bool = False, exec_version: bool = False) -> list[App]:
    search_dirs = [
        Path("/usr/share/applications"),
        Path("/usr/local/share/applications"),
        Path.home() / ".local/share/applications",
    ]
    apps: list[App] = []
    seen_names: set[str] = set()
    scanned = 0
    for base in search_dirs:
        if not base.is_dir():
            continue
        for entry in sorted(base.glob("*.desktop")):
            scanned += 1
            fields = _parse_desktop_entry(entry)
            if fields.get("NoDisplay") == "true" or fields.get("Type", "Application") != "Application":
                continue
            name = fields.get("Name")
            if not name or name in seen_names:
                continue
            seen_names.add(name)

            version, publisher = "-", "-"
            binary = _resolve_binary(fields.get("Exec", ""))
            if binary:
                version, publisher = _package_version_for_binary(binary)
                if version == "-" and exec_version:
                    for flag in ("--version", "-version", "-V", "-v"):
                        out = _run([binary, flag])
                        if out:
                            version = out.splitlines()[0][:120]
                            break
            apps.append(App(name=name, version=version, publisher=publisher,
                             source="desktop-entry", location=str(entry)))
    if verbose:
        print(f"[scan] linux: {scanned} desktop entries under {len(search_dirs)} directories", file=sys.stderr)
    return apps


def scan_linux_manual_packages(verbose: bool = False) -> list[App]:
    """Opt-in bulk listing of packages the user explicitly asked to install
    (not every dependency pulled in with them)."""
    apps: list[App] = []
    if shutil.which("apt-mark"):
        names = _run(["apt-mark", "showmanual"]).splitlines()
        for name in names:
            ver = _run(["dpkg-query", "-W", "-f=${Version}", name])
            apps.append(App(name=name, version=ver or "-", publisher="apt",
                             source="package (manual)", location="-"))
    elif shutil.which("dnf"):
        out = _run(["dnf", "repoquery", "--userinstalled", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}"], timeout=15.0)
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                apps.append(App(name=parts[0], version=parts[1], publisher="dnf",
                                 source="package (manual)", location="-"))
    elif shutil.which("pacman"):
        out = _run(["pacman", "-Qe"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                apps.append(App(name=parts[0], version=parts[1], publisher="pacman",
                                 source="package (manual)", location="-"))
    if verbose:
        print(f"[scan] linux: {len(apps)} manually installed packages", file=sys.stderr)
    return apps


def scan(verbose: bool = False, include_packages: bool = False, exec_version: bool = False) -> list[App]:
    system = platform.system()
    if system == "Windows":
        return scan_windows(verbose=verbose)
    if system == "Darwin":
        return scan_macos(verbose=verbose)
    if system == "Linux":
        apps = scan_linux(verbose=verbose, exec_version=exec_version)
        if include_packages:
            apps += scan_linux_manual_packages(verbose=verbose)
        return apps
    raise SystemExit(f"Unsupported platform: {system!r}")


# --------------------------------------------------------------------------
# Upload to a ReleaseTrain account ("Installed versions", Account page)
#
# The password is never accepted as a CLI argument: a plain --password would
# sit in shell history and be visible to other local processes via `ps`.
# Instead: --email is a plain argument, the password comes from
# RELEASETRAIN_PASSWORD or a hidden getpass prompt, and a successful login's
# token is cached at ~/.releasetrain/token.json (mode 600) so later runs
# don't need to re-enter credentials until it expires.
# --------------------------------------------------------------------------
RT_TOKEN_FILE = Path.home() / ".releasetrain" / "token.json"
RT_MACHINE_FILE = Path.home() / ".releasetrain" / "machine.json"
RT_MAX_COMPONENT_LEN = 64
RT_MAX_VERSION_LEN = 32
RT_MAX_VENDOR_LEN = 64
RT_MAX_MACHINE_LEN = 80
RT_VERSION_RX = None  # set below, mirrors the server/client's own validation


def rt_os_label() -> str:
    system = platform.system()
    if system == "Windows":
        return f"Windows {platform.release()}"
    if system == "Darwin":
        return f"macOS {platform.mac_ver()[0] or platform.release()}"
    return system or "unknown OS"


def rt_default_machine_label() -> str:
    return f"{platform.node() or 'unknown-host'} ({rt_os_label()})"


def rt_get_machine_label(args: argparse.Namespace) -> str:
    """A stable per-computer label, e.g. 'DESKTOP-ABC123 (Windows 11)', so
    the same component recorded from two of a user's own machines doesn't
    collide as one row. --machine overrides and is remembered for next time;
    otherwise the last-used (or freshly auto-detected) label is reused, so
    running this script again from the same machine doesn't need --machine
    repeated every time."""
    if args.machine:
        _rt_save_machine_label(args.machine)
        return args.machine
    try:
        cached = json.loads(RT_MACHINE_FILE.read_text(encoding="utf-8")).get("machine")
        if cached:
            return cached
    except (OSError, ValueError, AttributeError):
        pass
    label = rt_default_machine_label()
    _rt_save_machine_label(label)
    return label


def _rt_save_machine_label(label: str) -> None:
    try:
        RT_MACHINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        RT_MACHINE_FILE.write_text(json.dumps({"machine": label}), encoding="utf-8")
    except OSError:
        pass  # caching is best-effort; --machine still works without it


def _rt_valid_version(v: str) -> bool:
    import re
    global RT_VERSION_RX
    if RT_VERSION_RX is None:
        RT_VERSION_RX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9 ._+:-]*$")
    return bool(RT_VERSION_RX.match(v))


def _rt_api(api_base: str, path: str, token: str | None = None,
            method: str = "GET", body: dict | None = None, timeout: float = 15.0) -> tuple[int, dict]:
    url = api_base.rstrip("/") + "/" + path.lstrip("/")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode("utf-8") or "{}")
        except (ValueError, OSError):
            payload = {}
        return e.code, payload
    except urllib.error.URLError as e:
        raise SystemExit(f"Could not reach {api_base}: {e.reason}")


def _rt_load_cached_token() -> tuple[str, str] | None:
    try:
        data = json.loads(RT_TOKEN_FILE.read_text(encoding="utf-8"))
        return data["token"], data.get("email", "")
    except (OSError, ValueError, KeyError):
        return None


def _rt_save_token(token: str, email: str) -> None:
    try:
        RT_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        RT_TOKEN_FILE.write_text(json.dumps({"token": token, "email": email}), encoding="utf-8")
        if os.name != "nt":
            os.chmod(RT_TOKEN_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # caching is best-effort; upload still works without it


def _rt_login(api_base: str, email: str) -> str:
    password = os.environ.get("RELEASETRAIN_PASSWORD")
    if not password:
        if not sys.stdin.isatty():
            raise SystemExit("No password available: set RELEASETRAIN_PASSWORD or run interactively.")
        password = getpass.getpass(f"ReleaseTrain password for {email}: ")
    status, payload = _rt_api(api_base, "auth/login", method="POST",
                               body={"email": email, "password": password})
    if status != 200 or not payload.get("token"):
        raise SystemExit(f"Login failed: {payload.get('error', 'unknown error')}")
    _rt_save_token(payload["token"], email)
    return payload["token"]


def rt_get_token(api_base: str, args: argparse.Namespace) -> str:
    if args.token:
        return args.token
    if os.environ.get("RELEASETRAIN_TOKEN"):
        return os.environ["RELEASETRAIN_TOKEN"]

    cached = _rt_load_cached_token()
    if cached:
        token, _ = cached
        status, _ = _rt_api(api_base, "users/me", token=token)
        if status == 200:
            return token  # cached token still valid; skip logging in again

    email = args.email or os.environ.get("RELEASETRAIN_EMAIL")
    if not email:
        if not sys.stdin.isatty():
            raise SystemExit("No credentials available: pass --email, --token, or set "
                              "RELEASETRAIN_TOKEN/RELEASETRAIN_EMAIL.")
        email = input("ReleaseTrain email: ").strip()
    return _rt_login(api_base, email)


RT_COMPONENT_MAP_FILE = Path.home() / ".releasetrain" / "component-map.json"

# ReleaseTrain only tracks a bare product name (versionProductName, e.g.
# "Chrome", "VirtualBox") and matches it case-insensitively, exact string
# only - it has no separate vendor/publisher field at all. A local scan's
# `name`, on the other hand, very often has the vendor baked into the
# product name itself ("Oracle VirtualBox 7.2.16", "Google Chrome"), or the
# vendor sits only in `publisher` ("Microsoft Corporation") while it's not
# in the product name at all ("Microsoft Edge" would need "Edge"). So the
# fix isn't "map the publisher to something on ReleaseTrain's side" (there's
# nothing there to map it to) - it's "use the publisher to recognize and
# strip the vendor prefix off the product name," then compare what's left
# against ReleaseTrain's own tracked names, tolerating small typos on both
# sides (a scanned Publisher string is exactly as messy as "Mircosoft" or
# "Microsoft Cooperation" in the wild).
RT_ORG_FILLER_PHRASES = ["and/or its affiliates", "and its affiliates"]
RT_ORG_GENERIC_WORDS = {
    "corporation", "corp", "incorporated", "inc", "llc", "ltd", "limited",
    "co", "company", "gmbh", "group", "holdings", "plc", "srl", "sa", "ag",
    "sarl", "bv", "oy", "kk", "pte", "pty", "systems", "software", "labs",
}
RT_NAME_NOISE_WORDS = {
    "edition", "desktop", "runtime", "for", "workplace", "x64", "x86",
    "64bit", "32bit", "64-bit", "32-bit", "amd64", "arm64",
}
RT_FUZZY_CUTOFF = 0.82


def _rt_fuzzy_eq(a: str, b: str, cutoff: float = RT_FUZZY_CUTOFF) -> bool:
    return a == b or difflib.SequenceMatcher(None, a, b).ratio() >= cutoff


def _rt_vendor_words(publisher: str) -> list[str]:
    """Publisher -> its core brand word(s), with legal/generic suffix words
    fuzzy-stripped so a typo ("Cooperation" for "Corporation") still counts."""
    if not publisher or publisher == "-":
        return []
    text = publisher
    for phrase in RT_ORG_FILLER_PHRASES:
        text = re.sub(re.escape(phrase), " ", text, flags=re.IGNORECASE)
    words = re.findall(r"[A-Za-z0-9']+", text)
    while words:
        last = words[-1].lower()
        if last in RT_ORG_GENERIC_WORDS or any(_rt_fuzzy_eq(last, s) for s in RT_ORG_GENERIC_WORDS):
            words.pop()
            continue
        break
    return words


def _rt_is_version_token(word: str) -> bool:
    return bool(re.match(r"^v?\d+(\.\d+){0,4}[a-z]?$", word, re.IGNORECASE))


def rt_normalize_name(name: str, publisher: str) -> str:
    """Best-guess bare product name: vendor prefix (from `publisher`, typo-
    tolerant) stripped off the front, then version numbers/bitness/edition
    noise dropped from what remains."""
    text = re.sub(r"\([^)]*\)", " ", name).replace("™", "").replace("®", "").replace("©", "")
    words = re.findall(r"[A-Za-z0-9.+#-]+", text)

    vendor_words = _rt_vendor_words(publisher)
    i = 0
    while i < len(vendor_words) and i < len(words) and _rt_fuzzy_eq(words[i].lower(), vendor_words[i].lower()):
        i += 1
    words = words[i:] or words  # never strip down to nothing

    words = [w for w in words if not _rt_is_version_token(w) and w.lower() not in RT_NAME_NOISE_WORDS]
    return " ".join(words).strip()


def rt_fetch_component_names(api_base: str) -> list[str]:
    try:
        status, payload = _rt_api(api_base, "c/names")
        return payload if status == 200 and isinstance(payload, list) else []
    except SystemExit:
        return []  # matching is best-effort; a failed fetch just disables it


def rt_load_component_map(path: Path) -> dict[str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return {str(k).strip().lower(): str(v).strip() for k, v in raw.items()}
    except (OSError, ValueError, AttributeError):
        return {}


def rt_vendor_label(publisher: str) -> str:
    """The cleaned vendor word(s) to store alongside a component, e.g.
    "Microsoft" from "Mircosoft Cooperation" - kept as a separate field
    (see the server's own comment on why) rather than folded into the
    component name."""
    return " ".join(_rt_vendor_words(publisher))


def rt_match_component(app: App, canonical_names: list[str], user_map: dict[str, str]) -> tuple[str, str, str]:
    """Returns (component_name_to_use, method, normalized_guess); method is
    one of map / exact / normalized / fuzzy / unmatched. `normalized_guess`
    is always the vendor-stripped attempt, shown for diagnostics even when
    it wasn't the value used. Only ever used as the actual component when it
    achieved a real match (normalized/fuzzy) - an "unmatched" result falls
    back to the app's own original name instead of the stripped guess, since
    a guess that didn't confirm against anything is exactly what produced
    ambiguous, over-stripped entries like a bare "Host" in the past."""
    key = app.name.strip().lower()
    normalized = rt_normalize_name(app.name, app.publisher)
    if key in user_map:
        return user_map[key], "map", normalized

    canon_lower = {c.lower(): c for c in canonical_names}
    if key in canon_lower:
        return canon_lower[key], "exact", normalized

    norm_lower = normalized.lower()
    if norm_lower in canon_lower:
        return canon_lower[norm_lower], "normalized", normalized
    if norm_lower and canon_lower:
        close = difflib.get_close_matches(norm_lower, list(canon_lower.keys()), n=1, cutoff=0.86)
        if close:
            return canon_lower[close[0]], "fuzzy", normalized
    return app.name.strip(), "unmatched", normalized


def rt_entry_key(e: dict) -> tuple[str, str, str]:
    """Matches the server's own uniqueness key: (component, vendor, machine),
    not component alone, so a same-named component from a different vendor
    or a different one of a user's own machines doesn't clobber another
    entry that happens to share just the component name."""
    return (str(e.get("component", "")).lower(), str(e.get("vendor", "")).lower(), str(e.get("machine", "")).lower())


def rt_upload(apps: list[App], api_base: str, args: argparse.Namespace) -> None:
    canonical_names = rt_fetch_component_names(api_base)
    if not canonical_names and args.verbose:
        print("[upload] could not fetch the tracked component list; uploading best-guess names, unconfirmed", file=sys.stderr)
    user_map = rt_load_component_map(Path(args.map_file))
    machine = "" if args.no_machine else rt_get_machine_label(args)
    if machine and args.verbose:
        print(f"[upload] machine: {machine!r} (override with --machine, or pass --no-machine to omit it)", file=sys.stderr)
    # One timestamp for the whole run: every entry here came from the same
    # scan, so they share one "recorded at", not a slightly-different value
    # per line depending on how long matching/lookup took for each one.
    # "Z", millisecond precision, matching what the server/client's own
    # `new Date().toISOString()` produces - not Python's default "+00:00"
    # offset, so a --dry-run print already shows the normalized form that
    # ends up stored, not something the server has to reformat first.
    recorded_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    entries = []
    skipped_no_version = 0
    match_counts = {"map": 0, "exact": 0, "normalized": 0, "fuzzy": 0, "unmatched": 0}
    unmatched_examples: list[str] = []
    for a in apps:
        version = a.version.strip()[:RT_MAX_VERSION_LEN]
        if not version or version == "-" or not _rt_valid_version(version):
            skipped_no_version += 1
            continue
        component, method, normalized_guess = rt_match_component(a, canonical_names, user_map)
        match_counts[method] += 1
        if method == "unmatched":
            unmatched_examples.append(f"{a.name!r} (tried {normalized_guess!r}, no match; uploading as {component!r})")
            if args.strict_match:
                continue
        entry = {"component": component.strip()[:RT_MAX_COMPONENT_LEN], "version": version, "recordedAt": recorded_at}
        vendor = rt_vendor_label(a.publisher)[:RT_MAX_VENDOR_LEN]
        if vendor:
            entry["vendor"] = vendor
        if machine:
            entry["machine"] = machine
        entries.append(entry)

    if skipped_no_version and args.verbose:
        print(f"[upload] skipping {skipped_no_version} entries with no usable version", file=sys.stderr)
    if canonical_names:
        print(f"Name matching: {match_counts['exact']} exact, {match_counts['normalized']} normalized, "
              f"{match_counts['fuzzy']} fuzzy, {match_counts['map']} from your map file, "
              f"{match_counts['unmatched']} unmatched"
              + (" (dropped, --strict-match)" if args.strict_match and match_counts['unmatched'] else ""))
        if unmatched_examples:
            shown = unmatched_examples[:10]
            print("Unmatched (not a confirmed tracked component name; uploaded under the original scanned "
                  "name so nothing is lost - add a --map-file entry to correct it, or pass --strict-match "
                  "to drop these instead):")
            for line in shown:
                print(f"  {line}")
            if len(unmatched_examples) > len(shown):
                print(f"  ... and {len(unmatched_examples) - len(shown)} more")
    if not entries:
        print("Nothing to upload: no entries have a usable version.")
        return

    token = rt_get_token(api_base, args)
    status, me = _rt_api(api_base, "users/me", token=token)
    if status != 200:
        raise SystemExit(f"Could not load your account: {me.get('error', status)}")
    user_id = me.get("_id") or me.get("id")

    merged = entries
    if not args.no_merge:
        existing = me.get("inventory") if isinstance(me.get("inventory"), list) else []
        by_key = {rt_entry_key(e): e for e in existing if e.get("component") and e.get("version")}
        for e in entries:
            by_key[rt_entry_key(e)] = e
        merged = list(by_key.values())
    if len(merged) > 300:
        print(f"Note: {len(merged)} entries exceeds the 300-item limit; keeping the first 300.", file=sys.stderr)
        merged = merged[:300]

    print(f"About to upload {len(entries)} entries to {me.get('email', 'your account')} "
          f"({'merging with' if not args.no_merge else 'replacing'} {len(me.get('inventory') or [])} saved entries).")
    if args.dry_run:
        print(json.dumps(merged, indent=2))
        print("(dry run: nothing was sent)")
        return
    if not args.yes:
        if not sys.stdin.isatty() or input("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            return

    status, result = _rt_api(api_base, f"users/{user_id}", token=token, method="PUT",
                              body={"inventory": merged})
    if status not in (200, 204):
        raise SystemExit(f"Upload failed: {result.get('error', status)}")
    print(f"Uploaded. Your account now has {len(merged)} recorded versions.")


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def print_table(apps: list[App], show_header: bool = True) -> None:
    if not apps:
        print("No software found.")
        return
    columns = [
        ("NAME", "name", max(len(a.name) for a in apps)),
        ("VERSION", "version", max(len(a.version) for a in apps)),
        ("PUBLISHER", "publisher", max(len(a.publisher) for a in apps)),
        ("SOURCE", "source", max(len(a.source) for a in apps)),
    ]
    widths = [max(len(header), width) for header, _, width in columns]
    if show_header:
        print("  ".join(h.ljust(w) for (h, _, _), w in zip(columns, widths)))
        print("  ".join("-" * w for w in widths))
    for a in apps:
        row = [a.name, a.version, a.publisher, a.source]
        print("  ".join(v.ljust(w) for v, w in zip(row, widths)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="releasetrain-inventory",
        description="Scan this machine for installed software (not OS/library packages) and print name + version.",
    )
    parser.add_argument("--json", action="store_true", help="print results as a JSON array instead of a table")
    parser.add_argument("--filter", metavar="TEXT", help="only show entries whose name contains TEXT (case-insensitive)")
    parser.add_argument("--sort", choices=["name", "version", "publisher"], default="name", help="sort key (default: name)")
    parser.add_argument("--reverse", action="store_true", help="reverse the sort order")
    parser.add_argument("--limit", type=int, metavar="N", help="show at most N results")
    parser.add_argument("--no-header", action="store_true", help="omit the table header row")
    parser.add_argument("-o", "--output", metavar="FILE", help="also write the output to FILE")
    parser.add_argument("--all", action="store_true",
                         help="also include entries with no detected version (shown as '-'); hidden by default")
    parser.add_argument("--include-packages", action="store_true",
                         help="Linux only: also list manually installed OS packages (apt/dnf/pacman), off by default")
    parser.add_argument("--exec-version", action="store_true",
                         help="Linux only: if a package can't supply a version, try running the app's own "
                              "--version as a last resort (off by default, since it executes the binary)")
    parser.add_argument("-v", "--verbose", action="store_true", help="print scan diagnostics to stderr")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    upload_group = parser.add_argument_group("upload to ReleaseTrain")
    upload_group.add_argument("--upload", action="store_true",
                               help="upload the results (whatever is shown, after --filter/--all/--sort/--limit) "
                                    "to your ReleaseTrain account's Installed versions")
    upload_group.add_argument("--api-base", default="https://releasetrain.io/api/", help=argparse.SUPPRESS)
    upload_group.add_argument("--email", help="ReleaseTrain account email (or set RELEASETRAIN_EMAIL); "
                                               "the password is never a CLI argument, see README")
    upload_group.add_argument("--token", help="use this token instead of logging in (or set RELEASETRAIN_TOKEN)")
    upload_group.add_argument("--map-file", default=str(RT_COMPONENT_MAP_FILE), metavar="FILE",
                               help=f"JSON {{scanned name: ReleaseTrain component}} overrides (default: {RT_COMPONENT_MAP_FILE})")
    upload_group.add_argument("--strict-match", action="store_true",
                               help="only upload entries that matched a tracked component name; drop unmatched "
                                    "guesses instead of uploading them")
    upload_group.add_argument("--machine", metavar="LABEL",
                               help="label for this computer (default: auto-detected hostname + OS, remembered "
                                    "in ~/.releasetrain/machine.json for next time); lets the same component "
                                    "on two of your machines be recorded as two separate entries")
    upload_group.add_argument("--no-machine", action="store_true", help="don't tag uploaded entries with a machine label")
    upload_group.add_argument("--no-merge", action="store_true",
                               help="replace your saved list instead of merging with it")
    upload_group.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
    upload_group.add_argument("--dry-run", action="store_true", help="show what would be uploaded without contacting the server")
    args = parser.parse_args(argv)

    apps = scan(verbose=args.verbose, include_packages=args.include_packages, exec_version=args.exec_version)

    if args.filter:
        needle = args.filter.lower()
        apps = [a for a in apps if needle in a.name.lower()]

    if not args.all:
        apps = [a for a in apps if a.version and a.version != "-"]

    apps.sort(key=lambda a: getattr(a, args.sort).lower(), reverse=args.reverse)

    if args.limit is not None:
        apps = apps[: args.limit]

    if args.json:
        rendered = json.dumps([asdict(a) for a in apps], indent=2)
    else:
        import io
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            print_table(apps, show_header=not args.no_header)
        finally:
            sys.stdout = old_stdout
        rendered = buf.getvalue().rstrip("\n")

    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        if args.verbose:
            print(f"[scan] wrote output to {args.output}", file=sys.stderr)

    if args.verbose:
        print(f"[scan] {len(apps)} entries after filtering", file=sys.stderr)

    if args.upload:
        rt_upload(apps, args.api_base, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
