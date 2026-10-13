"""SBOM output for releasetrain-inventory: CycloneDX 1.6 and SPDX 2.3 JSON.

Stdlib only, like the rest of the package. Each scanned entry becomes one
component (CycloneDX) or package (SPDX), under one root that stands for the
scanned machine, so other SBOM tools (vulnerability scanners, the
releasetrain patch-status pipeline) can read the inventory in a standard
format instead of this tool's own JSON.

Identifiers are only emitted when they are certain. A package URL (purl) is
written for Linux entries backed by a real package (dpkg/rpm/pacman), since
the package name and its manager are known exactly; Windows registry
entries, macOS app bundles and dev tools get no purl and no CPE, because a
guessed vendor/product identifier makes vulnerability matching worse, not
better (a scanner would trust it).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional
from urllib.parse import quote

# Package-manager label (as recorded by the scanner) -> purl type.
_PURL_TYPES = {"apt": "deb", "dpkg": "deb", "dnf": "rpm", "rpm": "rpm", "pacman": "alpm"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _known(value: Optional[str]) -> Optional[str]:
    """None for the scanner's placeholders ('-', '', None)."""
    if value is None:
        return None
    value = str(value).strip()
    return None if value in ("", "-") else value


def linux_purl(package: str, version: str, manager: Optional[str], distro: Optional[str],
               codename: Optional[str] = None) -> Optional[str]:
    """pkg:deb/ubuntu/auditd@1:3.1.2-2.1build1.1?distro=noble style purl, or None.

    Only for a known package manager and a real package name and version.
    Namespace is the os-release ID, the distro qualifier its codename (or
    version). Encoding matches packageurl-python's canonical form: ':' and
    '~' stay literal in the version (Debian epochs and tildes), '+' and
    everything else reserved is percent-encoded.
    """
    ptype = _PURL_TYPES.get((manager or "").lower())
    package = _known(package)
    version = _known(version)
    if not ptype or not package or not version:
        return None
    ns = (distro or {"deb": "debian", "rpm": "fedora", "alpm": "arch"}[ptype]).lower()
    purl = f"pkg:{ptype}/{quote(ns, safe='')}/{quote(package, safe='')}@{quote(version, safe=':~')}"
    return f"{purl}?distro={quote(codename.lower(), safe='')}" if codename else purl


def _package_of(app, manager: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """(package name, package manager) when the entry is backed by an OS package.

    'package (manual)' entries store the package as the name and the manager
    label as the publisher; Linux desktop entries store the package that owns
    the launcher's executable in the publisher field (resolved via dpkg/rpm/
    pacman, the manager the caller detected).
    """
    if app.source == "package (manual)":
        return app.name, app.publisher
    if app.source == "desktop-entry" and _known(app.publisher):
        return app.publisher, manager
    return None, None


def _publisher_of(app) -> Optional[str]:
    """A real publisher/vendor, never a package name or manager label."""
    if app.source in ("package (manual)", "desktop-entry"):
        return None
    return _known(app.publisher)


def _ref(prefix: str, i: int, name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9.-]+", "-", name).strip("-")[:40] or "item"
    return f"{prefix}{i}-{slug}"


def to_cyclonedx(apps: Iterable, *, tool_version: str, machine: str, os_name: str,
                 manager: Optional[str] = None, distro: Optional[str] = None, codename: Optional[str] = None,
                 timestamp: Optional[str] = None, serial: Optional[str] = None) -> dict:
    """A CycloneDX 1.6 JSON BOM (as a dict) for the scanned machine."""
    components = []
    root_ref = "machine"
    deps = []
    for i, app in enumerate(apps, 1):
        ref = _ref("component-", i, app.name)
        comp = {
            "type": "operating-system" if app.source == "os" else "application",
            "bom-ref": ref,
            "name": app.name,
        }
        version = _known(app.version)
        if version:
            comp["version"] = version
        publisher = _publisher_of(app)
        if publisher:
            comp["publisher"] = publisher
        package, pkg_manager = _package_of(app, manager)
        purl = linux_purl(package, app.version, pkg_manager, distro, codename) if package else None
        if purl:
            comp["purl"] = purl
        props = [{"name": "releasetrain:source", "value": app.source}]
        if _known(app.location):
            props.append({"name": "releasetrain:location", "value": app.location})
        if package:
            props.append({"name": "releasetrain:package", "value": package})
        comp["properties"] = props
        components.append(comp)
        deps.append(ref)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or _now(),
            "tools": {"components": [{
                "type": "application", "name": "releasetrain-inventory", "version": tool_version,
                "externalReferences": [{"type": "vcs", "url": "https://github.com/SE4CPS/releasetrain-inventory"}],
            }]},
            "component": {"type": "device", "bom-ref": root_ref, "name": machine,
                          "properties": [{"name": "releasetrain:os", "value": os_name}]},
        },
        "components": components,
        "dependencies": [{"ref": root_ref, "dependsOn": deps}] + [{"ref": r} for r in deps],
    }


def to_spdx(apps: Iterable, *, tool_version: str, machine: str, os_name: str,
            manager: Optional[str] = None, distro: Optional[str] = None, codename: Optional[str] = None,
            timestamp: Optional[str] = None, namespace: Optional[str] = None) -> dict:
    """An SPDX 2.3 JSON document (as a dict) for the scanned machine."""
    root_id = "SPDXRef-Machine"
    packages = [{
        "SPDXID": root_id,
        "name": machine,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": "DEVICE",
        "comment": f"Machine scanned by releasetrain-inventory ({os_name}).",
    }]
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}]
    for i, app in enumerate(apps, 1):
        sid = _ref("SPDXRef-Package-", i, app.name)
        pkg = {
            "SPDXID": sid,
            "name": app.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "primaryPackagePurpose": "OPERATING-SYSTEM" if app.source == "os" else "APPLICATION",
        }
        version = _known(app.version)
        if version:
            pkg["versionInfo"] = version
        publisher = _publisher_of(app)
        pkg["supplier"] = f"Organization: {publisher}" if publisher else "NOASSERTION"
        package, pkg_manager = _package_of(app, manager)
        purl = linux_purl(package, app.version, pkg_manager, distro, codename) if package else None
        if purl:
            pkg["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]
        notes = [f"source: {app.source}"]
        if _known(app.location):
            notes.append(f"location: {app.location}")
        pkg["comment"] = "; ".join(notes)
        packages.append(pkg)
        relationships.append({"spdxElementId": root_id, "relationshipType": "CONTAINS", "relatedSpdxElement": sid})
    created = timestamp or _now()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"releasetrain-inventory-{machine}",
        "documentNamespace": namespace or f"https://github.com/SE4CPS/releasetrain-inventory/spdx/{quote(machine, safe='')}-{uuid.uuid4()}",
        "creationInfo": {"created": created, "creators": [f"Tool: releasetrain-inventory-{tool_version}"]},
        "packages": packages,
        "relationships": relationships,
    }
