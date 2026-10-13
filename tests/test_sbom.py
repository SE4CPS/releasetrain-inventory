"""SBOM output (CycloneDX 1.6, SPDX 2.3). Stdlib unittest, no network:

    python -m unittest discover -s tests
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from releasetrain_inventory.cli import App, main  # noqa: E402
from releasetrain_inventory.sbom import linux_purl, to_cyclonedx, to_spdx  # noqa: E402

APPS = [
    App(name="Ubuntu", version="24.04.1 LTS", publisher="-", source="os", location="/etc/os-release"),
    App(name="auditd", version="1:3.1.2-2.1build1.1", publisher="apt", source="package (manual)", location="-"),
    App(name="Firefox", version="157.0", publisher="firefox", source="desktop-entry", location="/usr/share/applications/firefox.desktop"),
    App(name="7-Zip 19.00 (x64 edition)", version="19.00.00.0", publisher="Igor Pavlov", source="registry", location="C:\\Program Files\\7-Zip\\"),
    App(name="node", version="22.1.0", publisher="-", source="dev-tool", location="/usr/bin/node"),
]
KW = dict(tool_version="0.3.0", machine="lab-pc", os_name="Linux", manager="dpkg", distro="ubuntu",
          codename="noble", timestamp="2026-10-13T00:00:00Z")


class PurlTests(unittest.TestCase):
    def test_canonical_deb_purl_keeps_epoch_and_tilde(self):
        self.assertEqual(linux_purl("auditd", "1:3.1.2-2.1build1.1", "apt", "ubuntu", "noble"),
                         "pkg:deb/ubuntu/auditd@1:3.1.2-2.1build1.1?distro=noble")
        self.assertEqual(linux_purl("lib++x", "1:2.3+dfsg-1~ubuntu1", "dpkg", "ubuntu", "noble"),
                         "pkg:deb/ubuntu/lib%2B%2Bx@1:2.3%2Bdfsg-1~ubuntu1?distro=noble")

    def test_rpm_and_alpm(self):
        self.assertEqual(linux_purl("curl", "8.6.0-1.fc40", "dnf", "fedora", "40"), "pkg:rpm/fedora/curl@8.6.0-1.fc40?distro=40")
        self.assertEqual(linux_purl("bash", "5.2.026-2", "pacman", "arch", None), "pkg:alpm/arch/bash@5.2.026-2")

    def test_no_purl_without_a_known_manager_or_version(self):
        self.assertIsNone(linux_purl("x", "1.0", None, "ubuntu"))
        self.assertIsNone(linux_purl("x", "-", "apt", "ubuntu"))
        self.assertIsNone(linux_purl("-", "1.0", "apt", "ubuntu"))


class CycloneDXTests(unittest.TestCase):
    def setUp(self):
        self.bom = to_cyclonedx(APPS, serial="urn:uuid:00000000-0000-0000-0000-000000000000", **KW)
        self.by_name = {c["name"]: c for c in self.bom["components"]}

    def test_envelope(self):
        self.assertEqual(self.bom["bomFormat"], "CycloneDX")
        self.assertEqual(self.bom["specVersion"], "1.6")
        self.assertEqual(self.bom["metadata"]["component"]["name"], "lab-pc")
        self.assertEqual(self.bom["metadata"]["tools"]["components"][0]["version"], "0.3.0")

    def test_os_and_package_backed_entries(self):
        self.assertEqual(self.by_name["Ubuntu"]["type"], "operating-system")
        self.assertNotIn("purl", self.by_name["Ubuntu"])
        self.assertEqual(self.by_name["auditd"]["purl"], "pkg:deb/ubuntu/auditd@1:3.1.2-2.1build1.1?distro=noble")
        # a desktop entry's "publisher" is the owning package: it becomes the purl, never a publisher
        self.assertEqual(self.by_name["Firefox"]["purl"], "pkg:deb/ubuntu/firefox@157.0?distro=noble")
        self.assertNotIn("publisher", self.by_name["Firefox"])
        self.assertNotIn("publisher", self.by_name["auditd"])

    def test_no_guessed_identifiers_for_registry_or_dev_tools(self):
        zip7 = self.by_name["7-Zip 19.00 (x64 edition)"]
        self.assertEqual(zip7["publisher"], "Igor Pavlov")
        for c in (zip7, self.by_name["node"]):
            self.assertNotIn("purl", c)
            self.assertNotIn("cpe", c)

    def test_unique_refs_and_dependencies(self):
        refs = [c["bom-ref"] for c in self.bom["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        root = next(d for d in self.bom["dependencies"] if d["ref"] == "machine")
        self.assertEqual(root["dependsOn"], refs)


class SPDXTests(unittest.TestCase):
    def setUp(self):
        self.doc = to_spdx(APPS, namespace="https://example.org/spdx/lab-pc-1", **KW)

    def test_envelope_and_relationships(self):
        self.assertEqual(self.doc["spdxVersion"], "SPDX-2.3")
        self.assertEqual(self.doc["dataLicense"], "CC0-1.0")
        ids = [p["SPDXID"] for p in self.doc["packages"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(self.doc["packages"]), len(APPS) + 1)
        contains = [r for r in self.doc["relationships"] if r["relationshipType"] == "CONTAINS"]
        self.assertEqual(len(contains), len(APPS))

    def test_supplier_and_purl(self):
        by_name = {p["name"]: p for p in self.doc["packages"]}
        self.assertEqual(by_name["7-Zip 19.00 (x64 edition)"]["supplier"], "Organization: Igor Pavlov")
        self.assertEqual(by_name["auditd"]["supplier"], "NOASSERTION")
        self.assertEqual(by_name["auditd"]["externalRefs"][0]["referenceLocator"],
                         "pkg:deb/ubuntu/auditd@1:3.1.2-2.1build1.1?distro=noble")
        self.assertNotIn("externalRefs", by_name["node"])


class CLITests(unittest.TestCase):
    def test_format_flag_writes_a_parseable_sbom(self):
        import io
        import tempfile
        from contextlib import redirect_stdout
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "bom.json"
            with mock.patch("releasetrain_inventory.cli.scan", return_value=list(APPS)), redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--format", "cyclonedx", "--machine", "lab-pc", "-o", str(out)]), 0)
            bom = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(bom["metadata"]["component"]["name"], "lab-pc")
            self.assertEqual(len(bom["components"]), len(APPS))

    def test_json_flag_unchanged(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock
        buf = io.StringIO()
        with mock.patch("releasetrain_inventory.cli.scan", return_value=list(APPS)), redirect_stdout(buf):
            main(["--json"])
        self.assertEqual(len(json.loads(buf.getvalue())), len(APPS))


if __name__ == "__main__":
    unittest.main()
