import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import netaudit  # noqa: E402

SAMPLES = ROOT / "samples"


def run(name):
    cfg = netaudit.Config(name, (SAMPLES / name).read_text())
    findings = netaudit.audit(cfg)
    return cfg, {f.rule.id for f in findings if not f.passed}, findings


class CiscoTests(unittest.TestCase):
    def test_insecure_findings(self):
        cfg, failed, findings = run("cisco-insecure.cfg")
        self.assertEqual(cfg.vendor, "cisco")
        for rid in ("IOS-001", "IOS-002", "IOS-003", "IOS-004", "IOS-005", "IOS-006", "IOS-007", "IOS-011"):
            self.assertIn(rid, failed)
        self.assertLess(netaudit.score(findings), 40)

    def test_hardened_passes_everything(self):
        _, failed, findings = run("cisco-hardened.cfg")
        self.assertEqual(failed, set())
        self.assertEqual(netaudit.score(findings), 100)

    def test_snmp_acl_detection(self):
        cfg = netaudit.Config("x", "hostname a\nsnmp-server community n0c-rw RW\nsnmp-server community ok RO ACL1\n")
        passed, evidence = netaudit.cisco_snmp_acl(cfg)
        self.assertFalse(passed)
        self.assertIn("n0c-rw", evidence)
        self.assertNotIn("ACL1", evidence)

    def test_vty_without_transport_is_flagged(self):
        cfg = netaudit.Config("x", "hostname a\nline vty 0 4\n transport input ssh\nline vty 5 15\n login\n")
        passed, evidence = netaudit.cisco_ssh_only(cfg)
        self.assertFalse(passed)
        self.assertIn("line vty 5 15", evidence)


class MikrotikTests(unittest.TestCase):
    def test_insecure_findings(self):
        cfg, failed, _ = run("mikrotik-insecure.rsc")
        self.assertEqual(cfg.vendor, "mikrotik")
        for rid in ("MT-001", "MT-002", "MT-003", "MT-004", "MT-010", "MT-011"):
            self.assertIn(rid, failed)

    def test_hardened_passes_everything(self):
        _, failed, _ = run("mikrotik-hardened.rsc")
        self.assertEqual(failed, set())

    def test_normal_export_is_normalised(self):
        cfg = netaudit.Config("x", "/ip service\nset telnet disabled=yes\nset ftp \\\n    disabled=yes\n")
        self.assertIn("/ip service set telnet disabled=yes", cfg.lines)
        self.assertIn("/ip service set ftp disabled=yes", cfg.lines)


class CliTests(unittest.TestCase):
    def test_exit_codes_and_formats(self):
        self.assertEqual(netaudit.main([str(SAMPLES / "cisco-hardened.cfg")]), 0)
        self.assertEqual(netaudit.main([str(SAMPLES / "cisco-insecure.cfg")]), 1)
        self.assertEqual(netaudit.main([str(SAMPLES / "cisco-insecure.cfg"), "--fail-on", "never"]), 0)
        with tempfile.TemporaryDirectory() as d:
            for fmt in ("json", "html", "markdown"):
                out = Path(d) / f"r.{fmt}"
                netaudit.main([str(SAMPLES), "-f", fmt, "-o", str(out), "--fail-on", "never"])
                self.assertGreater(out.stat().st_size, 200)
            data = json.loads((Path(d) / "r.json").read_text(encoding="utf-8"))
            self.assertEqual(len(data), 4)

    def test_ignore(self):
        cfg = netaudit.Config("x", (SAMPLES / "cisco-insecure.cfg").read_text())
        ids = {f.rule.id for f in netaudit.audit(cfg, {"IOS-001"})}
        self.assertNotIn("IOS-001", ids)


if __name__ == "__main__":
    unittest.main()
