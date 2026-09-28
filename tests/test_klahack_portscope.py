# test_klahack_portscope.py | Author: klahack | MIT License
"""Loopback-only unit tests for klahack-portscope."""

import io
import json
import socket
import threading
import unittest

import klahack_portscope as portscope


class LoopbackServer:
    """Minimal one-connection TCP server bound only to IPv4 loopback."""

    def __init__(self, payload=b""):
        self.payload = payload
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.socket.settimeout(2.0)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        try:
            connection, _ = self.socket.accept()
            with connection:
                if self.payload:
                    connection.sendall(self.payload)
        except (OSError, socket.timeout):
            pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        del exc_type, exc_value, traceback
        self.socket.close()
        self.thread.join(timeout=2.0)


class PortParsingTests(unittest.TestCase):
    """Validate mixed port syntax and bounds."""

    def test_mixed_ports_are_sorted_and_deduplicated(self):
        self.assertEqual(portscope.parse_ports("443,80,80,22-24,23"), [22, 23, 24, 80, 443])

    def test_invalid_ports_are_rejected(self):
        for value in ("0", "65536", "80-79", "abc", "22,,80", "1-70000"):
            with self.subTest(value=value):
                with self.assertRaises(portscope.InputError):
                    portscope.parse_ports(value)

    def test_top_ports_preserve_prevalence_order(self):
        self.assertEqual(portscope.top_ports(4), [80, 443, 22, 21])
        with self.assertRaises(portscope.InputError):
            portscope.top_ports(101)


class TargetParsingTests(unittest.TestCase):
    """Validate literal and bounded CIDR target expansion."""

    def test_literal_and_cidr_targets(self):
        targets = portscope.parse_targets("127.0.0.1,127.0.0.0/30", family=4, max_hosts=4)
        self.assertEqual(
            targets,
            [
                {"host": "127.0.0.1", "ip": "127.0.0.1"},
                {"host": "127.0.0.0/30", "ip": "127.0.0.1"},
                {"host": "127.0.0.0/30", "ip": "127.0.0.2"},
            ],
        )

    def test_family_mismatch_and_host_limit_are_rejected(self):
        with self.assertRaises(portscope.InputError):
            portscope.parse_targets("127.0.0.1", family=6)
        with self.assertRaises(portscope.InputError):
            portscope.parse_targets("127.0.0.0/24", family=4, max_hosts=10)


class ScannerTests(unittest.TestCase):
    """Exercise real TCP state detection on loopback only."""

    def test_open_state_and_passive_banner(self):
        with LoopbackServer(b"SSH-2.0-test\r\n") as server:
            result = portscope.scan_port("127.0.0.1", server.port, timeout=1.0, grab_banner=True)
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["banner"], "SSH-2.0-test")

    def test_closed_state(self):
        reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        result = portscope.scan_port("127.0.0.1", port, timeout=1.0)
        diagnostic = ""
        if result["state"] != "closed":
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(1.0)
            try:
                probe.connect(("127.0.0.1", port))
                diagnostic = "diagnostic connection unexpectedly succeeded"
            except OSError as exc:
                diagnostic = "exception=%r errno=%r winerror=%r args=%r" % (
                    type(exc).__name__, exc.errno, getattr(exc, "winerror", None), exc.args
                )
            finally:
                probe.close()
        self.assertEqual(result["state"], "closed", diagnostic)


class OutputAndSafetyTests(unittest.TestCase):
    """Verify output contracts and defensive safeguards."""

    def test_json_schema_contains_branding_and_summary(self):
        targets = [{"host": "localhost", "ip": "127.0.0.1"}]
        results = [{
            "host": "localhost",
            "ip": "127.0.0.1",
            "port": 80,
            "state": "open",
            "service": "http",
            "banner": "HTTP/1.0 200 OK",
        }]
        report = portscope.build_json_report(
            targets, results, "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:01.000Z", 1.0
        )
        encoded = json.dumps(report)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["tool"], "klahack-portscope")
        self.assertEqual(decoded["author"], "klahack")
        self.assertEqual(decoded["version"], "1.0.0")
        self.assertEqual(decoded["summary"], {"open": 1, "closed": 0, "filtered": 0})
        self.assertEqual(decoded["targets"][0]["results"][0]["port"], 80)

    def test_banner_sanitization_blocks_terminal_controls(self):
        malicious = b"\x1b[31mRED\x1b[0m\r\nhello\x00world\x07"
        cleaned = portscope.sanitize_banner(malicious)
        self.assertEqual(cleaned, "RED hello world")
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\n", cleaned)

    def test_service_names_cannot_inject_terminal_controls(self):
        self.assertRegex(portscope.service_name(22), r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")

    def test_permission_gate_allows_local_targets(self):
        targets = [{"host": "loopback", "ip": "127.0.0.1"}]
        self.assertFalse(portscope.permission_required(targets))
        self.assertTrue(portscope.confirm_permission(targets, preconfirmed=False))

    def test_permission_gate_rejects_noninteractive_public_target(self):
        targets = [{"host": "public-example", "ip": "8.8.8.8"}]
        errors = io.StringIO()
        self.assertTrue(portscope.permission_required(targets))
        self.assertFalse(
            portscope.confirm_permission(
                targets, preconfirmed=False, input_stream=io.StringIO("yes\n"), error_stream=errors
            )
        )
        self.assertIn("--i-have-permission", errors.getvalue())
        self.assertTrue(portscope.confirm_permission(targets, preconfirmed=True))


if __name__ == "__main__":
    unittest.main()
