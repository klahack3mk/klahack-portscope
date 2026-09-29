# test_klahack_portscope.py | Author: klahack | MIT License
"""Loopback-only unit tests for klahack-portscope."""

import io
import json
import socket
import threading
import unittest
from unittest import mock

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
        refused_socket = mock.MagicMock()
        refused_socket.__enter__.return_value = refused_socket
        refused_socket.connect.side_effect = OSError(10061, "connection refused")
        with mock.patch.object(portscope.socket, "socket", return_value=refused_socket):
            result = portscope.scan_port("127.0.0.1", 1, timeout=1.0)
        self.assertEqual(result["state"], "closed")
        refused_socket.__exit__.assert_called_once()


class EncodedCapture:
    """Text stream test double that enforces a declared output encoding."""

    def __init__(self, encoding: str):
        self.encoding = encoding
        self._parts = []

    def write(self, value: str) -> int:
        value.encode(self.encoding)
        self._parts.append(value)
        return len(value)

    def flush(self) -> None:
        pass

    def getvalue(self) -> str:
        return "".join(self._parts)


class OutputAndSafetyTests(unittest.TestCase):
    """Verify output contracts and defensive safeguards."""

    def test_startup_banner_uses_unicode_when_supported(self):
        stream = io.StringIO()
        with mock.patch.object(portscope.sys, "stderr", stream):
            portscope.print_startup(quiet=False)
        output = stream.getvalue()
        self.assertIn("╔══════════════════════════════════════════════╗", output)
        self.assertIn("P O R T S C O P E  //  TCP RECON", output)
        self.assertIn(portscope.LEGAL_WARNING, output)

    def test_startup_banner_falls_back_to_ascii_when_needed(self):
        stream = EncodedCapture("ascii")
        with mock.patch.object(portscope.sys, "stderr", stream):
            portscope.print_startup(quiet=False)
        output = stream.getvalue()
        self.assertIn("+----------------------------------------------+", output)
        self.assertIn("P O R T S C O P E  //  TCP RECON", output)
        self.assertNotIn("╔", output)
        self.assertIn(portscope.LEGAL_WARNING, output)

    def test_quiet_suppresses_startup_banner_only(self):
        stream = io.StringIO()
        with mock.patch.object(portscope.sys, "stderr", stream):
            portscope.print_startup(quiet=True)
        output = stream.getvalue()
        self.assertNotIn("P O R T S C O P E", output)
        self.assertEqual(output, portscope.LEGAL_WARNING + "\n")

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
