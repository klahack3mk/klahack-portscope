#!/usr/bin/env python3
# klahack_portscope.py | Author: klahack | MIT License
"""Portable, responsible TCP connect scanner for authorized network audits.

State semantics are deliberately small and stable across operating systems:

* open: the TCP connection succeeded.
* closed: the peer refused the connection (ECONNREFUSED or Windows 10061),
  proving that the host responded.
* filtered: the attempt timed out or no route was available (including
  EHOSTUNREACH, ENETUNREACH, and Windows equivalents). Other unsuccessful
  non-refusal socket results are conservatively reported as filtered.
"""

import argparse
import concurrent.futures
import csv
import datetime
import errno
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import time

TOOL_NAME = "klahack-portscope"
AUTHOR = "klahack"
VERSION = "1.0.0"
VERSION_TEXT = "%s %s by %s" % (TOOL_NAME, VERSION, AUTHOR)
LEGAL_WARNING = "Scan only networks you own or have explicit written permission to test."
MAX_BANNER_BYTES = 256
HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888}

# Ordered by general TCP prevalence. --top-ports keeps this order.
TOP_PORTS = [
    80, 443, 22, 21, 25, 3389, 110, 445, 139, 143,
    53, 135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025,
    587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000,
    514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26,
    1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000,
    5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121,
    1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544,
    5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070,
    5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646,
    49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000,
]

SERVICE_FALLBACKS = {
    7: "echo", 9: "discard", 13: "daytime", 21: "ftp", 22: "ssh",
    25: "smtp", 26: "rsftp", 37: "time", 53: "domain", 79: "finger",
    80: "http", 81: "http-alt", 88: "kerberos", 106: "poppassd",
    110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 179: "bgp",
    199: "smux", 389: "ldap", 427: "svrloc", 443: "https",
    445: "microsoft-ds", 465: "smtps", 513: "login", 514: "shell",
    515: "printer", 543: "klogin", 544: "kshell", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 646: "ldp",
    873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
    1000: "cadlock", 1720: "h323q931", 1723: "pptp", 1900: "ssdp",
    2000: "cisco-sccp", 2049: "nfs", 2121: "ftp-alt",
    3000: "http-alt", 3128: "squid-http", 3306: "mysql",
    3389: "ms-wbt-server", 5000: "upnp", 5060: "sip",
    5101: "talarian-tcp", 5190: "aol", 5357: "wsdapi",
    5432: "postgresql", 5631: "pcanywheredata", 5666: "nrpe",
    5800: "vnc-http", 5900: "vnc", 6000: "x11", 6001: "x11-1",
    6646: "unknown", 7070: "realserver", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp13", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9100: "jetdirect", 9999: "abyss", 10000: "webmin",
}

ANSI_ESCAPE_RE = re.compile(
    r"(?:\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1bP.*?\x1b\\|\x1b[@-_][0-?]*[ -/]*[@-~])",
    re.DOTALL,
)

REFUSED_CODES = {getattr(errno, "ECONNREFUSED", 111), 10061}
FILTERED_CODES = {
    getattr(errno, "ETIMEDOUT", 110),
    getattr(errno, "EHOSTUNREACH", 113),
    getattr(errno, "ENETUNREACH", 101),
    getattr(errno, "EHOSTDOWN", 112),
    getattr(errno, "ENETDOWN", 100),
    getattr(errno, "EACCES", 13),
    getattr(errno, "EPERM", 1),
    getattr(errno, "EADDRNOTAVAIL", 99),
    10013, 10049, 10050, 10051, 10060, 10064, 10065,
}

_INTERRUPTED = False


class InputError(ValueError):
    """Raised when user-supplied scan input is invalid."""


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    value = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
    return value.replace("+00:00", "Z")


def parse_ports(spec: str) -> list:
    """Parse, deduplicate, validate, and sort a mixed port expression."""
    if not spec or not spec.strip():
        raise InputError("port specification cannot be empty")
    ports = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            raise InputError("empty item in port specification")
        if "-" in part:
            if part.count("-") != 1:
                raise InputError("invalid port range: %s" % part)
            start_text, end_text = part.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise InputError("invalid port range: %s" % part)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise InputError("port range starts after it ends: %s" % part)
            if start < 1 or end > 65535:
                raise InputError("ports must be in the range 1-65535")
            ports.update(range(start, end + 1))
        else:
            if not part.isdigit():
                raise InputError("invalid port: %s" % part)
            port = int(part)
            if port < 1 or port > 65535:
                raise InputError("ports must be in the range 1-65535")
            ports.add(port)
    return sorted(ports)


def top_ports(count: int) -> list:
    """Return the requested number of common ports in prevalence order."""
    if count < 1 or count > len(TOP_PORTS):
        raise InputError("--top-ports must be between 1 and %d" % len(TOP_PORTS))
    return TOP_PORTS[:count]


def _family_value(family: int) -> int:
    """Translate 4/6/0 into a socket address-family constant."""
    if family == 4:
        return socket.AF_INET
    if family == 6:
        return socket.AF_INET6
    return socket.AF_UNSPEC


def _append_target(targets: list, seen: set, host: str, ip_text: str, max_hosts: int) -> None:
    """Append one unique resolved target while enforcing the safety limit."""
    key = (host, ip_text)
    if key in seen:
        return
    if len(targets) >= max_hosts:
        raise InputError("target expansion exceeds --max-hosts=%d" % max_hosts)
    seen.add(key)
    targets.append({"host": host, "ip": ip_text})


def _network_addresses(network: object) -> object:
    """Yield usable addresses, retaining the sole address in host routes."""
    if network.num_addresses == 1:
        return iter((network.network_address,))
    return network.hosts()


def parse_targets(spec: str, family: int = 0, max_hosts: int = 256) -> list:
    """Resolve comma-separated IPs, hostnames, and CIDRs into target records."""
    if max_hosts < 1:
        raise InputError("--max-hosts must be at least 1")
    if not spec or not spec.strip():
        raise InputError("--target is required")

    targets = []
    seen = set()
    for raw_item in spec.split(","):
        item = raw_item.strip()
        if not item:
            raise InputError("empty item in target specification")

        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise InputError("invalid CIDR target '%s': %s" % (item, exc))
            if family and network.version != family:
                raise InputError("target '%s' does not match -%d" % (item, family))
            if network.num_addresses > max_hosts + 2:
                raise InputError("CIDR target '%s' exceeds --max-hosts=%d" % (item, max_hosts))
            for address in _network_addresses(network):
                _append_target(targets, seen, item, str(address), max_hosts)
            continue

        try:
            address = ipaddress.ip_address(item)
        except ValueError:
            address = None
        if address is not None:
            if family and address.version != family:
                raise InputError("target '%s' does not match -%d" % (item, family))
            _append_target(targets, seen, item, str(address), max_hosts)
            continue

        try:
            answers = socket.getaddrinfo(
                item, None, _family_value(family), socket.SOCK_STREAM, socket.IPPROTO_TCP
            )
        except socket.gaierror as exc:
            raise InputError("cannot resolve target '%s': %s" % (item, exc))
        resolved = set()
        for answer in answers:
            ip_text = answer[4][0]
            try:
                normalized = str(ipaddress.ip_address(ip_text))
            except ValueError:
                continue
            resolved.add(normalized)
        if not resolved:
            raise InputError("target '%s' resolved to no usable address" % item)
        for ip_text in sorted(
            resolved, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value).packed)
        ):
            _append_target(targets, seen, item, ip_text, max_hosts)

    if not targets:
        raise InputError("target specification resolved to no hosts")
    return targets


def address_is_local(ip_text: str) -> bool:
    """Return whether an address is private, loopback, or link-local."""
    address = ipaddress.ip_address(ip_text)
    return bool(address.is_private or address.is_loopback or address.is_link_local)


def permission_required(targets: list) -> bool:
    """Return whether any resolved target needs explicit authorization."""
    return any(not address_is_local(target["ip"]) for target in targets)


def confirm_permission(targets: list, preconfirmed: bool, input_stream=None, error_stream=None) -> bool:
    """Apply the public-target permission gate without trusting target names."""
    if not permission_required(targets):
        return True
    if preconfirmed:
        return True
    input_stream = input_stream or sys.stdin
    error_stream = error_stream or sys.stderr
    if not hasattr(input_stream, "isatty") or not input_stream.isatty():
        error_stream.write(
            "Error: public targets require --i-have-permission in non-interactive mode.\n"
        )
        return False
    error_stream.write(
        "Public target detected. Confirm you have explicit written permission to scan it.\n"
        "Type 'yes' to continue: "
    )
    error_stream.flush()
    answer = input_stream.readline()
    if answer.strip().lower() != "yes":
        error_stream.write("Authorization not confirmed; scan refused.\n")
        return False
    return True


def sanitize_banner(value: object) -> str:
    """Decode and neutralize control/ANSI sequences from an untrusted banner."""
    if isinstance(value, bytes):
        text = value[:MAX_BANNER_BYTES].decode("utf-8", errors="replace")
    else:
        text = str(value)[:MAX_BANNER_BYTES]
    text = ANSI_ESCAPE_RE.sub("", text)
    text = "".join(" " if ord(char) < 32 or 127 <= ord(char) <= 159 else char for char in text)
    return re.sub(r"\s+", " ", text).strip()


def service_name(port: int) -> str:
    """Resolve a safe TCP service name with a deterministic built-in fallback."""
    fallback = SERVICE_FALLBACKS.get(port, "unknown")
    try:
        name = socket.getservbyport(port, "tcp")
    except OSError:
        return fallback
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}", name):
        return name
    return fallback


def classify_connect_code(code: int) -> str:
    """Map platform-specific connect_ex results into the documented states."""
    if code == 0:
        return "open"
    if code in REFUSED_CODES:
        return "closed"
    if code in FILTERED_CODES:
        return "filtered"
    return "filtered"


def _receive_banner(sock: socket.socket, port: int, host: str, timeout: float) -> str:
    """Passively read a banner, then probe common HTTP ports if necessary."""
    deadline = time.monotonic() + timeout
    data = b""
    passive_timeout = timeout if port not in HTTP_PORTS else min(timeout, 0.20)
    try:
        sock.settimeout(max(0.001, passive_timeout))
        data = sock.recv(MAX_BANNER_BYTES)
    except (socket.timeout, OSError):
        data = b""

    if not data and port in HTTP_PORTS:
        remaining = deadline - time.monotonic()
        if remaining > 0:
            host_header = "[%s]" % host if ":" in host else host
            request = (
                "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s/%s\r\n\r\n"
                % (host_header, TOOL_NAME, VERSION)
            ).encode("ascii", errors="replace")
            try:
                sock.settimeout(max(0.001, remaining))
                sock.sendall(request)
                data = sock.recv(MAX_BANNER_BYTES)
            except (socket.timeout, OSError):
                data = b""
    return sanitize_banner(data) if data else ""


def scan_port(ip_text: str, port: int, timeout: float = 1.0, grab_banner: bool = False) -> dict:
    """Perform one TCP connect attempt and return a platform-neutral result."""
    address = ipaddress.ip_address(ip_text)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    endpoint = (ip_text, port, 0, 0) if family == socket.AF_INET6 else (ip_text, port)
    state = "filtered"
    banner = ""
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex(endpoint)
            state = classify_connect_code(code)
            if state == "open" and grab_banner:
                banner = _receive_banner(sock, port, ip_text, timeout)
        except socket.timeout:
            state = "filtered"
        except OSError as exc:
            state = classify_connect_code(exc.errno or -1)
    return {
        "port": port,
        "state": state,
        "service": service_name(port),
        "banner": banner,
    }


def _scan_task(target: dict, port: int, timeout: float, grab_banner: bool) -> object:
    """Run one worker task unless interruption has already been requested."""
    if _INTERRUPTED:
        return None
    result = scan_port(target["ip"], port, timeout, grab_banner)
    result["host"] = target["host"]
    result["ip"] = target["ip"]
    return result


def _progress(scanned: int, total: int, enabled: bool) -> None:
    """Render a compact in-place progress indicator to stderr."""
    if not enabled:
        return
    percent = (100.0 * scanned / total) if total else 100.0
    sys.stderr.write("\rScanning: %d/%d (%5.1f%%)" % (scanned, total, percent))
    sys.stderr.flush()


def _handle_interrupt(signum: int, frame: object) -> None:
    """Record Ctrl+C and transfer control back to the scan coordinator."""
    del signum, frame
    global _INTERRUPTED
    _INTERRUPTED = True
    raise KeyboardInterrupt


def scan_targets(
    targets: list,
    ports: list,
    timeout: float = 1.0,
    threads: int = 100,
    delay: float = 0.0,
    grab_banner: bool = False,
    show_progress: bool = False,
) -> tuple:
    """Scan bounded task batches and return (partial-or-full results, interrupted)."""
    global _INTERRUPTED
    _INTERRUPTED = False
    total = len(targets) * len(ports)
    scanned = 0
    results = []
    interrupted = False
    batch_limit = max(threads * 4, 1)
    task_iterator = (
        (target, port)
        for target in targets
        for port in ports
    )
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    previous_handler = None
    can_set_signal = True
    try:
        previous_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, _handle_interrupt)
    except (ValueError, AttributeError):
        can_set_signal = False

    try:
        exhausted = False
        while not exhausted and not interrupted:
            batch = []
            while len(batch) < batch_limit:
                try:
                    batch.append(next(task_iterator))
                except StopIteration:
                    exhausted = True
                    break
            if not batch:
                break

            futures = []
            handled = set()
            try:
                for index, (target, port) in enumerate(batch):
                    if _INTERRUPTED:
                        raise KeyboardInterrupt
                    if delay > 0 and (scanned > 0 or index > 0):
                        time.sleep(delay)
                    futures.append(executor.submit(_scan_task, target, port, timeout, grab_banner))
                for future in concurrent.futures.as_completed(futures):
                    handled.add(future)
                    result = future.result()
                    if result is not None:
                        results.append(result)
                        scanned += 1
                        _progress(scanned, total, show_progress)
            except KeyboardInterrupt:
                interrupted = True
                _INTERRUPTED = True
                for future in futures:
                    future.cancel()
                for future in futures:
                    if future in handled or not future.done() or future.cancelled():
                        continue
                    try:
                        result = future.result()
                    except Exception:
                        result = None
                    if result is not None:
                        results.append(result)
                        scanned += 1
                        _progress(scanned, total, show_progress)
    finally:
        executor.shutdown(wait=True)
        if can_set_signal and previous_handler is not None:
            signal.signal(signal.SIGINT, previous_handler)
        if show_progress:
            sys.stderr.write("\n")
            sys.stderr.flush()

    results.sort(key=lambda item: (item["host"], ipaddress.ip_address(item["ip"]).version,
                                   ipaddress.ip_address(item["ip"]).packed, item["port"]))
    return results, interrupted


def summarize(results: list) -> dict:
    """Count each documented state."""
    return {
        "open": sum(1 for item in results if item["state"] == "open"),
        "closed": sum(1 for item in results if item["state"] == "closed"),
        "filtered": sum(1 for item in results if item["state"] == "filtered"),
    }


def visible_results(results: list, mode: str = "default") -> list:
    """Apply terminal/output visibility semantics without changing the summary."""
    if mode == "verbose":
        return list(results)
    if mode == "open-only":
        return [item for item in results if item["state"] == "open"]
    return [item for item in results if item["state"] in ("open", "filtered")]


def build_json_report(
    targets: list,
    results: list,
    started_at: str,
    finished_at: str,
    duration_s: float,
    mode: str = "default",
) -> dict:
    """Build the stable machine-readable JSON schema."""
    displayed = visible_results(results, mode)
    target_rows = []
    for target in targets:
        rows = []
        for item in displayed:
            if item["host"] == target["host"] and item["ip"] == target["ip"]:
                rows.append({
                    "port": item["port"],
                    "state": item["state"],
                    "service": item["service"],
                    "banner": item["banner"],
                })
        rows.sort(key=lambda item: item["port"])
        target_rows.append({"host": target["host"], "ip": target["ip"], "results": rows})
    return {
        "tool": TOOL_NAME,
        "author": AUTHOR,
        "version": VERSION,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_s": round(duration_s, 6),
        "targets": target_rows,
        "summary": summarize(results),
    }


def _state_color(state: str) -> str:
    """Return an ANSI color sequence for a state."""
    return {"open": "\033[32m", "closed": "\033[31m", "filtered": "\033[33m"}.get(state, "")


def colors_enabled(no_color: bool, stream=None) -> bool:
    """Apply portable color policy and safely initialize modern Windows terminals."""
    stream = stream or sys.stdout
    if no_color or "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        try:
            os.system("")
        except OSError:
            return False
    return True


def format_terminal(targets: list, results: list, duration_s: float, mode: str, color: bool) -> str:
    """Format deterministic human-readable scan tables and a summary."""
    displayed = visible_results(results, mode)
    lines = []
    for target in targets:
        lines.append("Target: %s (%s)" % (target["host"], target["ip"]))
        lines.append("PORT   STATE      SERVICE          BANNER")
        lines.append("-----  ---------  ---------------  ------")
        rows = [
            item for item in displayed
            if item["host"] == target["host"] and item["ip"] == target["ip"]
        ]
        if not rows:
            lines.append("(no matching results)")
        for item in sorted(rows, key=lambda value: value["port"]):
            state = item["state"]
            shown_state = state
            if color:
                shown_state = "%s%s\033[0m" % (_state_color(state), state)
            lines.append("%-5d  %-9s  %-15s  %s" % (
                item["port"], shown_state, item["service"], item["banner"]
            ))
        lines.append("")
    counts = summarize(results)
    lines.append(
        "Summary: open=%d closed=%d filtered=%d scanned=%d duration=%.3fs"
        % (counts["open"], counts["closed"], counts["filtered"], len(results), duration_s)
    )
    return "\n".join(lines) + "\n"


def output_mode(args: argparse.Namespace) -> str:
    """Translate display flags into one visibility mode."""
    if args.verbose:
        return "verbose"
    if args.open_only:
        return "open-only"
    return "default"


def write_results(
    args: argparse.Namespace,
    targets: list,
    results: list,
    started_at: str,
    finished_at: str,
    duration_s: float,
) -> None:
    """Write terminal, JSON, or CSV output to stdout or the requested file."""
    mode = output_mode(args)
    destination = None
    close_destination = False
    try:
        if args.output:
            destination = open(args.output, "w", encoding="utf-8", newline="")
            close_destination = True
        else:
            destination = sys.stdout

        if args.json:
            report = build_json_report(targets, results, started_at, finished_at, duration_s, mode)
            json.dump(report, destination, indent=2, ensure_ascii=False)
            destination.write("\n")
        elif args.csv:
            writer = csv.writer(destination, lineterminator="\n")
            writer.writerow(["host", "ip", "port", "protocol", "state", "service", "banner"])
            for item in visible_results(results, mode):
                writer.writerow([
                    item["host"], item["ip"], item["port"], "tcp", item["state"],
                    item["service"], item["banner"],
                ])
        else:
            color = colors_enabled(args.no_color, destination) if not args.output else False
            destination.write(format_terminal(targets, results, duration_s, mode, color))
        destination.flush()
    finally:
        if close_destination and destination is not None:
            destination.close()
    if args.output:
        sys.stderr.write("Results written to %s\n" % args.output)


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Portable TCP connect scanner for explicitly authorized audits.",
        epilog=LEGAL_WARNING,
        allow_abbrev=False,
    )
    parser.add_argument("-t", "--target", help="IP, hostname, CIDR, or comma-separated targets")
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument("-p", "--ports", help="ports such as 22,80,443,8000-8100")
    port_group.add_argument("--top-ports", type=int, metavar="N", help="N common ports (1-100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="socket timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100, help="worker threads, maximum 1000 (default: 100)")
    parser.add_argument("--delay", type=float, default=0.0, help="delay between task submissions in seconds")
    family_group = parser.add_mutually_exclusive_group()
    family_group.add_argument("-4", dest="ipv4", action="store_true", help="use IPv4 only")
    family_group.add_argument("-6", dest="ipv6", action="store_true", help="use IPv6 only")
    parser.add_argument("--banner", action="store_true", help="grab up to 256 bytes of service banner")
    format_group = parser.add_mutually_exclusive_group()
    format_group.add_argument("--json", action="store_true", help="emit JSON")
    format_group.add_argument("--csv", action="store_true", help="emit CSV")
    parser.add_argument("--output", metavar="FILE", help="write results to FILE")
    parser.add_argument("--quiet", action="store_true", help="suppress the ASCII banner")
    display_group = parser.add_mutually_exclusive_group()
    display_group.add_argument("--verbose", action="store_true", help="show open, closed, and filtered ports")
    display_group.add_argument("--open-only", action="store_true", help="show only open ports")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--no-progress", action="store_true", help="disable scan progress")
    parser.add_argument("--max-hosts", type=int, default=256, help="maximum expanded hosts (default: 256)")
    parser.add_argument(
        "--i-have-permission", action="store_true",
        help="confirm explicit authorization for public targets in non-interactive use",
    )
    parser.add_argument("--version", action="version", version=VERSION_TEXT)
    return parser


def print_startup(quiet: bool) -> None:
    """Print branding and the mandatory responsible-use warning to stderr."""
    if not quiet:
        sys.stderr.write(
            "+---------------------+\n"
            "| klahack-portscope   |\n"
            "| by klahack          |\n"
            "+---------------------+\n"
        )
    sys.stderr.write(LEGAL_WARNING + "\n")
    sys.stderr.flush()


def _finite_number(value: float) -> bool:
    """Check float finiteness without importing a non-approved helper module."""
    return value == value and value not in (float("inf"), float("-inf"))


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate numeric and required CLI arguments."""
    if not args.target:
        raise InputError("--target is required")
    if args.ports is None and args.top_ports is None:
        raise InputError("one of --ports or --top-ports is required")
    if not _finite_number(args.timeout) or args.timeout <= 0:
        raise InputError("--timeout must be a finite number greater than 0")
    if args.threads < 1 or args.threads > 1000:
        raise InputError("--threads must be between 1 and 1000")
    if not _finite_number(args.delay) or args.delay < 0:
        raise InputError("--delay must be a finite non-negative number")
    if args.max_hosts < 1:
        raise InputError("--max-hosts must be at least 1")


def main(argv=None) -> int:
    """Run the CLI and return one of the documented fixed exit codes."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    print_startup("--quiet" in arguments)
    parser = build_parser()
    try:
        args = parser.parse_args(arguments)
        validate_arguments(args)
        ports = parse_ports(args.ports) if args.ports is not None else top_ports(args.top_ports)
        family = 4 if args.ipv4 else (6 if args.ipv6 else 0)
        targets = parse_targets(args.target, family, args.max_hosts)
        if not confirm_permission(targets, args.i_have_permission):
            return 2

        started_at = utc_now()
        started_clock = time.monotonic()
        progress = not args.no_progress and not args.quiet and hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
        results, interrupted = scan_targets(
            targets=targets,
            ports=ports,
            timeout=args.timeout,
            threads=args.threads,
            delay=args.delay,
            grab_banner=args.banner,
            show_progress=progress,
        )
        duration_s = time.monotonic() - started_clock
        finished_at = utc_now()
        write_results(args, targets, results, started_at, finished_at, duration_s)
        if interrupted:
            sys.stderr.write("Scan interrupted; partial results shown.\n")
            return 130
        return 0
    except InputError as exc:
        sys.stderr.write("Error: %s\n" % exc)
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("Scan interrupted.\n")
        return 130
    except (OSError, ValueError) as exc:
        sys.stderr.write("Runtime error: %s\n" % exc)
        return 1
    except Exception as exc:
        sys.stderr.write("Runtime error: %s\n" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
