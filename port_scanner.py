#!/usr/bin/env python3
"""
Syntecxhub - Project 1: TCP Port Scanner
Multi-threaded TCP connect scanner with logging and error handling.

Use ONLY on hosts you own or have permission to scan.
"""

import argparse
import logging
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

OPEN, CLOSED, TIMEOUT, ERROR = "open", "closed", "timeout", "error"


def parse_ports(spec):
    """Parse '80', '20-100', or '22,80,443' (mixed ok) into a sorted list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            try:
                start, end = int(start), int(end)
            except ValueError as exc:
                raise ValueError(f"Invalid port range: {part}") from exc
            if start > end:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError as exc:
                raise ValueError(f"Invalid port: {part}") from exc

    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)


def scan_port(ip, port, timeout):
    """Try a TCP connect to ip:port. Returns (port, status)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            return port, OPEN
    except ConnectionRefusedError:
        return port, CLOSED
    except (socket.timeout, TimeoutError):
        return port, TIMEOUT
    except OSError as exc:
        logging.debug("OS error on port %d: %s", port, exc)
        return port, ERROR


def service_name(port):
    """Return the locally known TCP service name, if available."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def setup_logging(log_file, verbose):
    """Configure logging to a UTF-8 file."""
    handlers = [logging.FileHandler(log_file, encoding="utf-8")]
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Simple multi-threaded TCP port scanner"
    )
    parser.add_argument("host", help="Target hostname or IP (e.g. 127.0.0.1)")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports: '80', '20-100', or '22,80,443' (default: 1-1024)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Timeout per port in seconds (default: 1.0)"
    )
    parser.add_argument(
        "-o", "--output", default="scan_results.log",
        help="Log file (default: scan_results.log)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print closed/timeout/error ports too"
    )
    args = parser.parse_args()

    # Validate user-supplied settings before starting the scan.
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if not args.output.strip():
        parser.error("--output must not be empty")

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        ip = socket.gethostbyname(args.host)
    except (socket.gaierror, UnicodeError):
        print(f"[!] Cannot resolve host: {args.host}", file=sys.stderr)
        sys.exit(1)

    try:
        setup_logging(args.output, args.verbose)
    except OSError as exc:
        print(f"[!] Cannot open log file '{args.output}': {exc}", file=sys.stderr)
        sys.exit(1)

    start = datetime.now()
    header = (
        f"Scanning {args.host} ({ip}) | {len(ports)} ports | "
        f"{args.threads} threads"
    )
    print(header)
    logging.info(header)

    results = {OPEN: [], CLOSED: [], TIMEOUT: [], ERROR: []}
    executor = ThreadPoolExecutor(max_workers=args.threads)
    interrupted = False

    try:
        futures = {
            executor.submit(scan_port, ip, port, args.timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            port = futures[future]
            try:
                result_port, status = future.result()
            except Exception:
                # Keep an unexpected worker failure from crashing the whole scan.
                logging.exception("Unexpected failure while scanning port %d", port)
                result_port, status = port, ERROR

            results[status].append(result_port)
            logging.info("Port %d: %s", result_port, status)

            if status == OPEN:
                print(f"[+] {result_port}/tcp open ({service_name(result_port)})")
            elif args.verbose:
                print(f"[-] {result_port}/tcp {status}")

    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] Scan interrupted by user")
        logging.warning("Scan interrupted by user")
        for future in futures:
            future.cancel()
    finally:
        # Wait for already-running socket operations to finish cleanly.
        executor.shutdown(wait=True, cancel_futures=True)

    elapsed = (datetime.now() - start).total_seconds()
    summary = (
        f"{'Interrupted' if interrupted else 'Done'} in {elapsed:.2f}s | "
        f"open: {len(results[OPEN])} | closed: {len(results[CLOSED])} | "
        f"timeout: {len(results[TIMEOUT])} | error: {len(results[ERROR])}"
    )
    print(summary)
    logging.info(summary)

    if results[OPEN]:
        logging.info("Open ports: %s", sorted(results[OPEN]))

    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
