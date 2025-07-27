#!/usr/bin/env python3

import asyncio
import signal
import sys
from typing import List, Optional
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import logging
from pathlib import Path
from datetime import datetime
from tqdm import tqdm


def setup_logging(
    log_file: Optional[str] = None, verbose: bool = False
) -> logging.Logger:
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[],
    )

    logger = logging.getLogger("PortDiscovery")
    logger.setLevel(log_level)

    logger.handlers.clear()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


logger = setup_logging()


class PortScanner:
    def __init__(self, target_host: str, timeout: float = 1.0, max_workers: int = 100):
        self.target_host = target_host
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports: List[int] = []
        self._running = True
        self._scanned_ports = 0
        self._total_ports = 0

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, frame) -> None:
        logger.info("\n[!] Exiting ... \n")
        self._running = False
        sys.exit(1)

    def check_port(self, port: int) -> Optional[int]:
        if not self._running:
            return None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_host, port))
                if result == 0:
                    return port
        except socket.error as e:
            logger.debug(f"Error checking port {port}: {e}")
        except Exception as e:
            logger.debug(f"Unexpected error checking port {port}: {e}")

        return None

    def scan_ports_sync(self, start_port: int = 1, end_port: int = 65535) -> List[int]:
        logger.info(
            f"Starting port scan on {self.target_host} (ports {start_port}-{end_port})"
        )
        start_time = time.time()

        self._total_ports = end_port - start_port + 1
        self._scanned_ports = 0
        open_ports = []

        pbar = tqdm(
            total=self._total_ports,
            desc=f"Scanning {self.target_host}",
            unit="ports",
            ncols=80,
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.check_port, port): port
                for port in range(start_port, end_port + 1)
            }

            for future in as_completed(future_to_port):
                if not self._running:
                    break

                port = future_to_port[future]
                self._scanned_ports += 1

                pbar.update(1)

                try:
                    result = future.result()
                    if result is not None:
                        open_ports.append(result)
                        print(f"\t[*] Port {result} - OPEN")
                        logger.info(f"Found open port: {result}")
                except Exception as e:
                    logger.error(f"Error processing port {port}: {e}")

        pbar.close()

        elapsed_time = time.time() - start_time
        logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
        logger.info(f"Found {len(open_ports)} open ports")

        return sorted(open_ports)

    async def check_port_async(self, port: int) -> Optional[int]:
        if not self._running:
            return None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
        except Exception as e:
            logger.debug(f"Unexpected error checking port {port}: {e}")

        return None

    async def scan_ports_async(
        self, start_port: int = 1, end_port: int = 65535
    ) -> List[int]:
        logger.info(
            f"Starting async port scan on {self.target_host} (ports {start_port}-{end_port})"
        )
        start_time = time.time()

        self._total_ports = end_port - start_port + 1
        self._scanned_ports = 0

        tasks = [
            self.check_port_async(port) for port in range(start_port, end_port + 1)
        ]

        open_ports = []

        pbar = tqdm(
            total=self._total_ports,
            desc=f"Async scanning {self.target_host}",
            unit="ports",
            ncols=80,
        )

        batch_size = 1000
        for i in range(0, len(tasks), batch_size):
            if not self._running:
                break

            batch = tasks[i : i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)

            for j, result in enumerate(results):
                self._scanned_ports += 1

                pbar.update(1)

                if isinstance(result, Exception):
                    logger.debug(
                        f"Error in batch {i//batch_size}, port {start_port + i + j}: {result}"
                    )
                elif result is not None:
                    open_ports.append(result)
                    print(f"\t[*] Port {result} - OPEN")
                    logger.info(f"Found open port: {result}")

        pbar.close()

        elapsed_time = time.time() - start_time
        logger.info(f"Async scan completed in {elapsed_time:.2f} seconds")
        logger.info(f"Found {len(open_ports)} open ports")

        return sorted(open_ports)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Port Discovery Tool - Scan for open ports on a target host",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_discovery.py 192.168.1.1
  python port_discovery.py 10.10.0.139 --timeout 2.0 --workers 200
  python port_discovery.py localhost --start-port 80 --end-port 443 --async
  python port_discovery.py 192.168.1.1 --log-file logs/scan.log --verbose
        """,
    )

    parser.add_argument("target", help="Target host IP address or hostname")

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Maximum number of concurrent workers (default: 100)",
    )

    parser.add_argument(
        "--start-port", type=int, default=1, help="Starting port number (default: 1)"
    )

    parser.add_argument(
        "--end-port",
        type=int,
        default=65535,
        help="Ending port number (default: 65535)",
    )

    parser.add_argument(
        "--async",
        action="store_true",
        dest="use_async",
        help="Use asynchronous scanning (faster for large port ranges)",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    parser.add_argument(
        "--log-file",
        type=str,
        help="Log file path (default: logs/port_discovery_YYYYMMDD_HHMMSS.log)",
    )

    parser.add_argument(
        "--no-progress", action="store_true", help="Disable progress bar"
    )

    args = parser.parse_args()

    if args.log_file:
        log_file = args.log_file
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"logs/port_discovery_{timestamp}.log"

    global logger
    logger = setup_logging(log_file, args.verbose)

    if args.start_port < 1 or args.end_port > 65535:
        logger.error("Port numbers must be between 1 and 65535")
        sys.exit(1)

    if args.start_port > args.end_port:
        logger.error("Start port must be less than or equal to end port")
        sys.exit(1)

    if args.timeout <= 0:
        logger.error("Timeout must be positive")
        sys.exit(1)

    if args.workers <= 0:
        logger.error("Number of workers must be positive")
        sys.exit(1)

    try:
        logger.info(f"Starting Port Discovery Tool")
        logger.info(f"Target: {args.target}")
        logger.info(f"Port range: {args.start_port}-{args.end_port}")
        logger.info(f"Timeout: {args.timeout}s")
        logger.info(f"Workers: {args.workers}")
        logger.info(f"Mode: {'Async' if args.use_async else 'Sync'}")
        logger.info(f"Log file: {log_file}")

        scanner = PortScanner(
            target_host=args.target, timeout=args.timeout, max_workers=args.workers
        )

        if args.use_async:
            open_ports = asyncio.run(
                scanner.scan_ports_async(args.start_port, args.end_port)
            )
        else:
            open_ports = scanner.scan_ports_sync(args.start_port, args.end_port)

        if open_ports:
            print(f"\n[*] Scan Summary:")
            print(f"[*] Target: {args.target}")
            print(f"[*] Open ports found: {len(open_ports)}")
            print(f"[*] Open ports: {', '.join(map(str, open_ports))}")
            logger.info(
                f"Scan completed successfully. Found {len(open_ports)} open ports."
            )
        else:
            print(f"\n[*] No open ports found on {args.target}")
            logger.info("Scan completed successfully. No open ports found.")

    except KeyboardInterrupt:
        logger.info("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
