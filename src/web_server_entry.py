from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Add src/ to path so imports work correctly
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from web_server import start_server


def main() -> None:
    parser = argparse.ArgumentParser(description="ET Pro Auto Downloader Web Management Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Binding host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Binding port (default: 8000)")
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    project_root = SRC_DIR.parent
    server = start_server(host=args.host, port=args.port, project_root=project_root)

    print(f"\n==================================================================")
    print(f"  ET Pro Auto Downloader Web Management Platform")
    print(f"  Server is running at: http://{args.host}:{args.port}")
    print(f"  Press Ctrl+C to terminate the server safely.")
    print(f"==================================================================\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt received. Terminating Web Server safely...")
    finally:
        from config import SHUTDOWN_EVENT
        SHUTDOWN_EVENT.set()
        server.server_close()
        print("[+] Web Server closed successfully.")


if __name__ == "__main__":
    main()
