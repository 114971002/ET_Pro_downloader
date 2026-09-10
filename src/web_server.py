import logging
from pathlib import Path
from typing import Optional
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn
from core_state import *
from routers import rules, cti, system, geoip
import threading

# Setup logger for the web server
logger = logging.getLogger("web_server")

app = FastAPI(title="ETPro Auto Downloader Dashboard")

# Save project_root in app state
app.state.project_root = Path(__file__).resolve().parent.parent

# Serve static directory if it exists
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(rules.router)
app.include_router(cti.router)
app.include_router(system.router)
app.include_router(geoip.router)

class FastAPIServerWrapper:
    """Wrapper class to mimic http.server ThreadingHTTPServer control interface for test suite compatibility"""
    def __init__(self, app, host: str, port: int):
        self.host = host
        self._port = port
        self.app = app
        
        # Resolve dynamic port if 0 is passed
        if port == 0:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((host, 0))
            self._port = sock.getsockname()[1]
            sock.close()

        try:
            from config import SHUTDOWN_EVENT
            SHUTDOWN_EVENT.clear()
        except Exception:
            pass

        self.config = uvicorn.Config(
            app=self.app,
            host=self.host,
            port=self._port,
            log_level="warning",
            loop="asyncio"
        )
        self.server = uvicorn.Server(self.config)

    @property
    def server_port(self) -> int:
        return self._port

    def serve_forever(self) -> None:
        """Starts the Uvicorn web server."""
        self.server.run()

    def shutdown(self) -> None:
        """Signals Uvicorn to exit."""
        self.server.should_exit = True
        try:
            from config import SHUTDOWN_EVENT
            SHUTDOWN_EVENT.set()
        except Exception:
            pass

    def server_close(self) -> None:
        """Teardown server wrapper."""
        self.shutdown()


def start_server(host: str = "127.0.0.1", port: int = 8000, project_root: Optional[Path] = None) -> FastAPIServerWrapper:
    """Convenience function to configure and launch the server instance wrapper."""
    if project_root is not None:
        app.state.project_root = project_root
        
    server_wrapper = FastAPIServerWrapper(app, host, port)
    logger.info("FastAPI Management Server initialized at http://%s:%d", host, server_wrapper.server_port)
    return server_wrapper
