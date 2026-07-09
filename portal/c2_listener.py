"""
Persistent C2 listener for connection-back malware testing.

Accepts TCP connections, logs them, and saves received data to disk.
Managed by the portal via start/stop/status API.

Data is saved per-session: each start() creates a new directory under
results/c2_data/session_<timestamp>/. When the listener stops, if
is_test_run=True the session directory is deleted automatically.
"""
import asyncio
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

C2_DATA_ROOT = Path(__file__).parent.parent / "results" / "c2_data"


@dataclass
class C2Connection:
    addr: str
    port: int
    connected_at: float
    bytes_received: int = 0
    data_file: str = ""
    closed: bool = False


@dataclass
class C2Listener:
    listen_port: int = 9001
    listen_host: str = "0.0.0.0"
    running: bool = False
    is_test_run: bool = False
    connections: list[C2Connection] = field(default_factory=list)
    _server: asyncio.AbstractServer | None = field(default=None, repr=False)
    _total_bytes: int = 0
    _session_dir: Path | None = field(default=None, repr=False)

    async def start(self, port: int = 9001, host: str = "0.0.0.0",
                    is_test_run: bool = False) -> bool:
        if self.running and self._server:
            if self.listen_port == port:
                return True
            await self.stop()

        self.listen_port = port
        self.listen_host = host
        self.is_test_run = is_test_run
        self.connections.clear()
        self._total_bytes = 0

        ts = time.strftime("%Y%m%d_%H%M%S")
        self._session_dir = C2_DATA_ROOT / f"session_{ts}"
        self._session_dir.mkdir(parents=True, exist_ok=True)

        try:
            self._server = await asyncio.start_server(
                self._handle_client, host, port,
            )
            self.running = True
            logger.info("C2 listener started on %s:%d (session: %s, test=%s)",
                        host, port, self._session_dir.name, is_test_run)
            return True
        except Exception as exc:
            logger.error("C2 listener failed to start on port %d: %s", port, exc)
            self.running = False
            return False

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self.running = False

        if self.is_test_run and self._session_dir and self._session_dir.exists():
            shutil.rmtree(self._session_dir, ignore_errors=True)
            logger.info("C2 listener stopped — test session cleaned up: %s",
                        self._session_dir.name)
        else:
            logger.info("C2 listener stopped (session: %s)",
                        self._session_dir.name if self._session_dir else "none")

        self._session_dir = None

    def status(self) -> dict:
        return {
            "running": self.running,
            "port": self.listen_port,
            "host": self.listen_host,
            "is_test_run": self.is_test_run,
            "session_dir": self._session_dir.name if self._session_dir else None,
            "total_connections": len(self.connections),
            "active_connections": sum(1 for c in self.connections if not c.closed),
            "total_bytes": self._total_bytes,
            "connections": [
                {
                    "addr": c.addr,
                    "port": c.port,
                    "connected_at": c.connected_at,
                    "bytes_received": c.bytes_received,
                    "data_file": c.data_file,
                    "closed": c.closed,
                }
                for c in self.connections[-20:]
            ],
        }

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        addr = peer[0] if peer else "unknown"
        port = peer[1] if peer else 0

        ts = time.strftime("%Y%m%d_%H%M%S")
        session_dir = self._session_dir or C2_DATA_ROOT
        session_dir.mkdir(parents=True, exist_ok=True)
        data_file = session_dir / f"c2_received_{ts}_{addr}_{port}.bin"

        conn = C2Connection(
            addr=addr, port=port,
            connected_at=time.time(),
            data_file=data_file.name,
        )
        self.connections.append(conn)
        logger.info("C2: connection from %s:%d", addr, port)

        try:
            with open(data_file, "wb") as f:
                while True:
                    data = await asyncio.wait_for(reader.read(8192), timeout=60)
                    if not data:
                        break
                    f.write(data)
                    conn.bytes_received += len(data)
                    self._total_bytes += len(data)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            logger.warning("C2: error reading from %s:%d: %s", addr, port, exc)
        finally:
            conn.closed = True
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        if conn.bytes_received == 0:
            data_file.unlink(missing_ok=True)
            logger.info("C2: %s:%d disconnected — 0 bytes (empty file removed)", addr, port)
        else:
            logger.info(
                "C2: %s:%d disconnected — %d bytes saved to %s",
                addr, port, conn.bytes_received, data_file.name,
            )


listener = C2Listener()
