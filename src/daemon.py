import platform
import subprocess
import threading
from datetime import datetime
from typing import Optional
from src.database import get_db_connection, STATE_LOCK
from src.processor import validate_and_parse_log_entry

def log_terminal(line: str, line_type: str = "info"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{line_type.upper()}] [{ts}] {line}")
    with STATE_LOCK:
        try:
            with get_db_connection() as conn:
                conn.execute("INSERT INTO terminal_logs (timestamp, text, log_type) VALUES (?, ?, ?)", (ts, line, line_type))
                conn.commit()
        except Exception:
            pass

class ArpWatcherDaemon:
    def __init__(self, interval: float = 5.0):
        self.interval = interval
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.last_scan_time = "Never"
        self.last_entry_count = 0

    def start(self):
        with STATE_LOCK:
            if self.is_running:
                return
            self.is_running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name="ArpSentinelWorker")
            self._thread.start()
            log_terminal("Live OS ARP Sentinel Daemon initialized.", "success")

    def stop(self):
        with STATE_LOCK:
            if not self.is_running:
                return
            self.is_running = False
            self._stop_event.set()
            log_terminal("Live OS ARP Sentinel Daemon paused.", "info")

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self.scan_os_table()
            except Exception as e:
                log_terminal(f"Daemon scan error: {e}", "critical")
            self._stop_event.wait(self.interval)

    def scan_os_table(self) -> int:
        cmd = ["arp", "-a"] if platform.system().lower() == "windows" else ["arp", "-n"]
        try:
            raw_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8", errors="ignore")
        except Exception:
            return 0

        found = 0
        for line in raw_output.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 2:
                record, status, msg, incident = validate_and_parse_log_entry(f"{parts[0]} {parts[1]}")
                if status == "ACCEPTED":
                    found += 1
                elif status == "ATTACK":
                    log_terminal(f"CRITICAL THREAT: {msg}", "critical")
        self.last_scan_time = datetime.now().strftime("%H:%M:%S")
        self.last_entry_count = found
        return found

SENTINEL_DAEMON = ArpWatcherDaemon(interval=5.0)