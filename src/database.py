import os
import sqlite3
import threading
from typing import Any, Dict

STATE_LOCK = threading.RLock()
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../sentinel.db")

def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with STATE_LOCK:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_assets (
                    ip TEXT PRIMARY KEY,
                    mac TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    entry_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    is_baseline INTEGER DEFAULT 0,
                    baseline_mac TEXT,
                    attack_count INTEGER DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT,
                    mac TEXT,
                    vendor TEXT,
                    entry_type TEXT,
                    status TEXT NOT NULL,
                    rule_name TEXT,
                    message TEXT NOT NULL,
                    details TEXT,
                    remediation TEXT,
                    raw_entry TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    rogue_mac TEXT NOT NULL,
                    baseline_mac TEXT NOT NULL,
                    details TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    status TEXT DEFAULT 'ACTIVE'
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS terminal_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    text TEXT NOT NULL,
                    log_type TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_metrics (
                    metric_key TEXT PRIMARY KEY,
                    metric_val INTEGER DEFAULT 0
                )
            """)
            conn.commit()

            metrics_keys = [
                "total_processed", "valid_records", "rejected_records", "detected_attacks",
                "INJECTION_BLOCKED", "SYNTAX_ERROR", "OCTET_BOUNDS_ERROR",
                "RESERVED_IP_DROPPED", "OUT_OF_SCOPE_WAN_IP", "INVALID_MAC_FORMAT",
                "BROADCAST_MAC_DROPPED"
            ]
            for key in metrics_keys:
                cursor.execute("INSERT OR IGNORE INTO system_metrics (metric_key, metric_val) VALUES (?, 0)", (key,))
            conn.commit()

def track_metric(metric_name: str, delta: int = 1):
    with STATE_LOCK:
        try:
            with get_db_connection() as conn:
                conn.execute("UPDATE system_metrics SET metric_val = metric_val + ? WHERE metric_key = ?", (delta, metric_name))
                conn.commit()
        except Exception as e:
            print(f"[!] Metric tracking error: {e}")

def get_current_metrics() -> Dict[str, Any]:
    metrics = {
        "total_processed": 0,
        "valid_records": 0,
        "rejected_records": 0,
        "detected_attacks": 0,
        "rejection_reasons": {}
    }
    with STATE_LOCK:
        try:
            with get_db_connection() as conn:
                rows = conn.execute("SELECT metric_key, metric_val FROM system_metrics").fetchall()
                for row in rows:
                    k, v = row["metric_key"], row["metric_val"]
                    if k in metrics:
                        metrics[k] = v
                    else:
                        metrics["rejection_reasons"][k] = v
        except Exception as e:
            print(f"[!] Metric retrieval error: {e}")
    return metrics

def record_structured_log(timestamp: str, ip: str, mac: str, vendor: str, entry_type: str,
                          status: str, rule_name: str, message: str, details: str, remediation: str, raw_entry: str):
    with STATE_LOCK:
        try:
            with get_db_connection() as conn:
                conn.execute("""
                    INSERT INTO security_logs
                    (timestamp, ip, mac, vendor, entry_type, status, rule_name, message, details, remediation, raw_entry)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (timestamp, ip, mac, vendor, entry_type, status, rule_name, message, details, remediation, raw_entry))
                conn.commit()
        except Exception as e:
            print(f"[!] Log recording error: {e}")