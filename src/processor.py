import ipaddress
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from src.database import get_db_connection, record_structured_log, STATE_LOCK, track_metric
from src.parser import extract_log_fields, normalize_mac_address, resolve_vendor

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
INJECTION_CHARACTERS = [";", "&&", "|", "`", "$", "<", ">", "%", "script", "eval("]

def validate_and_parse_log_entry(raw_line: str) -> Tuple[Optional[Dict[str, Any]], str, str, Optional[Dict[str, Any]]]:
    track_metric("total_processed")
    clean_line = raw_line.strip()
    log_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
        return None, "SKIPPED", "Comment or empty line ignored.", None

    if any(char in clean_line.lower() for char in INJECTION_CHARACTERS):
        track_metric("rejected_records")
        track_metric("INJECTION_BLOCKED")
        msg = f"Security Alert: Malicious injection pattern blocked in '{clean_line}'"
        record_structured_log(log_ts, "N/A", "N/A", "Unknown", "N/A", "WARN", "INJECTION_BLOCKED",
                              msg, "Command separator or script token detected.", "Sanitize inputs.", clean_line)
        return None, "REJECTED", msg, None

    extracted_ts, ip_str, mac_str, entry_type = extract_log_fields(clean_line)
    if extracted_ts:
        log_ts = extracted_ts

    if not ip_str or not mac_str:
        track_metric("rejected_records")
        track_metric("SYNTAX_ERROR")
        msg = f"Syntax Error: Unparseable entry in '{clean_line}'"
        record_structured_log(log_ts, ip_str or "N/A", mac_str or "N/A", "Unknown", entry_type, "WARN", "SYNTAX_ERROR",
                              msg, "Invalid syntax format.", "Review log format.", clean_line)
        return None, "REJECTED", msg, None

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version != 4:
            raise ValueError("Only IPv4 addresses operate on Layer-2 ARP.")
    except Exception as e:
        track_metric("rejected_records")
        track_metric("SYNTAX_ERROR")
        return None, "REJECTED", f"Invalid IPv4 syntax: {e}", None

    ip_clean = str(ip_obj)

    if not (ip_obj.is_private or ip_obj.is_link_local):
        track_metric("rejected_records")
        track_metric("OUT_OF_SCOPE_WAN_IP")
        msg = f"Public WAN IP '{ip_clean}' dropped (ARP is non-routable)."
        record_structured_log(log_ts, ip_clean, mac_str, "Public WAN", entry_type, "WARN", "OUT_OF_SCOPE_WAN_IP",
                              msg, "ARP operates strictly on local LANs.", "Ensure local subnets.", clean_line)
        return None, "REJECTED", msg, None

    mac_clean = normalize_mac_address(mac_str)
    if not mac_clean or mac_clean == BROADCAST_MAC:
        track_metric("rejected_records")
        track_metric("INVALID_MAC_FORMAT")
        return None, "REJECTED", f"Invalid or broadcast MAC format: '{mac_str}'", None

    vendor_name, device_type = resolve_vendor(mac_clean)

    with STATE_LOCK:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            existing_row = cursor.execute("SELECT * FROM network_assets WHERE ip = ?", (ip_clean,)).fetchone()
            mac_clones = cursor.execute("SELECT ip, vendor FROM network_assets WHERE mac = ? AND ip != ?", (mac_clean, ip_clean)).fetchall()

            attack_incident = None

            # Threat Rule 1: ARP Poisoning
            if existing_row:
                existing_mac = existing_row["mac"]
                baseline_mac = existing_row["baseline_mac"] or existing_mac

                if existing_mac != mac_clean:
                    track_metric("detected_attacks")
                    alert_details = f"ARP CONFLICT: IP {ip_clean} changed binding from {baseline_mac} to rogue MAC {mac_clean}."
                    remediation = "Deploy Dynamic ARP Inspection (DAI) on switch port."

                    cursor.execute("""
                        INSERT INTO security_incidents (timestamp, severity, rule_name, ip, rogue_mac, baseline_mac, details, remediation, status)
                        VALUES (?, 'CRITICAL', 'ARP_CACHE_POISONING', ?, ?, ?, ?, ?, 'ACTIVE')
                    """, (log_ts, ip_clean, mac_clean, baseline_mac, alert_details, remediation))
                    
                    cursor.execute("UPDATE network_assets SET status = 'POISONED / ATTACK', last_seen = ?, attack_count = attack_count + 1 WHERE ip = ?", (log_ts, ip_clean))
                    conn.commit()

                    attack_incident = {"severity": "CRITICAL", "rule": "ARP_CACHE_POISONING", "ip": ip_clean, "rogue_mac": mac_clean, "baseline_mac": baseline_mac, "details": alert_details, "remediation": remediation}
                    return dict(existing_row), "ATTACK", alert_details, attack_incident

            # Valid Storage Update
            track_metric("valid_records")
            if not existing_row:
                cursor.execute("""
                    INSERT INTO network_assets (ip, mac, vendor, device_type, entry_type, status, first_seen, last_seen, is_baseline, baseline_mac, attack_count)
                    VALUES (?, ?, ?, ?, ?, 'VALIDATED', ?, ?, 0, ?, 0)
                """, (ip_clean, mac_clean, vendor_name, device_type, entry_type, log_ts, log_ts, mac_clean))
            else:
                cursor.execute("""
                    UPDATE network_assets SET mac = ?, vendor = ?, device_type = ?, entry_type = ?, last_seen = ?
                    WHERE ip = ? AND status != 'POISONED / ATTACK'
                """, (mac_clean, vendor_name, device_type, entry_type, log_ts, ip_clean))
            conn.commit()

            msg = f"Verified clean binding: {ip_clean} -> {mac_clean} ({vendor_name})"
            return {"ip": ip_clean, "mac": mac_clean, "vendor": vendor_name, "status": "VALIDATED"}, "ACCEPTED", msg, None