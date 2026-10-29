import re
from typing import Optional, Tuple

MAC_VENDORS = {
    "00:11:22": ("Cisco Systems", "Enterprise Gateway / Switch"),
    "aa:bb:cc": ("Intel Mobile", "Corporate Workstation"),
    "ff:ee:dd": ("Unknown / Rogue NIC", "Adversary Injection Node"),
    "b8:27:eb": ("Raspberry Pi Foundation", "IoT / Microcontroller"),
    "00:50:56": ("VMware Virtual Target", "Virtual Machine / Hypervisor"),
    "00:0c:29": ("VMware Workstation", "Virtual Guest"),
    "50:c7:bf": ("TP-Link Corporation", "Smart Router"),
    "f0:18:98": ("Apple Inc.", "macOS / iOS Endpoint"),
    "24:0a:c4": ("Espressif Systems", "Smart IoT / ESP32"),
}

def resolve_vendor(mac: str) -> Tuple[str, str]:
    prefix = mac.lower()[:8]
    return MAC_VENDORS.get(prefix, ("Generic Network Hardware", "Host Endpoint"))

def normalize_mac_address(raw_mac: str) -> Optional[str]:
    clean = raw_mac.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    if len(clean) != 12 or not all(c in "0123456789abcdef" for c in clean):
        return None
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))

def extract_log_fields(clean_line: str) -> Tuple[Optional[str], str, str, str]:
    ts = None
    m_bracket = re.match(r"^\[(.*?)\]\s*(.*)$", clean_line)
    if m_bracket:
        ts = m_bracket.group(1).strip()
        clean_line = m_bracket.group(2).strip()

    parts = [p.strip() for p in clean_line.split(",") if p.strip()] if "," in clean_line else clean_line.split()

    if parts and re.match(r"^\d{4}-\d{2}-\d{2}", parts[0]):
        if len(parts) >= 2 and re.match(r"^\d{2}:\d{2}", parts[1]):
            ts = f"{parts[0]} {parts[1]}"
            parts = parts[2:]
        else:
            ts = parts[0]
            parts = parts[1:]

    ip_str = parts[0] if len(parts) > 0 else ""
    mac_str = parts[1] if len(parts) > 1 else ""
    entry_type = parts[2].lower() if len(parts) > 2 else "dynamic"

    return ts, ip_str, mac_str, entry_type