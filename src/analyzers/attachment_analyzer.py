"""
Safe Attachment Risk Analyzer.
Statically inspects file metadata and calculates SHA-256 hashes without ever executing files:
- Detects dangerous extensions (.exe, .scr, .bat, .vbs, .hta)
- Detects macro-enabled documents (.docm, .xlsm, .pptm)
- Detects deceptive double extensions (e.g. invoice.pdf.exe)
- Detects HTML phishing attachments (.html, .htm)
"""

import hashlib
import os
from typing import Dict, Any, List, Optional

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".ps1",
    ".hta", ".cpl", ".msi", ".jar", ".com", ".pif"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}

SUSPICIOUS_CONTAINERS = {
    ".iso", ".img", ".vhd", ".html", ".htm", ".svg"
}

STANDARD_SAFE_EXTENSIONS = {
    ".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv",
    ".png", ".jpg", ".jpeg", ".gif", ".zip"
}


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of file content safely."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def analyze_attachment_file(filename: str, content_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Perform safe static inspection on an email attachment.
    Never executes or launches the file.
    """
    clean_name = os.path.basename(filename).strip()
    name_lower = clean_name.lower()
    threat_flags: List[str] = []

    # 1. Double extension check (e.g. statement.pdf.exe)
    parts = name_lower.split('.')
    is_double_extension = False
    if len(parts) > 2:
        second_last = "." + parts[-2]
        last = "." + parts[-1]
        if second_last in STANDARD_SAFE_EXTENSIONS and last in (DANGEROUS_EXTENSIONS | MACRO_EXTENSIONS | SUSPICIOUS_CONTAINERS):
            is_double_extension = True
            threat_flags.append(f"Deceptive double extension detected: '{second_last}{last}' masquerading as safe document")

    # 2. Extension danger check
    ext = os.path.splitext(name_lower)[1]
    is_executable = ext in DANGEROUS_EXTENSIONS
    is_macro = ext in MACRO_EXTENSIONS
    is_suspicious_container = ext in SUSPICIOUS_CONTAINERS

    if is_executable:
        threat_flags.append(f"High-Risk Executable script or binary extension ({ext})")
    if is_macro:
        threat_flags.append(f"Macro-enabled document ({ext}) capable of executing malicious VBA payloads")
    if is_suspicious_container:
        threat_flags.append(f"Suspicious container/HTML file ({ext}) commonly used for credential harvesting")

    # 3. Calculate SHA-256 if file bytes provided
    sha256_hash = compute_sha256(content_bytes) if content_bytes else "N/A (Filename Inspection Only)"
    file_size_kb = round(len(content_bytes) / 1024, 2) if content_bytes else 0.0

    # 4. Determine Verdict
    if is_executable or is_double_extension or is_macro:
        verdict = "Dangerous"
        risk_score = 95
    elif is_suspicious_container:
        verdict = "Suspicious"
        risk_score = 65
    else:
        verdict = "Safe"
        risk_score = 10

    return {
        "filename": clean_name,
        "extension": ext,
        "file_size_kb": file_size_kb,
        "sha256": sha256_hash,
        "is_executable": is_executable,
        "is_macro": is_macro,
        "is_double_extension": is_double_extension,
        "risk_score": risk_score,
        "verdict": verdict,
        "threat_flags": threat_flags
    }
