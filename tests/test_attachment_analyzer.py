"""
Unit tests for attachment risk analyzer.
"""

import pytest
from src.analyzers.attachment_analyzer import analyze_attachment_file


def test_dangerous_executable_attachment():
    result = analyze_attachment_file("invoice_update.exe", b"MZDummyExecutableBytes")
    assert result["is_executable"] is True
    assert result["verdict"] == "Dangerous"
    assert result["risk_score"] >= 90
    assert result["sha256"] != "N/A (Filename Inspection Only)"


def test_deceptive_double_extension():
    result = analyze_attachment_file("Salary_Report.pdf.exe")
    assert result["is_double_extension"] is True
    assert result["verdict"] == "Dangerous"


def test_macro_enabled_document():
    result = analyze_attachment_file("Purchase_Order.docm")
    assert result["is_macro"] is True
    assert result["verdict"] == "Dangerous"


def test_safe_pdf_attachment():
    result = analyze_attachment_file("Sprint_Notes.pdf", b"%PDF-1.4CleanPDFBytes")
    assert result["verdict"] == "Safe"
    assert result["risk_score"] < 40
