"""
Integration tests for FastAPI endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "active_model" in data


def test_predict_phishing_sample():
    payload = {
        "text": "Your account has been suspended! Click here immediately to restore access or face legal prosecution: http://185.220.101.5/login",
        "subject": "CRITICAL: Urgent action required",
        "sender": "security@paypa1-support.com"
    }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ["Dangerous", "Suspicious"]
    assert data["risk_score"] >= 50
    assert len(data["key_reasons"]) > 0
    assert data["phishing_probability"] > 0.5
    assert len(data["urls_detected"]) >= 1


def test_predict_legitimate_sample():
    payload = {
        "text": "Hi team, sprint retrospective is scheduled for Friday at 3 PM. Please update your Jira tickets.",
        "subject": "Sprint Retrospective & Demo",
        "sender": "sarah.jenkins@acme-corp.com"
    }
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Safe"
    assert data["risk_score"] < 40


def test_analyze_url_endpoint():
    payload = {"url": "http://paypal-verification-center.xyz/auth"}
    response = client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_typosquat"] is True
    assert data["is_suspicious_tld"] is True
    assert data["defanged_url"].startswith("hxxp://")


def test_model_metrics_endpoint():
    response = client.get("/api/v1/models/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "models" in data
    assert "benchmark_table" in data


def test_analyze_eml_endpoint():
    raw_eml = """From: Security Alert <security@paypa1-support.com>
To: victim@example.com
Subject: URGENT: Confirm your identity
Date: Mon, 19 Nov 2026 10:00:00 +0000
Message-ID: <test-999@paypa1-support.com>

Please verify your account credentials immediately or balance will be locked:
http://185.220.101.5/login
"""
    files = {"file": ("suspicious.eml", raw_eml.encode("utf-8"), "message/rfc822")}
    response = client.post("/api/v1/analyze/eml", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ["Dangerous", "Suspicious"]
    assert data["risk_score"] >= 50
    assert len(data["urls_detected"]) >= 1
    assert "subject" in data


def test_batch_predict_endpoint():
    payload = {
        "emails": [
            {
                "text": "CRITICAL: Urgent action required, PayPal account locked: http://185.220.101.5/login",
                "subject": "Account Lockout",
                "sender": "security@paypa1-fake.com"
            },
            {
                "text": "Sprint retrospective this Friday at 3pm on Google Meet.",
                "subject": "Sprint Meeting",
                "sender": "lead@company.com"
            }
        ]
    }
    response = client.post("/api/v1/predict/batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_scanned"] == 2
    assert data["dangerous_count"] >= 1
    assert data["safe_count"] >= 1
    assert len(data["results"]) == 2


def test_attachment_analyze_endpoint():
    response = client.post("/api/v1/analyze/attachment", data={"filename": "invoice_update.exe"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_executable"] is True
    assert data["verdict"] == "Dangerous"


def test_simulator_and_feedback_endpoints():
    # 1. Get next quiz question
    q_resp = client.get("/api/v1/simulator/next")
    assert q_resp.status_code == 200
    q_data = q_resp.json()
    assert "id" in q_data

    # 2. Submit answer
    ans_resp = client.post("/api/v1/simulator/answer", json={"scenario_id": q_data["id"], "user_guess_is_phish": True})
    assert ans_resp.status_code == 200
    ans_data = ans_resp.json()
    assert "is_correct" in ans_data
    assert "explanation" in ans_data

    # 3. Submit feedback
    fb_resp = client.post("/api/v1/feedback", json={
        "email_snippet": "Test email snippet",
        "predicted_verdict": "Safe",
        "user_reported_label": "Correct",
        "comments": "Accurate prediction"
    })
    assert fb_resp.status_code == 200

    # 4. List feedback
    list_resp = client.get("/api/v1/feedback")
    assert list_resp.status_code == 200
    assert len(list_resp.json()["feedback"]) >= 1


def test_dataset_upload_endpoint():
    csv_content = (
        'subject,sender,body\n'
        '"Urgent PayPal Alert","security@paypa1-support.com","Your account access is restricted. Verify at http://185.220.101.5/auth"\n'
        '"Team Sync Tomorrow","manager@company.com","Reminder regarding tomorrow morning team sync in Room 4."\n'
    )
    files = {"file": ("test_emails.csv", csv_content.encode("utf-8"), "text/csv")}
    response = client.post("/api/v1/predict/dataset", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["total_scanned"] == 2
    assert data["phishing_flagged_count"] >= 1
    assert data["legit_verified_count"] >= 1
    assert len(data["results"]) == 2
    assert "flag_status" in data["results"][0]


def test_sample_dataset_download():
    response = client.get("/api/v1/dataset/sample")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert b"subject" in response.content


def test_pdf_report_endpoints():
    # Single PDF
    single_payload = {
        "subject": "Test Urgent Alert",
        "sender": "alert@bank.com",
        "verdict": "Dangerous",
        "risk_score": 85,
        "phishing_probability": 0.9,
        "key_reasons": ["Urgent language", "Untrusted domain"],
        "tactics": {"scores": {"urgency": 90, "fear": 80}}
    }
    single_resp = client.post("/api/v1/report/pdf", json=single_payload)
    assert single_resp.status_code == 200
    assert single_resp.headers["content-type"] == "application/pdf"
    assert len(single_resp.content) > 1000

    # Batch PDF
    batch_payload = {
        "total_scanned": 1,
        "dangerous_count": 1,
        "suspicious_count": 0,
        "safe_count": 0,
        "results": [
            {
                "subject": "Test Phish",
                "sender": "evil@domain.com",
                "verdict": "Dangerous",
                "risk_score": 90,
                "primary_tactic": "Urgency"
            }
        ]
    }
    batch_resp = client.post("/api/v1/report/batch-pdf", json=batch_payload)
    assert batch_resp.status_code == 200
    assert batch_resp.headers["content-type"] == "application/pdf"
    assert len(batch_resp.content) > 1000


def test_kaggle_spam_csv_upload_with_over_100_rows():
    """Test realistic Kaggle spam dataset format (v1,v2 columns, Latin-1, 150 rows)."""
    lines = ["v1,v2,,,"]
    for i in range(150):
        if i % 2 == 0:
            lines.append(f'spam,"URGENT: Win $1000 cash prize #{i} by verifying http://185.220.101.5/prize",,,')
        else:
            lines.append(f'ham,"Hey team, meeting at {i} PM in conference room.",,,')
    csv_bytes = "\n".join(lines).encode("latin-1")

    files = {"file": ("spam.csv", csv_bytes, "text/csv")}
    response = client.post("/api/v1/predict/dataset", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["total_scanned"] == 100
    assert data["dataset_total_rows"] == 150
    assert data["phishing_flagged_count"] >= 40
    assert data["legit_verified_count"] >= 40
    assert len(data["results"]) == 100

