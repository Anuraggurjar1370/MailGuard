"""
Pydantic Request and Response Schemas for MailGuard API.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class PredictRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100000, description="Email body or combined email text")
    subject: Optional[str] = Field(None, max_length=500, description="Email subject line")
    sender: Optional[str] = Field(None, max_length=500, description="Sender header (e.g. 'Security <admin@paypal-verify.com>')")


class UrlAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2000, description="URL to analyze statically")


class WordAttribution(BaseModel):
    word: str
    importance: float


class PredictResponse(BaseModel):
    verdict: str
    risk_score: int
    verdict_badge: str
    verdict_description: str
    model_name: str
    phishing_probability: float
    highlighted_html: str
    top_phishing_words: List[WordAttribution]
    top_legitimate_words: List[WordAttribution]
    key_reasons: List[str]
    score_breakdown: Dict[str, Any]
    urls_detected: List[Dict[str, Any]]
    tactics: Optional[Dict[str, Any]] = None
    brand_impersonation: Optional[Dict[str, Any]] = None
    latency_ms: float


class BatchPredictRequest(BaseModel):
    emails: List[PredictRequest] = Field(..., max_length=1000, description="List of emails to scan in batch")


class BatchPredictResponse(BaseModel):
    total_scanned: int
    dangerous_count: int
    suspicious_count: int
    safe_count: int
    phishing_flagged_count: int = 0
    legit_verified_count: int = 0
    dataset_total_rows: Optional[int] = None
    results: List[Dict[str, Any]]


class AttachmentAnalyzeRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)


class FeedbackRequest(BaseModel):
    email_snippet: str
    predicted_verdict: str
    user_reported_label: str
    comments: Optional[str] = ""


class SimulatorAnswerRequest(BaseModel):
    scenario_id: str
    user_guess_is_phish: bool


class EmlAnalyzeResponse(BaseModel):
    verdict: str
    risk_score: int
    verdict_badge: str
    verdict_description: str
    subject: str
    from_header: str
    to_header: str
    date_header: str
    header_anomalies: List[str]
    auth_status: Dict[str, str]
    hops_count: int
    hops: List[Dict[str, Any]]
    urls_detected: List[Dict[str, Any]]
    highlighted_html: str
    key_reasons: List[str]
    score_breakdown: Dict[str, Any]
    tactics: Optional[Dict[str, Any]] = None
    brand_impersonation: Optional[Dict[str, Any]] = None
    latency_ms: float
