"""
Unit tests for multilingual phishing detector.
"""

import pytest
from src.analyzers.multilingual_detector import MultilingualDetector


def test_detect_hindi_script():
    hindi_text = "कृपया तुरंत अपना बैंक पासवर्ड बदलें और खाता सुरक्षित करें।"
    result = MultilingualDetector.analyze_multilingual_threats(hindi_text)
    assert result["detected_language"] == "Hindi"
    assert result["has_multilingual_lures"] is True
    assert len(result["matched_cues"]) >= 1


def test_detect_hinglish():
    hinglish_text = "Kripya turant apna bank khata verify karein warna account block ho jayega."
    result = MultilingualDetector.analyze_multilingual_threats(hinglish_text)
    assert result["detected_language"] == "Hinglish"
    assert result["has_multilingual_lures"] is True
    assert any("turant" in c for c in result["matched_cues"])


def test_detect_spanish():
    spanish_text = "Aviso urgente: Su cuenta de banco ha sido bloqueada. Por favor verifique su contrasena inmediatamente."
    result = MultilingualDetector.analyze_multilingual_threats(spanish_text)
    assert result["detected_language"] == "Spanish"
    assert result["has_multilingual_lures"] is True
    assert any("urgente" in c for c in result["matched_cues"])


def test_standard_english():
    eng_text = "Here are the notes from our team standup."
    result = MultilingualDetector.analyze_multilingual_threats(eng_text)
    assert result["detected_language"] == "English"
    assert result["has_multilingual_lures"] is False
