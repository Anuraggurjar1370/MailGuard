"""
Model Evaluation and Benchmarking Suite.
Calculates Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix,
Precision-Recall curves, Calibration Brier score, and measures inference latency and model sizes.
"""

import time
import os
import json
import numpy as np
from typing import Dict, Any, List
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, precision_recall_curve,
    roc_curve, brier_score_loss
)


def evaluate_model(
    model,
    X_test,
    y_test,
    model_name: str,
    feature_pipeline=None
) -> Dict[str, Any]:
    """
    Computes comprehensive evaluation metrics, latency benchmark, and error distributions.
    Prioritizes Phishing Recall (Class 1).
    """
    # Transform features if raw test data is passed
    if feature_pipeline is not None:
        X_test_trans = feature_pipeline.transform(X_test)
    else:
        X_test_trans = X_test

    # Inference latency measurement (warmup + 50 iterations benchmark)
    # Warmup
    _ = model.predict(X_test_trans[:min(5, len(y_test))])
    
    start_time = time.perf_counter()
    n_runs = 50
    for _ in range(n_runs):
        preds = model.predict(X_test_trans)
    elapsed = time.perf_counter() - start_time
    avg_latency_ms = (elapsed / (n_runs * len(y_test))) * 1000.0

    # Probabilities
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X_test_trans)[:, 1]
    elif hasattr(model, "decision_function"):
        scores = model.decision_function(X_test_trans)
        probs = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
    else:
        probs = preds.astype(float)

    # Standard metrics
    acc = float(accuracy_score(y_test, preds))
    prec = float(precision_score(y_test, preds, pos_label=1, zero_division=0))
    rec = float(recall_score(y_test, preds, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_test, preds, pos_label=1, zero_division=0))
    
    try:
        auc = float(roc_auc_score(y_test, probs))
    except Exception:
        auc = 0.5

    brier = float(brier_score_loss(y_test, probs))
    cm = confusion_matrix(y_test, preds).tolist()  # [[TN, FP], [FN, TP]]

    # Precision-Recall and ROC curves data
    precisions, recalls, pr_thresholds = precision_recall_curve(y_test, probs)
    fpr, tpr, roc_thresholds = roc_curve(y_test, probs)

    # Subsample curve points for compact JSON storage
    step = max(1, len(precisions) // 20)
    pr_curve_sample = [{"precision": round(float(p), 4), "recall": round(float(r), 4)} for p, r in zip(precisions[::step], recalls[::step])]
    roc_curve_sample = [{"fpr": round(float(f), 4), "tpr": round(float(t), 4)} for f, t in zip(fpr[::step], tpr[::step])]

    return {
        "model_name": model_name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall_phishing": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "brier_score": round(brier, 4),
        "latency_ms_per_email": round(avg_latency_ms, 3),
        "confusion_matrix": {
            "true_negative": cm[0][0],
            "false_positive": cm[0][1],
            "false_negative": cm[1][0],
            "true_positive": cm[1][1]
        },
        "pr_curve": pr_curve_sample,
        "roc_curve": roc_curve_sample,
        "priority_explanation": (
            "Phishing Recall is prioritized over Precision because False Negatives (allowing an active "
            "phishing attack or credential harvest into an executive or employee inbox) carry catastrophic risk "
            "(ransomware, BEC wire fraud, account takeover). A False Positive causes minor verification friction, "
            "whereas a False Negative causes compromise."
        )
    }


def format_benchmark_table(metrics_dict: Dict[str, Dict[str, Any]], model_sizes: Dict[str, float]) -> List[Dict[str, Any]]:
    """Format tabular benchmark comparing models on accuracy, recall, latency, and memory footprint."""
    rows = []
    for name, m in metrics_dict.items():
        size_kb = model_sizes.get(name, 0.0)
        rows.append({
            "Model": name,
            "Accuracy": f"{m['accuracy'] * 100:.2f}%",
            "Recall (Phish)": f"{m['recall_phishing'] * 100:.2f}%",
            "Precision": f"{m['precision'] * 100:.2f}%",
            "F1-Score": f"{m['f1_score'] * 100:.2f}%",
            "ROC-AUC": f"{m['roc_auc']:.4f}",
            "Latency (ms)": f"{m['latency_ms_per_email']:.2f} ms",
            "Size (KB)": f"{size_kb:.1f} KB"
        })
    return rows
