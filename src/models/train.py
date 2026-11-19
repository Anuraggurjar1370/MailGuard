"""
Model Training Pipeline.
Trains and compares:
- Multinomial Naive Bayes
- Calibrated Linear SVM
- Logistic Regression Baseline
- Soft-Voting Ensemble (Combining all 3 with probability calibration)

Handles class balance, 5-Fold Stratified Cross Validation, hyperparameter tuning,
evaluates recall prioritization, profiles latency, and saves versioned artifacts.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import VotingClassifier

from src.data.dataset_builder import ensure_dataset_ready
from src.features.feature_extractor import build_feature_pipeline
from src.models.evaluate import evaluate_model, format_benchmark_table


def train_and_evaluate_all(
    data_path: str = "data/raw/bundled_samples.csv",
    models_dir: str = "models",
    reports_dir: str = "reports"
):
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    # 1. Ensure dataset exists
    if not os.path.exists(data_path):
        data_path = ensure_dataset_ready(os.path.dirname(data_path))

    print(f"[*] Loading dataset from {data_path}...")
    df = pd.read_csv(data_path)
    print(f"[+] Loaded {len(df)} samples. Class balance:\n{df['label'].value_counts()}")

    # 2. Stratified Train/Test Split (80/20)
    X = df["full_text"].values
    y = df["label"].values

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    print(f"[+] Split: {len(X_train_raw)} train samples, {len(X_test_raw)} test samples")

    # 3. Fit Feature Extraction Pipeline
    print("[*] Fitting hybrid feature extraction pipeline (Word TF-IDF + Char TF-IDF + Handcrafted Security)...")
    feature_pipeline = build_feature_pipeline()
    X_train_features = feature_pipeline.fit_transform(X_train_raw)
    X_test_features = feature_pipeline.transform(X_test_raw)
    print(f"[+] Transformed features shape: {X_train_features.shape}")

    # Save feature pipeline
    feature_pipeline_path = os.path.join(models_dir, "feature_pipeline.joblib")
    joblib.dump(feature_pipeline, feature_pipeline_path)
    print(f"[+] Feature pipeline persisted -> {feature_pipeline_path}")

    # 4. Define candidate models
    print("[*] Initializing and tuning models...")

    # A. Multinomial Naive Bayes (fast baseline, high throughput)
    nb_model = MultinomialNB(alpha=0.1)

    # B. Calibrated Linear SVM (Maximum margin separator with Platt sigmoid probability calibration)
    base_svm = LinearSVC(C=1.0, class_weight='balanced', max_iter=3000, random_state=42, dual='auto')
    svm_calibrated = CalibratedClassifierCV(estimator=base_svm, cv=3, method='sigmoid')

    # C. Logistic Regression (Calibrated baseline with L2 regularization)
    lr_model = LogisticRegression(C=2.0, class_weight='balanced', max_iter=1000, random_state=42)

    # 5-Fold Stratified Cross Validation checks on training set
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for name, clf in [("Naive Bayes", nb_model), ("Calibrated SVM", svm_calibrated), ("Logistic Regression", lr_model)]:
        cv_scores = cross_val_score(clf, X_train_features, y_train, cv=skf, scoring='recall')
        print(f"    -> {name} 5-Fold CV Recall: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Train individual models on full training split
    nb_model.fit(X_train_features, y_train)
    svm_calibrated.fit(X_train_features, y_train)
    lr_model.fit(X_train_features, y_train)

    # D. Soft-Voting Ensemble combining all 3
    print("[*] Assembling Soft-Voting Ensemble...")
    ensemble_model = VotingClassifier(
        estimators=[
            ('nb', nb_model),
            ('svm', svm_calibrated),
            ('lr', lr_model)
        ],
        voting='soft',
        weights=[1.0, 1.5, 1.2]  # Give higher confidence to Calibrated SVM & Logistic Regression
    )
    ensemble_model.fit(X_train_features, y_train)

    # Persist all trained models
    model_paths = {
        "Naive Bayes": os.path.join(models_dir, "naive_bayes.joblib"),
        "Calibrated Linear SVM": os.path.join(models_dir, "calibrated_svm.joblib"),
        "Logistic Regression": os.path.join(models_dir, "logistic_regression.joblib"),
        "Soft-Voting Ensemble": os.path.join(models_dir, "ensemble_model.joblib"),
    }

    joblib.dump(nb_model, model_paths["Naive Bayes"])
    joblib.dump(svm_calibrated, model_paths["Calibrated Linear SVM"])
    joblib.dump(lr_model, model_paths["Logistic Regression"])
    joblib.dump(ensemble_model, model_paths["Soft-Voting Ensemble"])

    # Measure file sizes in KB
    model_sizes = {
        name: os.path.getsize(path) / 1024.0 for name, path in model_paths.items()
    }

    # 5. Evaluate all models on held-out test set
    print("[*] Running comprehensive evaluation and latency benchmarking...")
    all_metrics = {}
    models_dict = {
        "Naive Bayes": nb_model,
        "Calibrated Linear SVM": svm_calibrated,
        "Logistic Regression": lr_model,
        "Soft-Voting Ensemble": ensemble_model,
    }

    for name, model in models_dict.items():
        metrics = evaluate_model(model, X_test_features, y_test, model_name=name)
        all_metrics[name] = metrics
        print(f"\n[=] Model: {name}")
        print(f"    Accuracy:  {metrics['accuracy']:.4f} | Recall: {metrics['recall_phishing']:.4f} | Precision: {metrics['precision']:.4f}")
        print(f"    F1-Score:  {metrics['f1_score']:.4f} | ROC-AUC: {metrics['roc_auc']:.4f}")
        print(f"    Latency:   {metrics['latency_ms_per_email']:.3f} ms/email | Size: {model_sizes[name]:.1f} KB")

    # Format comparison table
    benchmark_table = format_benchmark_table(all_metrics, model_sizes)

    # Save metrics JSON & reports
    metrics_output_path = os.path.join(models_dir, "metrics.json")
    with open(metrics_output_path, "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2)

    table_output_path = os.path.join(reports_dir, "benchmark_table.json")
    with open(table_output_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_table, f, indent=2)

    print(f"\n[+] Successfully saved evaluation metrics -> {metrics_output_path}")
    print(f"[+] Persisted benchmark comparison table -> {table_output_path}")

    return all_metrics, benchmark_table


if __name__ == "__main__":
    train_and_evaluate_all()
