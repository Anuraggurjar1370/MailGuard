"""
MailGuard Launcher.
Initializes data pipelines, trains models if absent, and serves the platform on port 8000.
"""

import os
import sys

# Ensure working directory is the project directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import uvicorn
from src.data.dataset_builder import ensure_dataset_ready
from src.models.train import train_and_evaluate_all

def main():
    print("=" * 70)
    print("  MailGuard : Explainable Multi-Layer Phishing Detection Platform")
    print("  Phase 1 MVP Release | Port 8000")
    print("=" * 70)

    # 1. Ensure bundled sample dataset is present
    data_path = "data/raw/bundled_samples.csv"
    if not os.path.exists(data_path):
        print("[*] Initializing bundled sample dataset...")
        ensure_dataset_ready()

    # 2. Check if models are trained
    model_path = "models/ensemble_model.joblib"
    if not os.path.exists(model_path):
        print("[*] Training baseline models, calibrated SVM, and soft-voting ensemble...")
        train_and_evaluate_all()

    print("\n[+] MailGuard backend & scanner UI launching on http://127.0.0.1:8000")
    print("[+] API Documentation available at http://127.0.0.1:8000/docs\n")
    uvicorn.run("src.api.app:app", host="127.0.0.1", port=8000, log_level="info")

if __name__ == "__main__":
    main()
