from __future__ import annotations

import json
import os
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from .reader import FEATURE_NAMES, load_feature_matrix

MODEL_FILENAME = "rf_attack_detector.joblib"
METRICS_FILENAME = "rf_metrics.json"


def _artifact_dir() -> Path:
    configured = os.environ.get("MODEL_ARTIFACT_DIR")
    if configured:
        return Path(configured)
    docker_path = Path("/app/data")
    return docker_path if docker_path.exists() else Path("data")


def train_random_forest(conn, validation_fraction: float = 0.25, random_state: int = 42) -> dict:
    X, y, _ = load_feature_matrix(conn, labeled_only=True, dataset_split="train")
    if len(y) == 0:
        raise ValueError("No labeled train windows found (dataset_split='train').")

    unique_classes = np.unique(y)
    if len(unique_classes) < 2:
        raise ValueError("Training requires both benign (0) and attack (1) labels.")

    stratify = y if len(y) >= 4 else None
    X_train, X_val, y_train, y_val = train_test_split(
        X,
        y,
        test_size=validation_fraction,
        random_state=random_state,
        stratify=stratify,
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        class_weight="balanced",
        random_state=random_state,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_val)
    y_prob = clf.predict_proba(X_val)[:, 1]

    metrics: dict[str, object] = {
        "timestamp": time.time(),
        "feature_names": FEATURE_NAMES,
        "n_train_rows": int(len(y_train)),
        "n_validation_rows": int(len(y_val)),
        "validation": {
            "accuracy": float(accuracy_score(y_val, y_pred)),
            "precision": float(precision_score(y_val, y_pred, zero_division=0)),
            "recall": float(recall_score(y_val, y_pred, zero_division=0)),
            "f1": float(f1_score(y_val, y_pred, zero_division=0)),
            "confusion_matrix": confusion_matrix(y_val, y_pred).tolist(),
        },
        "feature_importances": {name: float(value) for name, value in zip(FEATURE_NAMES, clf.feature_importances_)},
    }
    if len(np.unique(y_val)) == 2:
        metrics["validation"]["roc_auc"] = float(roc_auc_score(y_val, y_prob))

    artifact_dir = _artifact_dir()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    model_path = artifact_dir / MODEL_FILENAME
    metrics_path = artifact_dir / METRICS_FILENAME

    joblib.dump(clf, model_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return {
        "model_path": str(model_path),
        "metrics_path": str(metrics_path),
        "metrics": metrics,
    }
