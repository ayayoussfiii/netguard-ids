"""
detector.py
───────────
Loads trained models and exposes a simple inference API
used by pipeline/consumer.py.
"""

import os
import pickle
from pathlib import Path

import numpy as np
import xgboost as xgb
import shap
from dotenv import load_dotenv
from loguru import logger

from pipeline.features import FEATURE_NAMES

load_dotenv()

MODEL_DIR = Path(os.getenv("MODEL_DIR", "ml/models/"))


class Detector:
    def __init__(self):
        self._if    = self._load_pickle("isolation_forest.pkl")
        self._xgb   = self._load_xgb("xgboost.json")
        self._shap  = self._load_pickle("shap_explainer.pkl")
        logger.success("Detector ready (IF + XGBoost + SHAP)")

    def _load_pickle(self, name: str):
        path = MODEL_DIR / name
        with open(path, "rb") as f:
            return pickle.load(f)

    def _load_xgb(self, name: str) -> xgb.XGBClassifier:
        model = xgb.XGBClassifier()
        model.load_model(str(MODEL_DIR / name))
        return model

    def anomaly_score(self, X: list) -> np.ndarray:
        """
        Returns IF anomaly score per event.
        Score < threshold  →  anomalous (lower is more anomalous).
        """
        arr = np.array(X, dtype=float)
        return self._if.score_samples(arr)   # shape (n,)

    def classify(self, X: list) -> np.ndarray:
        """
        Returns class probabilities [p_benign, p_sus, p_evil] per event.
        """
        arr = np.array(X, dtype=float)
        return self._xgb.predict_proba(arr)  # shape (n, 3)

    def explain(self, X: list) -> list[dict]:
        """
        Returns per-event SHAP values as a list of dicts {feature: contribution}.
        Uses the SHAP values for the predicted class only.
        """
        arr      = np.array(X, dtype=float)
        sv       = self._shap(arr)          # shape (n, n_features, n_classes)
        results  = []

        for i in range(len(X)):
            proba     = self.classify([X[i]])[0]
            pred_class = int(proba.argmax())
            contribs   = sv.values[i, :, pred_class]

            top = sorted(
                zip(FEATURE_NAMES, contribs.tolist()),
                key=lambda x: abs(x[1]),
                reverse=True,
            )[:10]

            results.append({f: round(v, 5) for f, v in top})

        return results
