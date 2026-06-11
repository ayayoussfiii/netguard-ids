"""

────────
Trains NetGuard's ML stack on the BETH dataset:

  1. Isolation Forest  — trained on benign-only events (training split)
  2. XGBoost           — trained on labelled data (train + val splits)
  3. SHAP explainer    — built from the trained XGBoost model

Saves models to MODEL_DIR (default: ml/models/).
"""

import os
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
import shap
import optuna
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    roc_auc_score, average_precision_score,
    classification_report, confusion_matrix
)
from sklearn.utils.class_weight import compute_sample_weight
from dotenv import load_dotenv
from loguru import logger

from pipeline.features import FEATURE_NAMES

load_dotenv()

BETH_DIR   = Path(os.getenv("BETH_DATA_DIR",  "data/beth/"))
MODEL_DIR  = Path(os.getenv("MODEL_DIR",       "ml/models/"))
CONTAMINATION = float(os.getenv("CONTAMINATION", "0.01"))

MODEL_DIR.mkdir(parents=True, exist_ok=True)


# ── Data loading ──────────────────────────────────────────────────────────────

def load_beth() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    logger.info("Loading BETH dataset...")
    train = pd.read_csv(BETH_DIR / "labelled_training_data.csv").fillna(0)
    val   = pd.read_csv(BETH_DIR / "labelled_validation_data.csv").fillna(0)
    test  = pd.read_csv(BETH_DIR / "labelled_testing_data.csv").fillna(0)
    logger.info(f"  train={len(train):,}  val={len(val):,}  test={len(test):,}")
    return train, val, test


def get_features(df: pd.DataFrame) -> np.ndarray:
    """Extract feature columns that exist in the dataframe (pre-computed or raw)."""
    available = [f for f in FEATURE_NAMES if f in df.columns]
    return df[available].values


def get_labels(df: pd.DataFrame) -> np.ndarray:
    """
    Build 3-class label: 0=benign, 1=SUS, 2=EVIL
    BETH provides binary columns: sus (0/1) and evil (0/1).
    EVIL takes priority over SUS.
    """
    y = np.zeros(len(df), dtype=int)
    y[df["sus"]  == 1] = 1
    y[df["evil"] == 1] = 2
    return y


# ── Isolation Forest ──────────────────────────────────────────────────────────

def train_isolation_forest(train: pd.DataFrame) -> IsolationForest:
    logger.info("Training Isolation Forest on benign-only data...")

    # BETH train split has no attack events — use all rows
    X_benign = get_features(train)

    model = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        max_features=0.8,
        max_samples=512,
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_benign)

    path = MODEL_DIR / "isolation_forest.pkl"
    with open(path, "wb") as f:
        pickle.dump(model, f)
    logger.success(f"  Isolation Forest saved → {path}")
    return model


# ── XGBoost ───────────────────────────────────────────────────────────────────

def _xgb_objective(trial, X_train, y_train, X_val, y_val):
    """Optuna objective — maximizes weighted F1 on validation set."""
    params = {
        "n_estimators":     trial.suggest_int("n_estimators", 300, 1000),
        "max_depth":        trial.suggest_int("max_depth", 4, 10),
        "learning_rate":    trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
        "subsample":        trial.suggest_float("subsample", 0.6, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
        "min_child_weight": trial.suggest_int("min_child_weight", 1, 20),
        "gamma":            trial.suggest_float("gamma", 0.0, 1.0),
        "reg_lambda":       trial.suggest_float("reg_lambda", 0.5, 3.0),
        "objective":        "multi:softprob",
        "num_class":        3,
        "eval_metric":      "mlogloss",
        "tree_method":      "hist",
        "device":           "cpu",
        "random_state":     42,
    }

    n_evil   = (y_train == 2).sum()
    n_benign = (y_train == 0).sum()
    scale    = n_benign / max(n_evil, 1)
    weights  = compute_sample_weight("balanced", y_train)
    weights[y_train == 2] *= scale   # extra weight on EVIL class

    model = xgb.XGBClassifier(**params)
    model.fit(
        X_train, y_train,
        sample_weight=weights,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    from sklearn.metrics import f1_score
    y_pred = model.predict(X_val)
    return f1_score(y_val, y_pred, average="weighted")


def train_xgboost(train: pd.DataFrame, val: pd.DataFrame,
                  n_trials: int = 30) -> xgb.XGBClassifier:
    logger.info("Training XGBoost classifier...")

    X_train, y_train = get_features(train), get_labels(train)
    X_val,   y_val   = get_features(val),   get_labels(val)

    logger.info(f"  Class distribution — train: {dict(zip(*np.unique(y_train, return_counts=True)))}")

    logger.info(f"  Running Optuna search ({n_trials} trials)...")
    study = optuna.create_study(direction="maximize")
    study.optimize(
        lambda trial: _xgb_objective(trial, X_train, y_train, X_val, y_val),
        n_trials=n_trials,
        show_progress_bar=True,
    )

    best_params = study.best_params
    best_params.update({
        "objective":    "multi:softprob",
        "num_class":    3,
        "eval_metric":  ["mlogloss", "merror"],
        "tree_method":  "hist",
        "device":       "cpu",
        "random_state": 42,
    })

    logger.info(f"  Best params: {json.dumps(best_params, indent=2)}")

    n_evil   = (y_train == 2).sum()
    n_benign = (y_train == 0).sum()
    weights  = compute_sample_weight("balanced", y_train)
    weights[y_train == 2] *= n_benign / max(n_evil, 1)

    final_model = xgb.XGBClassifier(**best_params)
    final_model.fit(X_train, y_train, sample_weight=weights, verbose=True)

    path = MODEL_DIR / "xgboost.json"
    final_model.save_model(str(path))
    logger.success(f"  XGBoost saved → {path}")
    return final_model


# ── SHAP explainer ────────────────────────────────────────────────────────────

def build_shap_explainer(model: xgb.XGBClassifier) -> shap.TreeExplainer:
    logger.info("Building SHAP TreeExplainer...")
    explainer = shap.TreeExplainer(
        model,
        feature_perturbation="tree_path_dependent",
    )
    path = MODEL_DIR / "shap_explainer.pkl"
    with open(path, "wb") as f:
        pickle.dump(explainer, f)
    logger.success(f"  SHAP explainer saved → {path}")
    return explainer


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(if_model: IsolationForest, xgb_model: xgb.XGBClassifier,
             test: pd.DataFrame):
    logger.info("Evaluating on BETH test set...")

    X_test = get_features(test)
    y_test = get_labels(test)

    # Isolation Forest
    if_scores = -if_model.score_samples(X_test)   # higher = more anomalous
    y_binary  = (y_test > 0).astype(int)

    auroc = roc_auc_score(y_binary, if_scores)
    auprc = average_precision_score(y_binary, if_scores)
    logger.info(f"  Isolation Forest — AUROC: {auroc:.4f}  AUPRC: {auprc:.4f}")

    # XGBoost
    proba   = xgb_model.predict_proba(X_test)
    y_pred  = proba.argmax(axis=1)

    logger.info("\n" + classification_report(
        y_test, y_pred,
        target_names=["benign", "SUS", "EVIL"],
        digits=4,
    ))

    cm = confusion_matrix(y_test, y_pred, normalize="true")
    logger.info(f"Confusion matrix (normalized):\n{np.round(cm, 3)}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    train, val, test = load_beth()

    if_model  = train_isolation_forest(train)
    xgb_model = train_xgboost(train, val)
    _         = build_shap_explainer(xgb_model)

    evaluate(if_model, xgb_model, test)
