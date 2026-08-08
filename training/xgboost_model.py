"""
===========================================================
CloudShield AI
XGBoost Training
===========================================================

Trains an XGBoost classifier and
saves the trained model.
"""

import os
import joblib
import pandas as pd

from xgboost import XGBClassifier


# ===========================================================
# PATHS
# ===========================================================

TRAIN_DATA = "../preprocessing/train.csv"

MODEL_DIR = "models"

os.makedirs(MODEL_DIR, exist_ok=True)


# ===========================================================
# TRAIN MODEL
# ===========================================================

def train_xgboost():

    print("\nTraining XGBoost...")

    df = pd.read_csv(TRAIN_DATA)
    df.columns = df.columns.str.strip()

    # -------------------------------------------------------
    # Features & Label
    # -------------------------------------------------------

    X = df.drop(
    columns=[
        "Label",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Attack Type"
    ]
)

    y = df["Label"]

    # -------------------------------------------------------
    # Train Model
    # -------------------------------------------------------

    model = XGBClassifier(

        n_estimators=100,

        max_depth=6,

        learning_rate=0.1,

        random_state=42,

        eval_metric="logloss",

        use_label_encoder=False

    )

    model.fit(X, y)

    # -------------------------------------------------------
    # Save Model
    # -------------------------------------------------------

    model_path = os.path.join(

        MODEL_DIR,

        "xgboost.pkl"

    )

    joblib.dump(

        model,

        model_path

    )

    print("XGBoost trained successfully.")

    print(f"Model Saved : {model_path}")

    return model