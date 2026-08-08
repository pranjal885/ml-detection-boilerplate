"""
===========================================================
CloudShield AI
Logistic Regression Training
===========================================================

Trains a Logistic Regression classifier and
saves the trained model.
"""

import os
import joblib
import pandas as pd

from sklearn.linear_model import LogisticRegression


# ===========================================================
# PATHS
# ===========================================================

TRAIN_DATA = "../preprocessing/train.csv"

MODEL_DIR = "models"

os.makedirs(MODEL_DIR, exist_ok=True)


# ===========================================================
# TRAIN MODEL
# ===========================================================

def train_logistic_regression():

    print("\nTraining Logistic Regression...")

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

    model = LogisticRegression(

        max_iter=1000,

        random_state=42

    )

    model.fit(X, y)

    # -------------------------------------------------------
    # Save Model
    # -------------------------------------------------------

    model_path = os.path.join(

        MODEL_DIR,

        "logistic_regression.pkl"

    )

    joblib.dump(

        model,

        model_path

    )

    print("Logistic Regression trained successfully.")

    print(f"Model Saved : {model_path}")

    return model