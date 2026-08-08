"""
===========================================================
CloudShield AI
Feature Scaling
===========================================================

Normalizes numerical features using MinMaxScaler
and saves the trained scaler for future predictions.
"""

import os
import joblib
import pandas as pd

from sklearn.preprocessing import MinMaxScaler


# ===========================================================
# MODELS DIRECTORY
# ===========================================================

MODEL_DIR = "models"

os.makedirs(MODEL_DIR, exist_ok=True)


# ===========================================================
# NORMALIZE DATASET
# ===========================================================

def normalize_dataset(df: pd.DataFrame):

    print("Scaling numerical features...")

    scaler = MinMaxScaler()

    numerical_columns = [

        "Port",

        "Packets",

        "Bytes",

        "Request Count",

        "Login Attempts",

        "CPU Usage",

        "Memory Usage",

        "Response Time"

    ]

    df[numerical_columns] = scaler.fit_transform(

        df[numerical_columns]

    )

    # -------------------------------------------------------
    # Save Scaler
    # -------------------------------------------------------

    joblib.dump(

        scaler,

        os.path.join(

            MODEL_DIR,

            "scaler.pkl"

        )

    )

    print("Feature scaling completed.")

    print("Scaler saved successfully.\n")

    return df