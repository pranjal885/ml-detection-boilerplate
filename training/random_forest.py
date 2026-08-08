"""
===========================================================
CloudShield AI
Random Forest Training
===========================================================

Trains a Random Forest classifier and
saves the trained model.
"""

import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier


# ===========================================================
# PATHS
# ===========================================================

TRAIN_DATA = "../preprocessing/train.csv"

MODEL_DIR = "models"

os.makedirs(MODEL_DIR, exist_ok=True)


# ===========================================================
# TRAIN MODEL
# ===========================================================

def train_random_forest():

    print("\nTraining Random Forest...")

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

    model = RandomForestClassifier(

        n_estimators=100,

        random_state=42,

        n_jobs=-1

    )

    model.fit(X, y)

    # -------------------------------------------------------
    # Save Model
    # -------------------------------------------------------

    model_path = os.path.join(

        MODEL_DIR,

        "random_forest.pkl"

    )

    joblib.dump(

        model,

        model_path

    )

    print("Random Forest trained successfully.")

    print(f"Model Saved : {model_path}")

    return model