"""
===========================================================
CloudShield AI
Decision Tree Training
===========================================================

Trains a Decision Tree classifier and
saves the trained model.
"""

import os
import joblib
import pandas as pd

from sklearn.tree import DecisionTreeClassifier


# ===========================================================
# PATHS
# ===========================================================

TRAIN_DATA = "../preprocessing/train.csv"

MODEL_DIR = "models"

os.makedirs(MODEL_DIR, exist_ok=True)


# ===========================================================
# TRAIN MODEL
# ===========================================================

def train_decision_tree():

    print("\nTraining Decision Tree...")

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

    model = DecisionTreeClassifier(

        random_state=42,

        max_depth=15

    )

    model.fit(X, y)

    # -------------------------------------------------------
    # Save Model
    # -------------------------------------------------------

    model_path = os.path.join(

        MODEL_DIR,

        "decision_tree.pkl"

    )

    joblib.dump(

        model,

        model_path

    )

    print("Decision Tree trained successfully.")

    print(f"Model Saved : {model_path}")

    return model