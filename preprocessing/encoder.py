"""
===========================================================
CloudShield AI
Categorical Feature Encoder
===========================================================

Encodes categorical features into numerical values
and saves the trained encoders for future prediction.
"""

import os
import joblib
import pandas as pd

from sklearn.preprocessing import LabelEncoder


# ===========================================================
# MODELS DIRECTORY
# ===========================================================

MODEL_DIR = "models"

os.makedirs(MODEL_DIR, exist_ok=True)


# ===========================================================
# ENCODE DATASET
# ===========================================================

def encode_dataset(df: pd.DataFrame):

    print("Encoding categorical columns...")

    categorical_columns = [

        "Protocol",

        "Attack Type"

    ]

    # Dictionary to store encoders
    encoders = {}

    for column in categorical_columns:

        print(f"Encoding : {column}")

        encoder = LabelEncoder()

        df[column] = encoder.fit_transform(df[column])

        encoders[column] = encoder

        # Save encoder
        filename = column.lower().replace(" ", "_") + "_encoder.pkl"

        joblib.dump(

            encoder,

            os.path.join(MODEL_DIR, filename)

        )

    print("Categorical encoding completed.")

    print("Encoders saved successfully.\n")

    return df