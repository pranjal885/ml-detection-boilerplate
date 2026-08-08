"""
===========================================================
CloudShield AI
Model Evaluation
===========================================================

Evaluates trained ML models using the
validation dataset.
"""

import os
import joblib
import pandas as pd

from sklearn.metrics import (

    accuracy_score,

    precision_score,

    recall_score,

    f1_score

)

# ===========================================================
# PATHS
# ===========================================================

VALIDATION_DATA = "../preprocessing/validation.csv"

MODEL_DIR = "models"

RESULT_DIR = "results"

os.makedirs(RESULT_DIR, exist_ok=True)


# ===========================================================
# EVALUATE MODEL
# ===========================================================

def evaluate_model(model_name):

    print(f"\nEvaluating {model_name}...")

    df = pd.read_csv(VALIDATION_DATA)
    df.columns = df.columns.str.strip()

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

    model = joblib.load(

        os.path.join(

            MODEL_DIR,

            model_name

        )

    )

    predictions = model.predict(X)

    accuracy = accuracy_score(

        y,

        predictions

    )

    precision = precision_score(

        y,

        predictions

    )

    recall = recall_score(

        y,

        predictions

    )

    f1 = f1_score(

        y,

        predictions

    )

    return {

        "Model": model_name.replace(".pkl", ""),

        "Accuracy": round(accuracy, 4),

        "Precision": round(precision, 4),

        "Recall": round(recall, 4),

        "F1 Score": round(f1, 4)

    }


# ===========================================================
# EVALUATE ALL
# ===========================================================

def evaluate_all_models():

    print("\nEvaluating All Models...")

    model_files = [

        "random_forest.pkl",

        "decision_tree.pkl",

        "logistic_regression.pkl",

        "xgboost.pkl"

    ]

    results = []

    for model in model_files:

        results.append(

            evaluate_model(model)

        )

    results_df = pd.DataFrame(results)

    results_df.to_csv(

        os.path.join(

            RESULT_DIR,

            "model_comparison.csv"

        ),

        index=False

    )

    # -------------------------------------------------------
    # Select Best Model
    # -------------------------------------------------------

    best = results_df.sort_values(

        by="F1 Score",

        ascending=False

    ).iloc[0]

    best_model = best["Model"] + ".pkl"

    joblib.dump(

        joblib.load(

            os.path.join(

                MODEL_DIR,

                best_model

            )

        ),

        os.path.join(

            MODEL_DIR,

            "best_model.pkl"

        )

    )

    print()

    print("=" * 60)

    print(results_df)

    print("=" * 60)

    print()

    print(f"Best Model : {best['Model']}")

    print(f"F1 Score   : {best['F1 Score']}")

    print()

    return results_df