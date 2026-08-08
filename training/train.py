"""
===========================================================
CloudShield AI
Machine Learning Training Pipeline
===========================================================

Main controller for training, evaluating,
and selecting the best ML model.
"""

from random_forest import train_random_forest
from decision_tree import train_decision_tree
from logistic_regression import train_logistic_regression
from xgboost_model import train_xgboost

from evaluate import evaluate_all_models


# ===========================================================
# MAIN
# ===========================================================

def main():

    print("=" * 60)
    print("CloudShield AI")
    print("Machine Learning Training Pipeline")
    print("=" * 60)

    # -------------------------------------------------------
    # Train Models
    # -------------------------------------------------------

    train_random_forest()

    train_decision_tree()

    train_logistic_regression()

    train_xgboost()

    # -------------------------------------------------------
    # Evaluate Models
    # -------------------------------------------------------

    print("\n")
    print("=" * 60)
    print("Evaluating Models")
    print("=" * 60)

    evaluate_all_models()

    print("\n")
    print("=" * 60)
    print("Training Completed Successfully")
    print("=" * 60)
    print("Best model saved as:")
    print("models/best_model.pkl")
    print("=" * 60)


# ===========================================================
# ENTRY POINT
# ===========================================================

if __name__ == "__main__":

    main()