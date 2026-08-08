"""
===========================================================
CloudShield AI
Dataset Splitter
===========================================================

Splits the processed dataset into

70% Training
15% Validation
15% Testing
"""

import pandas as pd

from sklearn.model_selection import train_test_split


# ===========================================================
# SPLIT DATASET
# ===========================================================

def split_dataset(df: pd.DataFrame):

    print("Creating Train / Validation / Test datasets...")

    # -------------------------------------------------------
    # First Split
    # 70% Train
    # 30% Temp
    # -------------------------------------------------------

    train_df, temp_df = train_test_split(

        df,

        test_size=0.30,

        random_state=42,

        stratify=df["Label"]

    )

    # -------------------------------------------------------
    # Second Split
    # 15% Validation
    # 15% Test
    # -------------------------------------------------------

    validation_df, test_df = train_test_split(

        temp_df,

        test_size=0.50,

        random_state=42,

        stratify=temp_df["Label"]

    )

    train_df.columns = train_df.columns.str.strip()
    validation_df.columns = validation_df.columns.str.strip()
    test_df.columns = test_df.columns.str.strip()

    # -------------------------------------------------------
    # Save Files
    # -------------------------------------------------------

    train_df.to_csv(

        "train.csv",

        index=False

    )

    validation_df.to_csv(

        "validation.csv",

        index=False

    )

    test_df.to_csv(

        "test.csv",

        index=False

    )

    # -------------------------------------------------------
    # Summary
    # -------------------------------------------------------

    print()

    print("=" * 60)

    print("Dataset Split Completed")

    print("=" * 60)

    print(f"Training Records   : {len(train_df)}")

    print(f"Validation Records : {len(validation_df)}")

    print(f"Testing Records    : {len(test_df)}")

    print("=" * 60)

    return train_df, validation_df, test_df