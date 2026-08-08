"""
===========================================================
CloudShield AI
Data Preprocessing Pipeline
===========================================================

Main controller for preprocessing the generated dataset.

Steps
------
1. Load Dataset
2. Remove Duplicates
3. Handle Missing Values
4. Encode Categorical Features
5. Normalize Numerical Features
6. Split Dataset
7. Save Processed Files
"""

import pandas as pd

import encoder
import scaler
import splitter


# ===========================================================
# FILE PATHS
# ===========================================================

INPUT_DATASET = "../dataset/cloudshield_dataset.csv"

PROCESSED_DATASET = "processed_dataset.csv"


# ===========================================================
# LOAD DATASET
# ===========================================================

print("=" * 60)
print("CloudShield AI - Data Preprocessing")
print("=" * 60)

print("\nLoading dataset...")

df = pd.read_csv(INPUT_DATASET)
df.columns = df.columns.str.strip()

print(f"Dataset Loaded : {len(df)} rows")


# ===========================================================
# REMOVE DUPLICATES
# ===========================================================

duplicates = df.duplicated().sum()

print(f"\nDuplicate Records Found : {duplicates}")

df.drop_duplicates(inplace=True)

print(f"Dataset Size : {len(df)} rows")


# ===========================================================
# HANDLE MISSING VALUES
# ===========================================================

missing = df.isnull().sum().sum()

print(f"\nMissing Values : {missing}")

df.dropna(inplace=True)

print(f"Dataset Size : {len(df)} rows")


# ===========================================================
# ENCODE CATEGORICAL FEATURES
# ===========================================================

print("\nEncoding categorical features...")

df = encoder.encode_dataset(df)


# ===========================================================
# NORMALIZE NUMERICAL FEATURES
# ===========================================================

print("Normalizing numerical features...")

df = scaler.normalize_dataset(df)


# ===========================================================
# SAVE PROCESSED DATASET
# ===========================================================

df.to_csv(

    PROCESSED_DATASET,

    index=False

)

print(f"\nProcessed Dataset Saved : {PROCESSED_DATASET}")


# ===========================================================
# SPLIT DATASET
# ===========================================================

print("\nSplitting dataset...")

splitter.split_dataset(df)


print("\nPreprocessing Completed Successfully.")

print("=" * 60)