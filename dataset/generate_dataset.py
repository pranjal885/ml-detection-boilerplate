"""
===========================================================
CloudShield AI
Synthetic Dataset Generator
===========================================================

Generates a synthetic cybersecurity dataset for
Cloud Network Anomaly Detection.

Output:
    cloudshield_dataset.csv
"""

import pandas as pd

import config
import generators
import utils


def main():

    dataset = []

    print("=" * 60)
    print("CloudShield Dataset Generator")
    print("=" * 60)

    # =====================================================
    # NORMAL
    # =====================================================

    print("Generating Normal Traffic...")

    for _ in range(config.NORMAL_ROWS):

        dataset.append(
            generators.generate_normal()
        )

    # =====================================================
    # BRUTE FORCE
    # =====================================================

    print("Generating Brute Force Traffic...")

    for _ in range(config.BRUTE_FORCE_ROWS):

        dataset.append(
            generators.generate_brute_force()
        )

    # =====================================================
    # SQL INJECTION
    # =====================================================

    print("Generating SQL Injection Traffic...")

    for _ in range(config.SQL_INJECTION_ROWS):

        dataset.append(
            generators.generate_sql_injection()
        )

    # =====================================================
    # DDOS
    # =====================================================

    print("Generating DDoS Traffic...")

    for _ in range(config.DDOS_ROWS):

        dataset.append(
            generators.generate_ddos()
        )

    # =====================================================
    # PORT SCAN
    # =====================================================

    print("Generating Port Scan Traffic...")

    for _ in range(config.PORT_SCAN_ROWS):

        dataset.append(
            generators.generate_port_scan()
        )

    # =====================================================
    # CREDENTIAL STUFFING
    # =====================================================

    print("Generating Credential Stuffing Traffic...")

    for _ in range(config.CREDENTIAL_STUFFING_ROWS):

        dataset.append(
            generators.generate_credential_stuffing()
        )

    # =====================================================
    # SHUFFLE DATASET
    # =====================================================

    print("Shuffling Dataset...")

    dataset = utils.shuffle_dataset(dataset)

    # =====================================================
    # DATAFRAME
    # =====================================================

    df = pd.DataFrame(dataset)

    # =====================================================
    # SAVE CSV
    # =====================================================

    df.to_csv(

        config.OUTPUT_FILE,

        index=False

    )

    # =====================================================
    # SUMMARY
    # =====================================================

    print()
    print("=" * 60)
    print("Dataset Generated Successfully")
    print("=" * 60)

    print(f"Total Records : {len(df)}")

    print(f"Output File   : {config.OUTPUT_FILE}")

    print()

    print("Attack Distribution")

    print(df["Attack Type"].value_counts())

    print()

    print("Label Distribution")

    print(df["Label"].value_counts())

    print("=" * 60)


if __name__ == "__main__":

    main()