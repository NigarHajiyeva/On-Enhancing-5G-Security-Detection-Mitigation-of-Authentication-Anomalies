#!/usr/bin/env python3
"""
Synthetic Dataset Generator with SMOTE
Thesis: On Enhancing 5G Security
Uses SMOTE for oversampling after collecting 3+ real samples per class
Academic justification: SMOTE interpolates between real samples,
producing more realistic synthetic data than Gaussian noise alone.
"""

import csv
import random
import os
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from imblearn.over_sampling import SMOTE

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INPUT    = os.path.join(BASE_DIR, "datasets", "features_sliding.csv")
OUTPUT   = os.path.join(BASE_DIR, "datasets", "master_dataset.csv")

SAMPLES_PER_CLASS = 100
NOISE             = 0.15

FEATURES = [
    'total_packets', 'auth_requests', 'reg_requests', 'reg_rejects', 'auth_failures', 'sctp_abort',
    'sec_mode_cmds', 'ng_setup_req', 'suci_unencrypted', 'duration',
    'auth_rate', 'reg_rate', 'reject_rate', 'auth_success_rate',
    'rand_repeat', 'is_active'
]

BINARY_FEATURES = {'suci_unencrypted', 'rand_repeat', 'is_active'}
INT_FEATURES    = {'auth_requests', 'reg_requests', 'reg_rejects', 'auth_failures', 'sctp_abort',
                   'sec_mode_cmds', 'ng_setup_req', 'total_packets'}

def augment_noise(sample_dict, n):
    """Gaussian noise augmentation for classes with < 2 samples"""
    rows = []
    for _ in range(n):
        new = {'label': sample_dict['label']}
        for k in FEATURES:
            val = float(sample_dict.get(k, 0))
            if k in BINARY_FEATURES:
                new[k] = int(val)
            elif val == 0:
                new[k] = 0
            else:
                noise = random.uniform(1 - NOISE, 1 + NOISE)
                new_val = max(0, val * noise)
                if k in INT_FEATURES:
                    new[k] = max(0, int(round(new_val)))
                else:
                    new[k] = round(new_val, 4)
        rows.append(new)
    return rows

def main():
    print("=" * 60)
    print("SYNTHETIC DATASET GENERATOR — SMOTE")
    print(f"Target: {SAMPLES_PER_CLASS} samples per class")
    print("=" * 60)

    os.makedirs(os.path.join(BASE_DIR, "datasets"), exist_ok=True)

    # Read real windows
    df = pd.read_csv(INPUT)

    print(f"\n[*] Real windows per class:")
    for label, grp in df.groupby('label'):
        print(f"    {label:<16} {len(grp)} windows")

    # Prepare features and labels
    X = df[FEATURES].values.astype(float)
    y = df['label'].values

    label_counts = Counter(y)
    all_rows = []

    # Separate classes: SMOTE needs >= 2 samples, ideally k_neighbors+1
    smote_labels  = [l for l, c in label_counts.items() if c >= 2]
    noise_labels  = [l for l, c in label_counts.items() if c < 2]

    print(f"\n[*] SMOTE classes: {smote_labels}")
    print(f"[*] Noise classes: {noise_labels}")

    # ── SMOTE for classes with >= 2 samples ──────────────────────
    if smote_labels:
        # Filter only SMOTE-eligible rows
        mask = np.isin(y, smote_labels)
        X_smote = X[mask]
        y_smote = y[mask]

        # k_neighbors = min(k, min_class_size - 1)
        min_class = min(Counter(y_smote).values())
        k = min(5, min_class - 1)
        k = max(1, k)

        print(f"\n[*] Applying SMOTE (k_neighbors={k})...")

        smote = SMOTE(
            sampling_strategy={l: SAMPLES_PER_CLASS for l in smote_labels},
            k_neighbors=k,
            random_state=42
        )

        X_res, y_res = smote.fit_resample(X_smote, y_smote)

        print(f"[*] SMOTE output: {len(X_res)} samples")

        # Convert back to dicts
        for i in range(len(X_res)):
            row = {'label': y_res[i]}
            for j, feat in enumerate(FEATURES):
                val = X_res[i][j]
                if feat in BINARY_FEATURES:
                    row[feat] = int(round(val))
                elif feat in INT_FEATURES:
                    row[feat] = max(0, int(round(val)))
                else:
                    row[feat] = round(float(val), 4)
            all_rows.append(row)

    # ── Noise augmentation for classes with < 2 samples ──────────
    for label in noise_labels:
        print(f"\n[*] Noise augmentation for: {label}")
        label_rows = df[df['label'] == label].to_dict('records')
        augmented = augment_noise(label_rows[0], SAMPLES_PER_CLASS)
        all_rows.extend(augmented)

    # ── Trim each class to exactly SAMPLES_PER_CLASS ─────────────
    final_rows = []
    grouped = defaultdict(list)
    for row in all_rows:
        grouped[row['label']].append(row)

    print(f"\n[*] Final class distribution:")
    for label in sorted(grouped.keys()):
        rows = grouped[label][:SAMPLES_PER_CLASS]
        final_rows.extend(rows)
        print(f"    {label:<16} {len(rows)} samples")

    random.shuffle(final_rows)

    # Write CSV
    output_fields = ['label'] + FEATURES
    with open(OUTPUT, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=output_fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(final_rows)

    print(f"\n[*] Total: {len(final_rows)} samples")
    print(f"[*] Saved: {OUTPUT}")
    print("=" * 60)
    print("DONE!")

if __name__ == "__main__":
    main()
