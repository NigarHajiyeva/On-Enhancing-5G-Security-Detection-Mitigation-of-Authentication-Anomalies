#!/usr/bin/env python3
"""
Hybrid Anomaly Detector
Thesis: On Enhancing 5G Security
Method: Rule-based + Isolation Forest
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

DATASET = "/home/eit42s/thesis-5g/datasets/master_dataset.csv"
FEATURES = [
    'total_packets', 'auth_requests', 'reg_requests', 'reg_rejects',
    'sec_mode_cmds', 'ng_setup_req', 'suci_unencrypted', 'duration',
    'auth_rate', 'reg_rate', 'reject_rate', 'auth_success_rate', 'rand_repeat'
]

def log(msg):
    print(msg)

# ─── Rule-based detector ───────────────────────────────────
def rule_based(row):
    # Brute-force: high reject rate
    if row['reject_rate'] >= 0.8 and row['auth_requests'] >= 5:
        return 'brute_force'
    # SUPI Harvesting: NULL scheme
    if row['suci_unencrypted'] == 1:
        return 'supi_harvest'
    # Bidding-down: rejects but no auth requests
    if row['reg_rejects'] >= 1 and row['auth_requests'] == 0:
        return 'bidding_down'
    # False BS: NGSetup request present
    if row['ng_setup_req'] >= 1 and row['reg_requests'] >= 1:
        return 'false_bs'
    # Replay: rand_repeat
    if row['rand_repeat'] == 1:
        return 'replay'
    return 'normal'

def main():
    log("=" * 60)
    log("HYBRID ANOMALY DETECTOR")
    log("Method: Rule-based + Isolation Forest")
    log("=" * 60)

    # Load dataset
    df = pd.read_csv(DATASET)
    log(f"\n[*] Dataset: {len(df)} samples, {len(FEATURES)} features")
    log(f"[*] Classes: {sorted(df['label'].unique())}")

    X = df[FEATURES]
    y = df['label']

    # ─── PART 1: Rule-based ───
    log("\n" + "─" * 40)
    log("PART 1 — Rule-based Detection")
    log("─" * 40)

    df['rule_pred'] = X.apply(rule_based, axis=1)
    rule_acc = (df['rule_pred'] == y).mean()
    log(f"Accuracy: {rule_acc*100:.1f}%")
    log("\nClassification Report:")
    log(classification_report(y, df['rule_pred']))

    # ─── PART 2: Isolation Forest ───
    log("─" * 40)
    log("PART 2 — Isolation Forest")
    log("─" * 40)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # Train one model per class (One-Class approach)
    # Then combine: IF flags anomaly, rule-based classifies
    iso = IsolationForest(
        n_estimators=100,
        contamination=0.17,  # ~5/6 classes are attacks
        random_state=42
    )

    # Train on normal only
    X_normal = X[y == 'normal']
    iso.fit(X_normal)

    # Predict: -1 = anomaly, 1 = normal
    iso_pred = iso.predict(X_test)
    iso_labels = ['normal' if p == 1 else 'attack' for p in iso_pred]
    y_binary = ['normal' if label == 'normal' else 'attack' for label in y_test]

    iso_acc = sum(a == b for a, b in zip(iso_labels, y_binary)) / len(y_binary)
    log(f"Anomaly detection accuracy: {iso_acc*100:.1f}%")

    tp = sum(1 for a, b in zip(iso_labels, y_binary) if a == 'attack' and b == 'attack')
    fp = sum(1 for a, b in zip(iso_labels, y_binary) if a == 'attack' and b == 'normal')
    tn = sum(1 for a, b in zip(iso_labels, y_binary) if a == 'normal' and b == 'normal')
    fn = sum(1 for a, b in zip(iso_labels, y_binary) if a == 'normal' and b == 'attack')

    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 0.0001)

    log(f"Precision: {precision*100:.1f}%")
    log(f"Recall:    {recall*100:.1f}%")
    log(f"F1-Score:  {f1*100:.1f}%")
    log(f"TP={tp} FP={fp} TN={tn} FN={fn}")

    # ─── PART 3: Hybrid ───
    log("\n" + "─" * 40)
    log("PART 3 — Hybrid (Rule-based + IF)")
    log("─" * 40)

    hybrid_preds = []
    for i, (idx, row) in enumerate(X_test.iterrows()):
        iso_result = iso.predict([row])[0]
        if iso_result == 1:
            hybrid_preds.append('normal')
        else:
            rule_result = rule_based(row)
            hybrid_preds.append(rule_result)

    hybrid_acc = sum(a == b for a, b in zip(hybrid_preds, y_test)) / len(y_test)
    log(f"Hybrid accuracy: {hybrid_acc*100:.1f}%")
    log("\nClassification Report:")
    log(classification_report(y_test, hybrid_preds))

    log("=" * 60)
    log("SUMMARY")
    log(f"Rule-based accuracy:  {rule_acc*100:.1f}%")
    log(f"Isolation Forest:     {iso_acc*100:.1f}%  (binary: normal vs attack)")
    log(f"Hybrid accuracy:      {hybrid_acc*100:.1f}%")
    log("=" * 60)

if __name__ == "__main__":
    main()
