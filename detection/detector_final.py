#!/usr/bin/env python3
"""
Final Hybrid Anomaly Detector - Train/Test Split
Thesis: On Enhancing 5G Security
Train: Synthetic augmented data (captures/)
Test:  Real unseen data (captures/test/)
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score
import warnings
warnings.filterwarnings('ignore')
import os

BASE_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TRAIN_CSV  = os.path.join(BASE_DIR, "datasets", "master_dataset.csv")
TEST_CSV   = os.path.join(BASE_DIR, "datasets", "features_test.csv")

FEATURES = [
    'total_packets', 'auth_requests', 'reg_requests', 'reg_rejects',
    'sec_mode_cmds', 'ng_setup_req', 'suci_unencrypted', 'duration',
    'auth_rate', 'reg_rate', 'reject_rate', 'auth_success_rate', 'rand_repeat', 'auth_failures', 'sctp_abort'
]

def log(msg):
    print(msg)

def simple_rule(row):
    if row['suci_unencrypted'] == 1:
        return 'supi_harvest'
    if row['reg_rejects'] >= 1 and row['sec_mode_cmds'] >= 1:
        return 'bidding_down'
    if row['ng_setup_req'] >= 1 and row['reg_rejects'] == 0 and row['suci_unencrypted'] == 0:
        return 'false_bs'
    if row['rand_repeat'] == 1 or row['sctp_abort'] == 1:
        return 'replay'
    if row['auth_failures'] > 0 or (row['auth_rate'] > 0.03 and row['auth_success_rate'] < 0.5):
        return 'brute_force'
    return 'normal'

def advanced_rule(row):
    scores = {
        'brute_force': 0.0, 'supi_harvest': 0.0,
        'bidding_down': 0.0, 'false_bs': 0.0,
        'replay': 0.0, 'normal': 0.0
    }
    if row['suci_unencrypted'] == 1:
        scores['supi_harvest'] += 1.0
    if row['reg_rejects'] >= 1:
        scores['bidding_down'] += 0.5
    if row['sec_mode_cmds'] >= 1 and row['reg_rejects'] >= 1:
        scores['bidding_down'] += 0.4
    if row['reject_rate'] >= 0.3:
        scores['bidding_down'] += 0.2
    if row['ng_setup_req'] >= 1 and row['reg_rejects'] == 0:
        scores['false_bs'] += 0.6
    if row['ng_setup_req'] >= 1 and row['auth_requests'] >= 1:
        scores['false_bs'] += 0.3
    if row['rand_repeat'] == 1 or row['sctp_abort'] == 1:
        scores['replay'] += 1.0
    if row['auth_failures'] > 0:
        scores['brute_force'] += 1.0
    if row['auth_rate'] > 0.03:
        scores['brute_force'] += 0.3
    if row['auth_success_rate'] < 0.5 and row['auth_requests'] >= 1:
        scores['brute_force'] += 0.3
    if row['reg_rejects'] == 0 and row['auth_requests'] >= 1 and row['suci_unencrypted'] == 0:
        scores['brute_force'] += 0.2
    if row['suci_unencrypted'] == 0 and row['rand_repeat'] == 0:
        scores['normal'] += 0.2
    if row['reg_rejects'] == 0 and row['auth_success_rate'] >= 0.8:
        scores['normal'] += 0.3
    if row['reject_rate'] == 0 and row['ng_setup_req'] == 0:
        scores['normal'] += 0.2
    return max(scores, key=scores.get)

def main():
    log("=" * 60)
    log("FINAL HYBRID ANOMALY DETECTOR")
    log("Thesis: On Enhancing 5G Security")
    log("Train: Synthetic data | Test: Real unseen captures")
    log("=" * 60)

    # Load train and test
    train_df = pd.read_csv(TRAIN_CSV)
    test_df  = pd.read_csv(TEST_CSV)

    log(f"\n[*] Train set: {len(train_df)} samples")
    log(f"[*] Test set:  {len(test_df)} windows (real unseen data)")
    log(f"[*] Train distribution:\n{train_df['label'].value_counts().to_string()}")
    log(f"\n[*] Test distribution:\n{test_df['label'].value_counts().to_string()}")

    X_train = train_df[FEATURES]
    y_train = train_df['label']
    X_test  = test_df[FEATURES]
    y_test  = test_df['label']

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # ─── PART 1: Simple Rule-based ───
    log("\n" + "─" * 40)
    log("PART 1 — Simple Rule-based Detection")
    log("─" * 40)
    simple_preds = X_test.apply(simple_rule, axis=1)
    simple_acc   = (simple_preds == y_test).mean()
    log(f"Accuracy: {simple_acc*100:.1f}%")
    log(classification_report(y_test, simple_preds, zero_division=0))

    # ─── PART 2: Advanced Rule-based ───
    log("─" * 40)
    log("PART 2 — Advanced Weighted Rule-based")
    log("─" * 40)
    advanced_preds = X_test.apply(advanced_rule, axis=1)
    advanced_acc   = (advanced_preds == y_test).mean()
    log(f"Accuracy: {advanced_acc*100:.1f}%")
    log(classification_report(y_test, advanced_preds, zero_division=0))

    # ─── PART 3: Random Forest ───
    log("─" * 40)
    log("PART 3 — Random Forest Classifier")
    log("─" * 40)
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=5,
        random_state=42,
        class_weight='balanced'
    )
    rf.fit(X_train_scaled, y_train)
    rf_preds = rf.predict(X_test_scaled)
    rf_acc   = (rf_preds == y_test).mean()
    log(f"Accuracy: {rf_acc*100:.1f}%")
    log(classification_report(y_test, rf_preds, zero_division=0))

    log("Top 5 Important Features:")
    importances = pd.Series(rf.feature_importances_, index=FEATURES)
    for feat, imp in importances.nlargest(5).items():
        log(f"  {feat:<25} {imp:.4f}")

    cv_scores = cross_val_score(rf, X_train_scaled, y_train, cv=5)
    log(f"\n5-Fold CV (train): {cv_scores.mean()*100:.1f}% ± {cv_scores.std()*100:.1f}%")

    # ─── PART 4: Hybrid ───
    log("\n" + "─" * 40)
    log("PART 4 — Hybrid Pipeline (Rules + RF)")
    log("─" * 40)
    hybrid_preds = []
    for idx, row in X_test.iterrows():
        row_scaled = scaler.transform([row])[0]
        if row['suci_unencrypted'] == 1:
            hybrid_preds.append('supi_harvest')
            continue
        if row['reg_rejects'] >= 1 and row['sec_mode_cmds'] >= 1:
            hybrid_preds.append('bidding_down')
            continue
        if row['auth_failures'] > 0:
            hybrid_preds.append('brute_force')
            continue
        if row['sctp_abort'] == 1:
            hybrid_preds.append('replay')
            continue
        hybrid_preds.append(rf.predict([row_scaled])[0])

    hybrid_acc = sum(a == b for a, b in zip(hybrid_preds, y_test)) / len(y_test)
    log(f"Accuracy: {hybrid_acc*100:.1f}%")
    log(classification_report(y_test, hybrid_preds, zero_division=0))

    # Confusion Matrix
    log("Confusion Matrix:")
    classes = sorted(y_test.unique())
    cm = confusion_matrix(y_test, hybrid_preds, labels=classes)
    log(f"{'':>16} " + " ".join(f"{c:>14}" for c in classes))
    for i, row_cm in enumerate(cm):
        log(f"{classes[i]:>16} " + " ".join(f"{v:>14}" for v in row_cm))

    # ─── SUMMARY ───
    log("\n" + "=" * 60)
    log("FINAL DETECTION PERFORMANCE SUMMARY")
    log("(Tested on REAL UNSEEN data)")
    log("=" * 60)
    log(f"Simple Rule-based:    {simple_acc*100:.1f}%")
    log(f"Advanced Rule-based:  {advanced_acc*100:.1f}%")
    log(f"Random Forest:        {rf_acc*100:.1f}%")
    log(f"Hybrid Pipeline:      {hybrid_acc*100:.1f}%")
    log(f"CV Score (train):     {cv_scores.mean()*100:.1f}% ± {cv_scores.std()*100:.1f}%")
    log("=" * 60)

if __name__ == "__main__":
    main()
