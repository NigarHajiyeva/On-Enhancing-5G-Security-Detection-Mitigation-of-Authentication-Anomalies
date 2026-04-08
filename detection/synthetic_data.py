#!/usr/bin/env python3
"""
Synthetic Dataset Generator
Thesis: On Enhancing 5G Security
Expands 6 real samples to 600 (100 per class) with noise augmentation
"""

import csv
import random
import os

INPUT  = "/home/eit42s/thesis-5g/datasets/features.csv"
OUTPUT = "/home/eit42s/thesis-5g/datasets/master_dataset.csv"
SAMPLES_PER_CLASS = 100
NOISE = 0.15

def read_features():
    with open(INPUT, 'r') as f:
        return list(csv.DictReader(f))

def augment(sample, n):
    rows = []
    for _ in range(n):
        new = {}
        for k, v in sample.items():
            if k == 'label':
                new[k] = v
                continue
            val = float(v)
            if val == 0:
                # small chance of non-zero noise
                new[k] = round(random.uniform(0, 0.3), 4) if random.random() < 0.05 else 0
            elif val == 1 and k in ('suci_unencrypted', 'rand_repeat'):
                # binary features stay binary
                new[k] = 1
            else:
                noise = random.uniform(1 - NOISE, 1 + NOISE)
                new[k] = round(max(0, val * noise), 4)
                if k in ('auth_requests', 'reg_requests', 'reg_rejects',
                         'sec_mode_cmds', 'ng_setup_req', 'total_packets'):
                    new[k] = max(0, int(new[k]))
        rows.append(new)
    return rows

def main():
    print("=" * 60)
    print("SYNTHETIC DATASET GENERATOR")
    print(f"Target: {SAMPLES_PER_CLASS} samples per class")
    print(f"Noise:  ±{int(NOISE*100)}%")
    print("=" * 60)

    os.makedirs("/home/eit42s/thesis-5g/datasets", exist_ok=True)
    samples = read_features()

    all_rows = []
    for s in samples:
        augmented = augment(s, SAMPLES_PER_CLASS)
        all_rows.extend(augmented)
        print(f"  [+] {s['label']:<16} → {SAMPLES_PER_CLASS} samples")

    random.shuffle(all_rows)

    fieldnames = list(all_rows[0].keys())
    with open(OUTPUT, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\n  Total: {len(all_rows)} samples → {OUTPUT}")

    # Class distribution
    from collections import Counter
    counts = Counter(r['label'] for r in all_rows)
    print("\n  Class distribution:")
    for label, count in sorted(counts.items()):
        print(f"    {label:<16} {count}")

    print("=" * 60)
    print("DONE!")

if __name__ == "__main__":
    main()
