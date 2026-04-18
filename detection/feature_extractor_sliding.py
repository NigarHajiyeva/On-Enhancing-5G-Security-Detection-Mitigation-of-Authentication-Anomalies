#!/usr/bin/env python3
"""
Sliding Window Feature Extractor
Thesis: On Enhancing 5G Security
Extracts features from pcap files using sliding windows
Academic justification: Simulates real-time detection scenarios
Multiple captures per class for SMOTE compatibility
"""

import subprocess
import os
import csv

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASETS     = os.path.join(BASE_DIR, "datasets")
FEATURES_CSV = os.path.join(DATASETS, "features_sliding.csv")

# Multiple captures per class — for SMOTE (minimum 3 real samples needed)
CAPTURES = {
    "normal": [
        os.path.join(BASE_DIR, "captures", "normal_traffic.pcap"),
        os.path.join(BASE_DIR, "captures", "normal_6.pcap"),
        os.path.join(BASE_DIR, "captures", "normal_7.pcap"),
        os.path.join(BASE_DIR, "captures", "normal_8.pcap"),
        os.path.join(BASE_DIR, "captures", "normal_9.pcap"),
        os.path.join(BASE_DIR, "captures", "normal_10.pcap"),
    ],
    "brute_force": [
        os.path.join(BASE_DIR, "captures", "brute_force.pcap"),
    ],
    "supi_harvest": [
        os.path.join(BASE_DIR, "captures", "supi_harvest_1.pcap"),
        os.path.join(BASE_DIR, "captures", "supi_harvest_2.pcap"),
        os.path.join(BASE_DIR, "captures", "supi_harvest_3.pcap"),
    ],
    "bidding_down": [
        os.path.join(BASE_DIR, "captures", "bidding_down_1.pcap"),
        os.path.join(BASE_DIR, "captures", "bidding_down_2.pcap"),
        os.path.join(BASE_DIR, "captures", "bidding_down_3.pcap"),
    ],
    "replay": [
        os.path.join(BASE_DIR, "captures", "replay_1.pcap"),
        os.path.join(BASE_DIR, "captures", "replay_2.pcap"),
        os.path.join(BASE_DIR, "captures", "replay_3.pcap"),
        
    ],
    "false_bs": [
        os.path.join(BASE_DIR, "captures", "false_bs.pcap"),
    ],
}

# Sliding window parameters
WINDOW_SIZE = 30  # seconds
STEP_SIZE   = 10  # seconds

def get_duration(pcap):
    r = subprocess.run(
        f"tshark -r {pcap} -T fields -e frame.time_relative 2>/dev/null | tail -1",
        shell=True, capture_output=True, text=True
    )
    try:
        return float(r.stdout.strip())
    except:
        return 0.0

def tshark_window(pcap, t_start, t_end, display_filter=""):
    time_filter = f"frame.time_relative >= {t_start} && frame.time_relative < {t_end}"
    if display_filter:
        full_filter = f"({time_filter}) && ({display_filter})"
    else:
        full_filter = time_filter

    r = subprocess.run(
        f"tshark -r {pcap} -d 'sctp.port==38412,ngap' "
        f"-Y \"{full_filter}\" 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    )
    try:
        return int(r.stdout.strip())
    except:
        return 0


def tshark_window_nodecode(pcap, t_start, t_end, display_filter=""):
    """Count packets in time window WITHOUT ngap decode — for SCTP chunk filters"""
    time_filter = f"frame.time_relative >= {t_start} && frame.time_relative < {t_end}"
    if display_filter:
        full_filter = f"({time_filter}) && ({display_filter})"
    else:
        full_filter = time_filter

    r = subprocess.run(
        f"tshark -r {pcap} "
        f"-Y \"{full_filter}\" 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    )
    try:
        return int(r.stdout.strip())
    except:
        return 0

def check_null_scheme_window(pcap, t_start, t_end):
    r = subprocess.run(
        f"tshark -r {pcap} -d 'sctp.port==38412,ngap' "
        f"-Y \"frame.time_relative >= {t_start} && frame.time_relative < {t_end}\" "
        f"-V 2>/dev/null | grep -i 'null scheme'",
        shell=True, capture_output=True, text=True
    ).stdout

    if not r.strip():
        return 0

    ip_check = subprocess.run(
        f"tshark -r {pcap} "
        f"-Y \"frame.time_relative >= {t_start} && frame.time_relative < {t_end}\" "
        f"2>/dev/null | grep '10.10.0.41'",
        shell=True, capture_output=True, text=True
    ).stdout

    return 1 if "10.10.0.41" in ip_check else 0

def check_rand_repeat_window(pcap, t_start, t_end):
    result = subprocess.run(
        f"tshark -r {pcap} -d 'sctp.port==38412,ngap' "
        f"-Y \"frame.time_relative >= {t_start} && frame.time_relative < {t_end}\" "
        f"-V 2>/dev/null | grep 'RAND value'",
        shell=True, capture_output=True, text=True
    )
    lines = [l.split(":")[-1].strip() for l in result.stdout.strip().split("\n") if "RAND" in l]
    return 1 if len(lines) != len(set(lines)) and len(lines) > 0 else 0

def extract_window_features(label, pcap, t_start, t_end, window_id):
    duration = t_end - t_start

    total_packets    = tshark_window(pcap, t_start, t_end)
    auth_requests    = tshark_window(pcap, t_start, t_end, "nas_5gs.mm.message_type == 0x56")
    auth_failures    = tshark_window(pcap, t_start, t_end, "nas_5gs.mm.message_type == 0x59")
    reg_requests     = tshark_window(pcap, t_start, t_end, "nas_5gs.mm.message_type == 0x41")
    reg_rejects      = tshark_window(pcap, t_start, t_end, "nas_5gs.mm.message_type == 0x44")
    sec_mode_cmds    = tshark_window(pcap, t_start, t_end, "nas_5gs.mm.message_type == 0x5d")
    ng_setup_req     = tshark_window(pcap, t_start, t_end, "ngap.procedureCode == 21")
    suci_unencrypted = check_null_scheme_window(pcap, t_start, t_end)
    rand_repeat      = check_rand_repeat_window(pcap, t_start, t_end)
    sctp_abort       = tshark_window_nodecode(pcap, t_start, t_end, "sctp.chunk_type == 6")

    auth_rate         = round(auth_requests / duration, 4)
    reg_rate          = round(reg_requests / duration, 4)
    reject_rate       = round(reg_rejects / max(reg_requests, 1), 4)
    auth_success      = max(auth_requests - reg_rejects, 0)
    auth_success_rate = round(auth_success / max(auth_requests, 1), 4)

    return {
        "label":             label,
        "window_id":         f"{label}_w{window_id}",
        "t_start":           round(t_start, 1),
        "t_end":             round(t_end, 1),
        "total_packets":     total_packets,
        "auth_requests":     auth_requests,
        "auth_failures":     auth_failures,
        "reg_requests":      reg_requests,
        "reg_rejects":       reg_rejects,
        "sec_mode_cmds":     sec_mode_cmds,
        "ng_setup_req":      ng_setup_req,
        "suci_unencrypted":  suci_unencrypted,
        "duration":          duration,
        "auth_rate":         auth_rate,
        "reg_rate":          reg_rate,
        "reject_rate":       reject_rate,
        "auth_success_rate": auth_success_rate,
        "rand_repeat":       rand_repeat,
        "sctp_abort":        sctp_abort,
        "is_active":         1 if total_packets > 50 else 0,
    }

def process_pcap(label, pcap, global_window_id):
    """Apply sliding window to a single pcap file"""
    print(f"\n  [*] Processing: {label} — {os.path.basename(pcap)}")

    duration = get_duration(pcap)
    if duration < WINDOW_SIZE:
        print(f"  [!] Duration {duration:.1f}s < window {WINDOW_SIZE}s — using full pcap")
        feat = extract_window_features(label, pcap, 0, duration, global_window_id)
        return [feat], global_window_id + 1

    windows = []
    t_start = 0.0
    window_id = global_window_id

    while t_start + WINDOW_SIZE <= duration:
        t_end = t_start + WINDOW_SIZE
        print(f"     Window {window_id}: {t_start:.0f}s — {t_end:.0f}s", end=" ")

        feats = extract_window_features(label, pcap, t_start, t_end, window_id)
        windows.append(feats)

        print(f"auth={feats['auth_requests']} reg={feats['reg_requests']} "
              f"rej={feats['reg_rejects']} suci={feats['suci_unencrypted']} "
              f"ng={feats['ng_setup_req']} active={feats['is_active']}")

        t_start += STEP_SIZE
        window_id += 1

    print(f"  [+] {len(windows)} windows from {duration:.1f}s")
    return windows, window_id

def main():
    print("=" * 60)
    print("SLIDING WINDOW FEATURE EXTRACTOR")
    print(f"Window: {WINDOW_SIZE}s | Step: {STEP_SIZE}s | Overlap: {int((1-STEP_SIZE/WINDOW_SIZE)*100)}%")
    print("=" * 60)

    os.makedirs(DATASETS, exist_ok=True)

    all_features = []
    stats = {}
    global_window_id = 0

    for label, pcap_list in CAPTURES.items():
        label_windows = []
        for pcap in pcap_list:
            if not os.path.exists(pcap):
                print(f"\n  [!] Skipping {os.path.basename(pcap)} — not found")
                continue
            windows, global_window_id = process_pcap(label, pcap, global_window_id)
            label_windows.extend(windows)

        all_features.extend(label_windows)
        stats[label] = len(label_windows)

    if not all_features:
        print("No features extracted!")
        return

    # Write CSV
    fieldnames = list(all_features[0].keys())
    with open(FEATURES_CSV, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_features)

    print("\n" + "=" * 60)
    print("EXTRACTION COMPLETE")
    print("=" * 60)
    print(f"\n{'Label':<16} {'Windows':>8}")
    print("-" * 26)
    for label, count in stats.items():
        print(f"{label:<16} {count:>8}")
    print("-" * 26)
    print(f"{'TOTAL':<16} {len(all_features):>8}")
    print(f"\n[*] Saved: {FEATURES_CSV}")

    # SMOTE check
    print("\n[SMOTE CHECK]")
    for label, count in stats.items():
        status = "✓ OK" if count >= 3 else "⚠ Need 3+ for SMOTE"
        print(f"  {label:<16} {count:>3} windows  {status}")

if __name__ == "__main__":
    main()
