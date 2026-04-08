#!/usr/bin/env python3
"""
Feature Extractor
Thesis: On Enhancing 5G Security
Extracts 13 behavioral features from pcap files
"""

import subprocess
import os
import csv
import time

CAPTURES = {
    "normal":       "/home/eit42s/thesis-5g/captures/normal_traffic.pcap",
    "brute_force":  "/home/eit42s/thesis-5g/captures/brute_force.pcap",
    "supi_harvest": "/home/eit42s/thesis-5g/captures/supi_harvest.pcap",
    "bidding_down": "/home/eit42s/thesis-5g/captures/bidding_down.pcap",
    "replay":       "/home/eit42s/thesis-5g/captures/replay_capture.pcap",
    "false_bs":     "/home/eit42s/thesis-5g/captures/false_bs.pcap",
}

OUTPUT = "/home/eit42s/thesis-5g/datasets/features.csv"

def tshark(pcap, filt):
    r = subprocess.run(
        f"tshark -r {pcap} -d 'sctp.port==38412,ngap' -Y \"{filt}\" 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    )
    try:
        return int(r.stdout.strip())
    except:
        return 0

def tshark_raw(pcap, filt=""):
    cmd = f"tshark -r {pcap} -d 'sctp.port==38412,ngap' 2>/dev/null"
    if filt:
        cmd += f" -Y \"{filt}\""
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout

def get_duration(pcap):
    r = subprocess.run(
        f"tshark -r {pcap} -T fields -e frame.time_relative 2>/dev/null | tail -1",
        shell=True, capture_output=True, text=True
    )
    try:
        return float(r.stdout.strip())
    except:
        return 1.0

def extract_features(label, pcap):
    print(f"  [*] Processing: {label}")

    total_packets = int(subprocess.run(
        f"tshark -r {pcap} 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip() or 0)

    auth_requests   = tshark(pcap, "nas_5gs.mm.message_type == 0x56")
    reg_requests    = tshark(pcap, "nas_5gs.mm.message_type == 0x41")
    reg_rejects     = tshark(pcap, "nas_5gs.mm.message_type == 0x44")
    sec_mode_cmds   = tshark(pcap, "nas_5gs.mm.message_type == 0x5d")
    ng_setup_req    = tshark(pcap, "ngap.procedureCode == 21")

    # SUCI NULL scheme — only flag if PDU session established via NULL scheme
    # (distinguishes intentional SUPI harvesting from normal NULL scheme usage)
    verbose = subprocess.run(
        f"tshark -r {pcap} -d 'sctp.port==38412,ngap' -V 2>/dev/null | grep -i 'NULL scheme'",
        shell=True, capture_output=True, text=True
    ).stdout
    null_count = verbose.lower().count("null scheme")
    # Check if 10.10.0.41 (ue-supi) is in the capture
    ip_check = subprocess.run(
        f"tshark -r {pcap} 2>/dev/null | grep '10.10.0.41'",
        shell=True, capture_output=True, text=True
    ).stdout
    suci_unencrypted = 1 if (null_count > 0 and "10.10.0.41" in ip_check) else 0

    duration = max(get_duration(pcap), 1.0)

    auth_rate    = round(auth_requests / duration, 4)
    reg_rate     = round(reg_requests / duration, 4)
    reject_rate  = round(reg_rejects / max(reg_requests, 1), 4)
    auth_success = max(auth_requests - reg_rejects, 0)
    auth_success_rate = round(auth_success / max(auth_requests, 1), 4)

    # RAND capture check — if RAND value exists in capture, replay was attempted
    rand_out = subprocess.run(
        f"tshark -r {pcap} -d 'sctp.port==38412,ngap' -V 2>/dev/null | grep 'RAND value'",
        shell=True, capture_output=True, text=True
    ).stdout
    rands = [l.split(":")[-1].strip() for l in rand_out.strip().split("\n") if "RAND value" in l]
    unique_rands = set(rands)
    # Replay: same RAND seen more than once, OR RAND exists but no registration (raw replay attempt)
    if len(rands) > len(unique_rands) and len(rands) > 0:
        rand_repeat = 1
    elif len(rands) > 0 and auth_requests == 0 and reg_requests == 0:
        rand_repeat = 1
    else:
        rand_repeat = 0

    features = {
        "label":              label,
        "total_packets":      total_packets,
        "auth_requests":      auth_requests,
        "reg_requests":       reg_requests,
        "reg_rejects":        reg_rejects,
        "sec_mode_cmds":      sec_mode_cmds,
        "ng_setup_req":       ng_setup_req,
        "suci_unencrypted":   suci_unencrypted,
        "duration":           round(duration, 2),
        "auth_rate":          auth_rate,
        "reg_rate":           reg_rate,
        "reject_rate":        reject_rate,
        "auth_success_rate":  auth_success_rate,
        "rand_repeat":        rand_repeat,
    }

    print(f"     total={total_packets} auth={auth_requests} reg={reg_requests} "
          f"reject={reg_rejects} suci_null={suci_unencrypted} rand_repeat={rand_repeat}")
    return features

def main():
    print("=" * 60)
    print("FEATURE EXTRACTOR")
    print("=" * 60)

    os.makedirs("/home/eit42s/thesis-5g/datasets", exist_ok=True)

    all_features = []
    for label, pcap in CAPTURES.items():
        if not os.path.exists(pcap):
            print(f"  [!] Skipping {label} — file not found")
            continue
        features = extract_features(label, pcap)
        all_features.append(features)

    # Write CSV
    fieldnames = list(all_features[0].keys())
    with open(OUTPUT, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_features)

    print("\n" + "=" * 60)
    print(f"DONE — {len(all_features)} samples saved to:")
    print(f"  {OUTPUT}")
    print("=" * 60)

    # Print table
    print(f"\n{'Label':<16} {'Pkts':>6} {'Auth':>5} {'Reg':>5} {'Rej':>5} {'SUCI':>5} {'Rand':>5}")
    print("-" * 55)
    for f in all_features:
        print(f"{f['label']:<16} {f['total_packets']:>6} {f['auth_requests']:>5} "
              f"{f['reg_requests']:>5} {f['reg_rejects']:>5} "
              f"{f['suci_unencrypted']:>5} {f['rand_repeat']:>5}")

if __name__ == "__main__":
    main()
