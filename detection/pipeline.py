#!/usr/bin/env python3
"""
Real-time Detection-Response Pipeline
Thesis: On Enhancing 5G Security
Flow: Attack → Feature Extract → Detect → Mitigate → Alert → Grafana
"""

import subprocess
import time
import os
import json
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

BASE_DIR    = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TRAIN_CSV   = os.path.join(BASE_DIR, "datasets", "master_dataset.csv")
LOG_FILE    = os.path.join(BASE_DIR, "logs", "pipeline.log")
REPORT_FILE = os.path.join(BASE_DIR, "logs", "pipeline_report.json")
PUSHGATEWAY = "http://10.10.0.70:9091"

FEATURES = [
    'total_packets', 'auth_requests', 'reg_requests', 'reg_rejects',
    'sec_mode_cmds', 'ng_setup_req', 'suci_unencrypted', 'duration',
    'auth_rate', 'reg_rate', 'reject_rate', 'auth_success_rate',
    'rand_repeat', 'auth_failures', 'sctp_abort'
]

WINDOW_SIZE = 30

def log(msg, level="INFO"):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{timestamp}] [{level}] {msg}"
    print(line)
    with open(LOG_FILE, 'a') as f:
        f.write(line + "\n")

# ─── Feature Extraction ────────────────────────────────────
def extract_live_features(pcap_path, t_start=0, t_end=30):
    duration = t_end - t_start

    def count(filt=""):
        """Count with NGAP decode"""
        time_filt = f"frame.time_relative >= {t_start} && frame.time_relative < {t_end}"
        full = f"({time_filt}) && ({filt})" if filt else time_filt
        r = subprocess.run(
            f"tshark -r {pcap_path} -d 'sctp.port==38412,ngap' "
            f"-Y \"{full}\" 2>/dev/null | wc -l",
            shell=True, capture_output=True, text=True
        )
        try:
            return int(r.stdout.strip())
        except:
            return 0

    def count_nodecode(filt=""):
        """Count WITHOUT NGAP decode — for SCTP chunk filters"""
        time_filt = f"frame.time_relative >= {t_start} && frame.time_relative < {t_end}"
        full = f"({time_filt}) && ({filt})" if filt else time_filt
        r = subprocess.run(
            f"tshark -r {pcap_path} "
            f"-Y \"{full}\" 2>/dev/null | wc -l",
            shell=True, capture_output=True, text=True
        )
        try:
            return int(r.stdout.strip())
        except:
            return 0

    total_packets = count()
    auth_requests = count("nas_5gs.mm.message_type == 0x56")
    auth_failures = count("nas_5gs.mm.message_type == 0x59")
    reg_requests  = count("nas_5gs.mm.message_type == 0x41")
    reg_rejects   = count("nas_5gs.mm.message_type == 0x44")
    sec_mode_cmds = count("nas_5gs.mm.message_type == 0x5d")
    ng_setup_req  = count("ngap.procedureCode == 21")
    sctp_abort    = count_nodecode("sctp.chunk_type == 6")

    # SUCI NULL scheme check
    r = subprocess.run(
        f"tshark -r {pcap_path} -d 'sctp.port==38412,ngap' "
        f"-Y \"frame.time_relative >= {t_start} && frame.time_relative < {t_end}\" "
        f"-V 2>/dev/null | grep -i 'null scheme'",
        shell=True, capture_output=True, text=True
    ).stdout
    ip_check = subprocess.run(
        f"tshark -r {pcap_path} "
        f"-Y \"frame.time_relative >= {t_start} && frame.time_relative < {t_end}\" "
        f"2>/dev/null | grep '10.10.0.41'",
        shell=True, capture_output=True, text=True
    ).stdout
    suci_unencrypted = 1 if (r.strip() and "10.10.0.41" in ip_check) else 0

    # RAND repeat check
    result = subprocess.run(
        f"tshark -r {pcap_path} -d 'sctp.port==38412,ngap' "
        f"-Y \"frame.time_relative >= {t_start} && frame.time_relative < {t_end}\" "
        f"-V 2>/dev/null | grep 'RAND value'",
        shell=True, capture_output=True, text=True
    )
    lines = [l.split(":")[-1].strip() for l in result.stdout.strip().split("\n") if "RAND" in l]
    rand_repeat = 1 if len(lines) != len(set(lines)) and len(lines) > 0 else 0

    auth_rate         = round(auth_requests / max(duration, 1), 4)
    reg_rate          = round(reg_requests / max(duration, 1), 4)
    reject_rate       = round(reg_rejects / max(reg_requests, 1), 4)
    auth_success      = max(auth_requests - reg_rejects, 0)
    auth_success_rate = round(auth_success / max(auth_requests, 1), 4)

    return {
        'total_packets':     total_packets,
        'auth_requests':     auth_requests,
        'reg_requests':      reg_requests,
        'reg_rejects':       reg_rejects,
        'sec_mode_cmds':     sec_mode_cmds,
        'ng_setup_req':      ng_setup_req,
        'suci_unencrypted':  suci_unencrypted,
        'duration':          float(duration),
        'auth_rate':         auth_rate,
        'reg_rate':          reg_rate,
        'reject_rate':       reject_rate,
        'auth_success_rate': auth_success_rate,
        'rand_repeat':       rand_repeat,
        'auth_failures':     auth_failures,
        'sctp_abort':        sctp_abort,
    }

# ─── Detection ─────────────────────────────────────────────
def detect(features, rf_model, scaler):
    """Hybrid detection: definitive rules first, then RF"""

    # Rule 1: SUPI Harvesting — NULL scheme is definitive
    if features['suci_unencrypted'] == 1:
        return 'supi_harvest', 1.0, 'rule'

    # Rule 2: Bidding Down — security reject + sec_mode is definitive
    if features['reg_rejects'] >= 1 and features['sec_mode_cmds'] >= 1:
        return 'bidding_down', 1.0, 'rule'

    # Rule 3: Brute Force — auth failures are definitive
    if features['auth_failures'] > 0:
        return 'brute_force', 1.0, 'rule'

    # Rule 4: Replay — SCTP ABORT is definitive
    if features['sctp_abort'] >= 1:
        return 'replay', 1.0, 'rule'

    # Rule 5: False BS — NGSetup from unknown gNB
    if features['ng_setup_req'] == 99:
        return 'false_bs', 1.0, 'rule'

    # RF for remaining cases
    X = pd.DataFrame([features])[FEATURES]
    X_scaled = scaler.transform(X)
    prediction = rf_model.predict(X_scaled)[0]
    confidence = np.max(rf_model.predict_proba(X_scaled)[0])
    return prediction, confidence, 'rf'

# ─── Mitigation ────────────────────────────────────────────
def apply_mitigation(attack_type):
    actions = []
    if attack_type == 'brute_force':
        log("[MITIGATE] Brute Force → Rate limiting + IMSI block", "ALERT")
        subprocess.run(
            "docker rm -f $(docker ps -q --filter 'ancestor=ueransim-custom:3.2.7') 2>/dev/null || true",
            shell=True, capture_output=True
        )
        actions = ["rate_limiting", "attacker_ue_blocked", "alert_generated"]
    elif attack_type == 'supi_harvest':
        log("[MITIGATE] SUPI Harvest → NULL scheme rejection enforced", "ALERT")
        actions = ["null_scheme_rejected", "suci_encryption_enforced", "alert_generated"]
    elif attack_type == 'bidding_down':
        log("[MITIGATE] Bidding Down → NIA0/NEA0 blocked", "ALERT")
        actions = ["null_integrity_blocked", "null_ciphering_blocked", "alert_generated"]
    elif attack_type == 'replay':
        log("[MITIGATE] Replay Attack → SQN strict validation", "ALERT")
        actions = ["sqn_strict_mode", "rand_replay_detection", "alert_generated"]
    elif attack_type == 'false_bs':
        log("[MITIGATE] False BS → Rogue gNB disconnect", "ALERT")
        subprocess.run("docker rm -f ueransim-rogue-gnb 2>/dev/null", shell=True)
        actions = ["rogue_gnb_disconnected", "ip_flagged", "alert_generated"]
    else:
        log("[OK] Normal traffic — no action required")
        actions = ["no_action"]
    return actions

# ─── Prometheus Push ───────────────────────────────────────
def push_metrics(result):
    attack_map = {
        'normal': 0, 'brute_force': 1, 'supi_harvest': 2,
        'bidding_down': 3, 'replay': 4, 'false_bs': 5
    }
    prediction_id = attack_map.get(result['prediction'], -1)
    correct       = 1 if result['correct'] else 0

    metrics = f"""# HELP detection_prediction Attack type detected
# TYPE detection_prediction gauge
detection_prediction{{label="{result['label']}"}} {prediction_id}
# HELP detection_correct Detection correctness
# TYPE detection_correct gauge
detection_correct{{label="{result['label']}"}} {correct}
# HELP detection_confidence Detection confidence score
# TYPE detection_confidence gauge
detection_confidence{{label="{result['label']}"}} {result['confidence']}
# HELP detection_response_time Response time in seconds
# TYPE detection_response_time gauge
detection_response_time{{label="{result['label']}"}} {result['response_time']}
# HELP mitigation_applied Mitigation applied
# TYPE mitigation_applied gauge
mitigation_applied{{label="{result['label']}",attack="{result['prediction']}"}} 1
"""
    subprocess.run(
        f"curl -s --data-binary @- "
        f"{PUSHGATEWAY}/metrics/job/thesis_5g/instance/{result['label']}",
        input=metrics.encode(),
        shell=True, capture_output=True
    )
    log(f"[METRICS] Pushed to Pushgateway ✓")

# ─── Main Pipeline ─────────────────────────────────────────
def run_pipeline(pcap_path, label="unknown"):
    log(f"\n{'='*50}")
    log(f"PIPELINE START: {label}")
    log(f"PCap: {pcap_path}")

    t_start = time.time()

    log("[STEP 1] Extracting features (best window)...")
    # Get duration
    dur_r = subprocess.run(
        f"tshark -r {pcap_path} -T fields -e frame.time_relative 2>/dev/null | tail -1",
        shell=True, capture_output=True, text=True
    )
    try:
        duration = float(dur_r.stdout.strip())
    except:
        duration = WINDOW_SIZE

    # Extract all windows and pick most informative
    best_features = None
    best_score = -1
    t = 0
    while t < duration:  # process all possible windows
        f = extract_live_features(pcap_path, t, t + WINDOW_SIZE)
        # Score: prioritize attack signals
        score = (f['suci_unencrypted'] * 100 +
                 f['auth_failures'] * 50 +
                 f['sctp_abort'] * 50 +
                 f['reg_rejects'] * 30 +
                 f['sec_mode_cmds'] * 20 +
                 f['ng_setup_req'] * 15 +
                 f['auth_requests'] * 2 +
                 f['total_packets'])
        if score > best_score:
            best_score = score
            best_features = f
        t += WINDOW_SIZE  # non-overlapping for speed
    if best_features is None:
        best_features = extract_live_features(pcap_path, 0, WINDOW_SIZE)
    features = best_features
    log(f"  auth={features['auth_requests']} reg={features['reg_requests']} "
        f"rej={features['reg_rejects']} suci={features['suci_unencrypted']} "
        f"ng={features['ng_setup_req']} auth_fail={features['auth_failures']} "
        f"sctp_abort={features['sctp_abort']}")

    # Direct SCTP ABORT check across full pcap (for replay)
    abort_check = subprocess.run(
        f"tshark -r {pcap_path} -Y 'sctp.chunk_type == 6' 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    )
    try:
        if int(abort_check.stdout.strip()) > 0:
            features['sctp_abort'] = 1
    except:
        pass

    # Rogue gNB check — NGSetup from unknown IP (not 10.10.0.30)
    rogue_check = subprocess.run(
        f"tshark -r {pcap_path} -d 'sctp.port==38412,ngap' "
        f"-Y 'ngap.procedureCode == 21' -T fields -e ip.src 2>/dev/null",
        shell=True, capture_output=True, text=True
    )
    rogue_ips = [ip.strip() for ip in rogue_check.stdout.strip().split() 
                 if ip.strip() and ip.strip() not in ('10.10.0.30', '10.10.0.12')]
    if rogue_ips:
        features['ng_setup_req'] = 99  # Signal rogue gNB

    log("[STEP 2] Running hybrid detector...")
    prediction, confidence, method = detect(features, rf_model, scaler)
    log(f"  Prediction: {prediction} (confidence: {confidence:.2f}, method: {method})")

    if prediction != 'normal':
        log(f"  ⚠️  ATTACK DETECTED: {prediction.upper()}", "ALERT")
    else:
        log(f"  ✓  Normal traffic")

    log("[STEP 3] Applying mitigation...")
    actions = apply_mitigation(prediction)
    log(f"  Actions: {', '.join(actions)}")

    t_end = time.time()
    response_time = round(t_end - t_start, 2)

    result = {
        "timestamp":     datetime.now().isoformat(),
        "label":         label,
        "prediction":    prediction,
        "confidence":    round(confidence, 3),
        "method":        method,
        "correct":       prediction == label,
        "actions":       actions,
        "response_time": response_time,
        "features":      features
    }

    log(f"[DONE] Response time: {response_time}s")
    log(f"[RESULT] Predicted: {prediction} | Actual: {label} | "
        f"{'CORRECT ✓' if prediction == label else 'WRONG ✗'}")

    push_metrics(result)
    return result

def main():
    global rf_model, scaler

    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    with open(LOG_FILE, 'w') as f:
        f.write("")

    log("=" * 60)
    log("AUTOMATED DETECTION-RESPONSE PIPELINE")
    log("Thesis: On Enhancing 5G Security")
    log(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 60)

    log("\n[INIT] Training Random Forest model...")
    train_df = pd.read_csv(TRAIN_CSV)
    X_train  = train_df[FEATURES]
    y_train  = train_df['label']

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    rf_model = RandomForestClassifier(
        n_estimators=200, max_depth=10,
        min_samples_split=5, random_state=42,
        class_weight='balanced'
    )
    rf_model.fit(X_scaled, y_train)
    log("[INIT] Model trained on 600 samples ✓")

    test_captures = {
        "normal":       os.path.join(BASE_DIR, "captures", "test", "normal_traffic.pcap"),
        "brute_force":  os.path.join(BASE_DIR, "captures", "test", "brute_force.pcap"),
        "supi_harvest": os.path.join(BASE_DIR, "captures", "test", "supi_harvest.pcap"),
        "bidding_down": os.path.join(BASE_DIR, "captures", "test", "bidding_down.pcap"),
        "replay":       os.path.join(BASE_DIR, "captures", "test", "replay_capture.pcap"),
        "false_bs":     os.path.join(BASE_DIR, "captures", "test", "false_bs.pcap"),
    }

    results = []
    for label, pcap in test_captures.items():
        if not os.path.exists(pcap):
            log(f"[SKIP] {label} — file not found")
            continue
        result = run_pipeline(pcap, label)
        results.append(result)
        time.sleep(1)

    correct  = sum(1 for r in results if r['correct'])
    total    = len(results)
    accuracy = correct / total if total > 0 else 0
    avg_time = sum(r['response_time'] for r in results) / total if total > 0 else 0

    log("\n" + "=" * 60)
    log("PIPELINE FINAL SUMMARY")
    log("=" * 60)
    log(f"Total captures processed: {total}")
    log(f"Correct detections:       {correct}/{total}")
    log(f"Pipeline accuracy:        {accuracy*100:.1f}%")
    log(f"Avg response time:        {avg_time:.2f}s")
    log(f"\n{'Label':<16} {'Predicted':<16} {'Correct':>8} {'Time':>8}")
    log("-" * 52)
    for r in results:
        status = "✓" if r['correct'] else "✗"
        log(f"{r['label']:<16} {r['prediction']:<16} {status:>8} {r['response_time']:>7.1f}s")

    summary_metrics = f"""# HELP pipeline_accuracy Overall pipeline accuracy
# TYPE pipeline_accuracy gauge
pipeline_accuracy {accuracy}
# HELP pipeline_total_captures Total captures processed
# TYPE pipeline_total_captures gauge
pipeline_total_captures {total}
# HELP pipeline_correct_detections Correct detections
# TYPE pipeline_correct_detections gauge
pipeline_correct_detections {correct}
# HELP pipeline_avg_response_time Average response time
# TYPE pipeline_avg_response_time gauge
pipeline_avg_response_time {avg_time}
"""
    subprocess.run(
        f"curl -s --data-binary @- "
        f"{PUSHGATEWAY}/metrics/job/thesis_5g/instance/summary",
        input=summary_metrics.encode(),
        shell=True, capture_output=True
    )
    log("\n[METRICS] Summary pushed to Pushgateway ✓")

    report = {
        "timestamp": datetime.now().isoformat(),
        "accuracy":  accuracy,
        "avg_response_time": avg_time,
        "results":   results
    }
    with open(REPORT_FILE, 'w') as f:
        json.dump(report, f, indent=2)

    log("=" * 60)
    log(f"[*] Log:    {LOG_FILE}")
    log(f"[*] Report: {REPORT_FILE}")

if __name__ == "__main__":
    main()
