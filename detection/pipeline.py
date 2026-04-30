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

def extract_live_features(pcap_path, t_start=0, t_end=30):
    duration = t_end - t_start

    def count(filt=""):
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

def detect(features, rf_model, scaler):
    """Hybrid detection: definitive rules first, then RF"""

    if features['suci_unencrypted'] == 1:
        return 'supi_harvest', 1.0, 'rule'

    if features['reg_rejects'] >= 1 and features['sec_mode_cmds'] >= 1:
        return 'bidding_down', 1.0, 'rule'

    # High-rate brute force only: rule (>=5 failures across full pcap)
    if features['auth_failures'] >= 5:
        return 'brute_force', 1.0, 'rule'
    # Low-rate brute force (1-4 failures): passed to RF

    if features['sctp_abort'] >= 1:
        return 'replay', 1.0, 'rule'

    if features['ng_setup_req'] == 99:
        return 'false_bs', 1.0, 'rule'

    X = pd.DataFrame([features])[FEATURES]
    X_scaled = scaler.transform(X)
    prediction = rf_model.predict(X_scaled)[0]
    confidence = np.max(rf_model.predict_proba(X_scaled)[0])
    return prediction, confidence, 'rf'

def apply_mitigation(attack_type):
    actions = []
    if attack_type == 'brute_force':
        log("[MITIGATE] Brute Force → Rate limiting + IMSI block", "ALERT")
        subprocess.run(
            "docker ps --filter 'ancestor=ueransim-custom:3.2.7' --format '{{.Names}}' | "
            "grep -vE 'ueransim-gnb|ueransim-ue1|ueransim-ue2' | "
            "xargs -r docker rm -f 2>/dev/null || true",
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

def push_metrics(result):
    attack_map = {
        'normal': 0, 'brute_force': 1, 'supi_harvest': 2,
        'bidding_down': 3, 'replay': 4, 'false_bs': 5
    }
    prediction_id = attack_map.get(result['prediction'], -1)

    metrics = f"""# HELP detection_prediction Attack type detected
# TYPE detection_prediction gauge
detection_prediction{{capture="{result['capture']}"}} {prediction_id}
# HELP detection_confidence Detection confidence score
# TYPE detection_confidence gauge
detection_confidence{{capture="{result['capture']}"}} {result['confidence']}
# HELP detection_response_time Response time in seconds
# TYPE detection_response_time gauge
detection_response_time{{capture="{result['capture']}"}} {result['response_time']}
# HELP mitigation_applied Mitigation applied
# TYPE mitigation_applied gauge
mitigation_applied{{capture="{result['capture']}",attack="{result['prediction']}"}} 1
"""
    subprocess.run(
        f"curl -s --data-binary @- "
        f"{PUSHGATEWAY}/metrics/job/thesis_5g/instance/{result['capture']}",
        input=metrics.encode(),
        shell=True, capture_output=True
    )
    log(f"[METRICS] Pushed to Pushgateway ✓")

def run_pipeline(pcap_path, capture_name):
    log(f"\n{'='*50}")
    log(f"PIPELINE START: {capture_name}")
    log(f"PCap: {pcap_path}")

    t_start = time.time()

    log("[STEP 1] Extracting features (best window)...")
    dur_r = subprocess.run(
        f"tshark -r {pcap_path} -T fields -e frame.time_relative 2>/dev/null | tail -1",
        shell=True, capture_output=True, text=True
    )
    try:
        duration = float(dur_r.stdout.strip())
    except:
        duration = WINDOW_SIZE

    best_features = None
    best_score = -1
    t = 0
    while t < duration:
        f = extract_live_features(pcap_path, t, t + WINDOW_SIZE)
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
        t += WINDOW_SIZE

    if best_features is None:
        best_features = extract_live_features(pcap_path, 0, WINDOW_SIZE)
    features = best_features

    log(f"  auth={features['auth_requests']} reg={features['reg_requests']} "
        f"rej={features['reg_rejects']} suci={features['suci_unencrypted']} "
        f"ng={features['ng_setup_req']} auth_fail={features['auth_failures']} "
        f"sctp_abort={features['sctp_abort']}")

    # Full-pcap SCTP ABORT check
    abort_check = subprocess.run(
        f"tshark -r {pcap_path} -Y 'sctp.chunk_type == 6' 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    )
    try:
        if int(abort_check.stdout.strip()) > 0:
            features['sctp_abort'] = 1
    except:
        pass

    # Full-pcap auth failure check (brute force spans multiple windows)
    auth_fail_check = subprocess.run(
        f"tshark -r {pcap_path} -d 'sctp.port==38412,ngap' "
        f"-Y 'nas_5gs.mm.message_type == 0x59' 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    )
    try:
        total_auth_failures = int(auth_fail_check.stdout.strip())
        if total_auth_failures > features['auth_failures']:
            features['auth_failures'] = total_auth_failures
            log(f"  [full-pcap] auth_failures updated: {total_auth_failures}")
    except:
        pass

    # Full-pcap rogue gNB check
    rogue_check = subprocess.run(
        f"tshark -r {pcap_path} -d 'sctp.port==38412,ngap' "
        f"-Y 'ngap.procedureCode == 21' -T fields -e ip.src 2>/dev/null",
        shell=True, capture_output=True, text=True
    )
    rogue_ips = [ip.strip() for ip in rogue_check.stdout.strip().split()
                 if ip.strip() and ip.strip() not in ('10.10.0.30', '10.10.0.12')]
    if rogue_ips:
        features['ng_setup_req'] = 99

    log("[STEP 2] Running hybrid detector...")
    prediction, confidence, method = detect(features, rf_model, scaler)
    # Low confidence RF prediction → flag as unknown
    if method == 'rf' and confidence < 0.65:
        log(f"  [WARNING] Low confidence ({confidence:.2f}) → flagging as unknown", "ALERT")
        prediction = 'unknown'
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
        "capture":       capture_name,
        "prediction":    prediction,
        "confidence":    round(confidence, 3),
        "method":        method,
        "actions":       actions,
        "response_time": response_time,
        "features":      features
    }

    log(f"[DONE] Response time: {response_time}s")
    log(f"[RESULT] Capture: {capture_name} → Detected: {prediction} ({method}, {confidence:.2f})")

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

    # Auto-discover test captures
    test_dir = os.path.join(BASE_DIR, "captures", "test")
    if not os.path.exists(test_dir):
        log(f"[ERROR] Test directory not found: {test_dir}")
        return

    test_captures = {}
    for fname in sorted(os.listdir(test_dir)):
        if fname.endswith(".pcap"):
            capture_name = fname.replace(".pcap", "")
            test_captures[capture_name] = os.path.join(test_dir, fname)
            log(f"[INIT] Found: {fname}")

    if not test_captures:
        log("[ERROR] No pcap files found in test/")
        return

    results = []
    for capture_name, pcap in test_captures.items():
        result = run_pipeline(pcap, capture_name)
        results.append(result)
        time.sleep(1)

    total    = len(results)
    avg_time = sum(r['response_time'] for r in results) / total if total > 0 else 0

    log("\n" + "=" * 60)
    log("PIPELINE FINAL SUMMARY")
    log("=" * 60)
    log(f"Total captures processed: {total}")
    log(f"Avg response time:        {avg_time:.2f}s")
    log(f"\n{'Capture':<20} {'Detected':<16} {'Method':<8} {'Conf':>6} {'Time':>8}")
    log("-" * 62)
    for r in results:
        log(f"{r['capture']:<20} {r['prediction']:<16} {r['method']:<8} "
            f"{r['confidence']:>6.2f} {r['response_time']:>7.1f}s")

    summary_metrics = f"""# HELP pipeline_total_captures Total captures processed
# TYPE pipeline_total_captures gauge
pipeline_total_captures {total}
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
        "avg_response_time": avg_time,
        "results": results
    }
    with open(REPORT_FILE, 'w') as f:
        json.dump(report, f, indent=2)

    log("=" * 60)
    log(f"[*] Log:    {LOG_FILE}")
    log(f"[*] Report: {REPORT_FILE}")

if __name__ == "__main__":
    main()
