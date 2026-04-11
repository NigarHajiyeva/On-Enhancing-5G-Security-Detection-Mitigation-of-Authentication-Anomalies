#!/usr/bin/env python3
"""
Bidding-down Attack - FGT5004
Thesis: On Enhancing 5G Security
Method: UE advertises only NULL security algorithms
"""
import subprocess
import time
import os

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CAPTURE_FILE = os.path.join(BASE_DIR, "captures", "bidding_down.pcap")
LOG_FILE     = os.path.join(BASE_DIR, "logs", "bidding_down.log")
CONFIG_DIR   = os.path.join(BASE_DIR, "config")
COMPOSE_FILE = os.path.join(BASE_DIR, "docker-compose.yml")

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "captures"), exist_ok=True)

    start_time = time.strftime('%Y-%m-%dT%H:%M:%S')

    log("=" * 60)
    log("BIDDING-DOWN ATTACK - FGT5004")
    log("Target: NAS Security Mode Command")
    log("Method: UE advertises NULL algorithms only")
    log("=" * 60)

    # PHASE 1: Start capture
    log("\n[PHASE 1] Starting capture...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/bidding_down.pcap", shell=True)
    subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/bidding_down.pcap",
        shell=True
    )
    time.sleep(3)
    log("[*] Capture started.")

    # PHASE 2: Start UE with NULL security algorithms
    log("\n[PHASE 2] Starting UE with NULL integrity and NULL ciphering...")
    subprocess.run("docker rm -f ueransim-ue-bidding 2>/dev/null", shell=True)

    cid = subprocess.run(
        f"""docker run -d \
            --name ueransim-ue-bidding \
            --network thesis-5g_5gcore \
            --ip 10.10.0.42 \
            --privileged \
            -v {CONFIG_DIR}/ue-bidding.yaml:/etc/ueransim/ue.yaml \
            ueransim-custom:3.2.7 ue /etc/ueransim/ue.yaml""",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    # Restart ue1/ue2 to make SCTP visible in capture
    subprocess.run(
        f"docker compose -f {COMPOSE_FILE} restart ue1 ue2",
        shell=True, capture_output=True
    )

    time.sleep(30)

    logs = subprocess.run(
        "docker logs ueransim-ue-bidding 2>&1",
        shell=True, capture_output=True, text=True
    ).stdout
    log(f"[*] UE logs:\n{logs[-500:]}")

    # PHASE 3: Stop capture
    log("\n[PHASE 3] Stopping capture...")
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)
    subprocess.run(f"docker cp open5gs-amf:/tmp/bidding_down.pcap {CAPTURE_FILE}", shell=True)
    subprocess.run("docker rm -f ueransim-ue-bidding 2>/dev/null", shell=True)

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

    # PHASE 4: Analyze
    log("\n[PHASE 4] Analyzing security algorithm negotiation...")

    tshark_result = subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' 2>/dev/null "
        f"| grep -iE 'reject|security mode'",
        shell=True, capture_output=True, text=True
    ).stdout

    amf_result = subprocess.run(
        f"docker logs --since {start_time} open5gs-amf 2>&1 | grep -iE 'security|reject|algorithm'",
        shell=True, capture_output=True, text=True
    ).stdout

    tshark_rejects = tshark_result.lower().count("reject")
    amf_rejects    = amf_result.lower().count("reject")

    log(f"[*] Tshark evidence:\n{tshark_result}")
    log(f"[*] AMF log evidence:\n{amf_result}")

    with open(LOG_FILE, 'w') as f:
        f.write("=== TSHARK OUTPUT ===\n")
        f.write(tshark_result)
        f.write("\n=== AMF LOGS ===\n")
        f.write(amf_result)

    log("\n" + "=" * 60)
    log("BIDDING-DOWN ATTACK RESULTS")
    log(f"PCap rejects (UE security mismatch): {tshark_rejects}")
    log(f"AMF log rejects:                     {amf_rejects}")
    log(f"NGAP/SCTP packets:                   {ngap_count}")
    log("AMF rejected NULL algorithms! ✓" if (tshark_rejects + amf_rejects) > 0 else "No rejection detected")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
