#!/usr/bin/env python3
"""
Brute-force Attack - FGT1110.001
Thesis: On Enhancing 5G Security
"""

import subprocess
import time

CAPTURE_FILE = "/home/eit42s/thesis-5g/captures/brute_force.pcap"
LOG_FILE     = "/home/eit42s/thesis-5g/logs/brute_force.log"
ATTEMPTS     = 10

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def get_bridge():
    r = subprocess.run(
        "docker network inspect thesis-5g_5gcore --format '{{.Id}}' | cut -c1-12",
        shell=True, capture_output=True, text=True
    )
    return f"br-{r.stdout.strip()}"

def main():
    log("=" * 60)
    log("BRUTE-FORCE ATTACK - FGT1110.001")
    log("Target: 5G Authentication (AMF → AUSF → UDM)")
    log(f"Attempts: {ATTEMPTS} | Method: Wrong cryptographic key")
    log("=" * 60)

    # PHASE 1: Start capture
    log(f"[*] Starting capture inside AMF container...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/brute_force.pcap", shell=True)
    tcpdump = subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/brute_force.pcap",
        shell=True
    )
    time.sleep(3)
    log("[*] Capture started.")

    # PHASE 2: Run attack attempts
    log("\n[PHASE 2] Executing Brute-force Attack...")
    for i in range(1, ATTEMPTS + 1):
        log(f"[*] Attempt {i}/{ATTEMPTS}...")
        # Container-i background-da baslat, 15 saniye gozle, sonra sil
        cid = subprocess.run(
            """docker run -d \
                --network thesis-5g_5gcore \
                --ip 10.10.0.40 \
                -v /home/eit42s/thesis-5g/config/attacker.yaml:/etc/ueransim/ue.yaml \
                gradiant/ueransim:3.2.6 ue /etc/ueransim/ue.yaml""",
            shell=True, capture_output=True, text=True
        ).stdout.strip()
        
        time.sleep(12)
        
        # Container logunu oxu
        logs = subprocess.run(
            f"docker logs {cid} 2>&1",
            shell=True, capture_output=True, text=True
        ).stdout + subprocess.run(
            f"docker logs {cid} 2>&1",
            shell=True, capture_output=True, text=True
        ).stderr
        
        subprocess.run(f"docker rm -f {cid} 2>/dev/null", shell=True)
        
        if "401" in logs or "failed" in logs.lower() or "reject" in logs.lower():
            log(f"[+] Attempt {i}: Authentication FAILED (expected) ✓")
        else:
            log(f"[?] Attempt {i}: No clear result")
        
        time.sleep(2)

    # PHASE 3: Stop capture
    log("\n[PHASE 3] Stopping capture...")
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)
    subprocess.run(f"docker cp open5gs-amf:/tmp/brute_force.pcap {CAPTURE_FILE}", shell=True)
    time.sleep(2)

    # PHASE 4: Analyze
    log("\n[PHASE 4] Analyzing results...")
    ausf_logs = subprocess.run(
        "docker logs open5gs-ausf 2>&1 | grep '401\\|ERROR' | tail -20",
        shell=True, capture_output=True, text=True
    ).stdout

    http_401 = ausf_logs.count("401")

    with open(LOG_FILE, 'w') as f:
        f.write(ausf_logs)

    log("\n" + "=" * 60)
    log("BRUTE-FORCE ATTACK RESULTS")
    log(f"Total attempts:       {ATTEMPTS}")
    log(f"AUSF HTTP 401 errors: {http_401}")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
