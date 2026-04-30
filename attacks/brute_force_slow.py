#!/usr/bin/env python3
"""
Brute-force Attack (Slow) - FGT1110.001
"""
import subprocess
import time
import os

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CAPTURE_FILE = os.path.join(BASE_DIR, "captures", "brute_force_slow.pcap")
LOG_FILE     = os.path.join(BASE_DIR, "logs", "brute_force_slow.log")
CONFIG_DIR   = os.path.join(BASE_DIR, "config")
COMPOSE_FILE = os.path.join(BASE_DIR, "docker-compose.yml")
ATTEMPTS     = 3

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def count_in_logs(keyword, since):
    out = subprocess.run(
        f"docker logs open5gs-amf --since {since} 2>&1 | grep -c '{keyword}' || true",
        shell=True, capture_output=True, text=True
    ).stdout.strip()
    try:
        return int(out)
    except:
        return 0

def main():
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "captures"), exist_ok=True)

    log("=" * 60)
    log("BRUTE-FORCE ATTACK (SLOW) - FGT1110.001")
    log(f"Attempts: {ATTEMPTS} | Interval: 15s | Method: Wrong key")
    log("=" * 60)

    # PHASE 1: Start capture
    log("[*] Starting capture inside AMF container...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/bf_slow.pcap", shell=True)
    subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i eth0 -w /tmp/bf_slow.pcap",
        shell=True
    )
    time.sleep(3)
    since = time.strftime('%Y-%m-%dT%H:%M:%S')
    log(f"[*] Capture started. Logging from: {since}")

    # PHASE 2: Slow attempts
    log("\n[PHASE 2] Executing slow brute-force...")
    mac_count = 0
    for i in range(1, ATTEMPTS + 1):
        log(f"[*] Attempt {i}/{ATTEMPTS}...")
        cid = subprocess.run(
            f"docker run -d --network thesis-5g_5gcore --privileged "
            f"-v {CONFIG_DIR}/attacker.yaml:/etc/ueransim/ue.yaml "
            f"ueransim-custom:3.2.7 ue /etc/ueransim/ue.yaml",
            shell=True, capture_output=True, text=True
        ).stdout.strip()

        if not cid:
            log(f"[!] Attempt {i}: Container failed to start")
            continue

        time.sleep(20)
        subprocess.run(f"docker rm -f {cid} 2>/dev/null", shell=True)

        failures = count_in_logs("MAC failure", since)
        log(f"[+] Attempt {i}: MAC failures so far: {failures}")

        if i < ATTEMPTS:
            log(f"[*] Waiting 15s before next attempt...")
            time.sleep(15)

    # PHASE 3: Stop capture
    log("\n[PHASE 3] Stopping capture...")
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(5)
    subprocess.run(
        f"docker cp open5gs-amf:/tmp/bf_slow.pcap {CAPTURE_FILE}",
        shell=True
    )

    # PHASE 4: Results
    log("\n[PHASE 4] Analyzing results...")
    mac_failures = count_in_logs("MAC failure", since)
    auth_rejects = count_in_logs("Authentication reject", since)

    pkt_count = subprocess.run(
        f"tshark -r {CAPTURE_FILE} 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    sctp_count = subprocess.run(
        f"tshark -r {CAPTURE_FILE} -Y 'sctp' 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    log("\n" + "=" * 60)
    log("SLOW BRUTE-FORCE RESULTS")
    log(f"Total attempts:    {ATTEMPTS}")
    log(f"MAC failures:      {mac_failures}")
    log(f"Auth rejects:      {auth_rejects}")
    log(f"Total packets:     {pkt_count}")
    log(f"SCTP packets:      {sctp_count}")
    log("Attack DETECTED ✓" if mac_failures > 0 else "Not detected")
    log("=" * 60)
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
