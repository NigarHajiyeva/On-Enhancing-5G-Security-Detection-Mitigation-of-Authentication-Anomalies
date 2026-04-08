#!/usr/bin/env python3
"""
Brute-force Attack - FGT1110.001
Thesis: On Enhancing 5G Security
"""
import subprocess
import time
import os

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CAPTURE_FILE = os.path.join(BASE_DIR, "captures", "brute_force.pcap")
LOG_FILE     = os.path.join(BASE_DIR, "logs", "brute_force.log")
CONFIG_DIR   = os.path.join(BASE_DIR, "config")
COMPOSE_FILE = os.path.join(BASE_DIR, "docker-compose.yml")
ATTEMPTS     = 20

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "captures"), exist_ok=True)

    start_time = time.strftime('%Y-%m-%dT%H:%M:%S')

    log("=" * 60)
    log("BRUTE-FORCE ATTACK - FGT1110.001")
    log("Target: 5G Authentication (AMF → AUSF → UDM)")
    log(f"Attempts: {ATTEMPTS} | Method: Wrong cryptographic key")
    log("=" * 60)

    # PHASE 1: Start capture inside AMF container
    log("[*] Starting capture inside AMF container...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/brute_force.pcap", shell=True)
    subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/brute_force.pcap",
        shell=True
    )
    time.sleep(3)
    log("[*] Capture started.")

    # PHASE 2: Run attack attempts
    log("\n[PHASE 2] Executing Brute-force Attack...")
    for i in range(1, ATTEMPTS + 1):
        log(f"[*] Attempt {i}/{ATTEMPTS}...")

        cid = subprocess.run(
            f"""docker run -d \
                --network thesis-5g_5gcore \
                --privileged \
                -v {CONFIG_DIR}/attacker.yaml:/etc/ueransim/ue.yaml \
                ueransim-custom:3.2.7 ue /etc/ueransim/ue.yaml""",
            shell=True, capture_output=True, text=True
        ).stdout.strip()

        if not cid:
            log(f"[!] Attempt {i}: Container failed to start — skipping")
            continue

        # Restart ue1/ue2 every 5 attempts to keep SCTP visible in capture
        if i % 5 == 0:
            subprocess.run(
                f"docker compose -f {COMPOSE_FILE} restart ue1 ue2",
                shell=True, capture_output=True
            )

        time.sleep(15)
        subprocess.run(f"docker rm -f {cid} 2>/dev/null", shell=True)

        # Check AMF logs for MAC failure
        amf_check = subprocess.run(
            "docker logs open5gs-amf 2>&1 | grep -iE 'MAC failure|Authentication reject|Registration reject' | tail -3",
            shell=True, capture_output=True, text=True
        ).stdout

        if amf_check.strip():
            log(f"[+] Attempt {i}: Rejected by AMF ✓")
        else:
            log(f"[?] Attempt {i}: No result detected")

        time.sleep(2)

    # PHASE 3: Stop capture
    log("\n[PHASE 3] Stopping capture...")
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)
    subprocess.run(f"docker cp open5gs-amf:/tmp/brute_force.pcap {CAPTURE_FILE}", shell=True)
    time.sleep(2)

    # Verify pcap
    pkt_count = subprocess.run(
        f"tshark -r {CAPTURE_FILE} 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip()
    log(f"[*] Packets in capture: {pkt_count}")

    ngap_count = subprocess.run(
        f"tshark -r {CAPTURE_FILE} 2>/dev/null | grep -iE 'ngap|sctp' | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip()
    log(f"[*] NGAP/SCTP packets: {ngap_count}")

    # PHASE 4: Analyze
    log("\n[PHASE 4] Analyzing results...")
    # Analyze from capture - more accurate
    mac_failures = int(subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' 2>/dev/null | grep 'Authentication failure' | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip() or 0)

    auth_rejects = int(subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' 2>/dev/null | grep 'Authentication reject' | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip() or 0)

    reg_rejects = int(subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' 2>/dev/null | grep 'Registration reject' | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip() or 0)

    with open(LOG_FILE, 'w') as f:
        f.write(f"MAC failures: {mac_failures}\nAuth rejects: {auth_rejects}\nReg rejects: {reg_rejects}\n")

    log("\n" + "=" * 60)
    log("BRUTE-FORCE ATTACK RESULTS")
    log(f"Total attempts:        {ATTEMPTS}")
    log(f"AMF MAC failures:      {mac_failures}")
    log(f"AMF Auth rejects:      {auth_rejects}")
    log(f"AMF Reg rejects:       {reg_rejects}")
    log(f"NGAP/SCTP packets:     {ngap_count}")
    log("Attack DETECTED ✓" if (mac_failures + auth_rejects + reg_rejects) > 0 else "No failures detected")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
