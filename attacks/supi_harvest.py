#!/usr/bin/env python3
"""
SUPI Harvesting Attack - FGT5019
Thesis: On Enhancing 5G Security
Method: protectionScheme=0 (NULL scheme) — SUPI sent in plaintext
"""
import subprocess
import time
import os

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CAPTURE_FILE = os.path.join(BASE_DIR, "captures", "supi_harvest.pcap")
LOG_FILE     = os.path.join(BASE_DIR, "logs", "supi_harvest.log")
CONFIG_DIR   = os.path.join(BASE_DIR, "config")
COMPOSE_FILE = os.path.join(BASE_DIR, "docker-compose.yml")

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "captures"), exist_ok=True)

    log("=" * 60)
    log("SUPI HARVESTING ATTACK - FGT5019")
    log("Target: UE Identity Privacy (SUCI Protection)")
    log("Method: protectionScheme=0 (NULL scheme)")
    log("=" * 60)

    # PHASE 1: Start capture inside AMF
    log("\n[PHASE 1] Starting capture...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/supi_harvest.pcap", shell=True)
    subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/supi_harvest.pcap",
        shell=True
    )
    time.sleep(3)
    log("[*] Capture started.")

    # PHASE 2: Start UE with NULL scheme
    log("\n[PHASE 2] Starting UE with NULL protection scheme...")
    subprocess.run("docker rm -f ueransim-ue-supi 2>/dev/null", shell=True)

    cid = subprocess.run(
        f"""docker run -d \
            --name ueransim-ue-supi \
            --network thesis-5g_5gcore \
            --ip 10.10.0.41 \
            --privileged \
            -v {CONFIG_DIR}/ue-supi.yaml:/etc/ueransim/ue.yaml \
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
        "docker logs ueransim-ue-supi 2>&1",
        shell=True, capture_output=True, text=True
    ).stdout
    log(f"[*] UE logs:\n{logs[-500:]}")

    # PHASE 3: Stop capture
    log("\n[PHASE 3] Stopping capture...")
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)
    subprocess.run(f"docker cp open5gs-amf:/tmp/supi_harvest.pcap {CAPTURE_FILE}", shell=True)
    subprocess.run("docker rm -f ueransim-ue-supi 2>/dev/null", shell=True)

    # Verify pcap
    pkt_count = subprocess.run(
        f"tshark -r {CAPTURE_FILE} 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip()
    log(f"[*] Packets in capture: {pkt_count}")

    # PHASE 4: Analyze SUPI exposure
    log("\n[PHASE 4] Analyzing SUPI exposure...")

    # Method 1: verbose grep
    scheme_result = subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' -V 2>/dev/null "
        f"| grep -iE 'protection scheme|null scheme'",
        shell=True, capture_output=True, text=True
    ).stdout

    # Method 2: field extraction
    scheme_id_result = subprocess.run(
        f"tshark -r {CAPTURE_FILE} -d 'sctp.port==38412,ngap' "
        f"-T fields -e nas_5gs.mm.prot_scheme_id 2>/dev/null | grep -v '^$'",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    # Method 3: AMF logs
    amf_logs = subprocess.run(
        "docker logs open5gs-amf 2>&1 | grep -i 'suci\\|supi\\|protection' | tail -10",
        shell=True, capture_output=True, text=True
    ).stdout

    null_count = scheme_result.lower().count("null")
    null_from_field = scheme_id_result.count("0") if scheme_id_result else 0
    detected = null_count > 0 or null_from_field > 0

    log(f"[*] NULL scheme (verbose):  {null_count} times")
    log(f"[*] Scheme ID field values: {scheme_id_result or 'N/A'}")
    log(f"[*] AMF logs:\n{amf_logs}")

    with open(LOG_FILE, 'w') as f:
        f.write("=== PROTECTION SCHEME GREP ===\n")
        f.write(scheme_result)
        f.write("\n=== SCHEME ID FIELD VALUES ===\n")
        f.write(scheme_id_result + "\n")
        f.write("\n=== AMF LOGS ===\n")
        f.write(amf_logs)

    log("\n" + "=" * 60)
    log("SUPI HARVESTING RESULTS")
    log(f"NULL scheme detected: {null_count} times (verbose) / {null_from_field} times (field)")
    log("SUPI transmitted in plaintext! ✓" if detected else "No NULL scheme detected")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
