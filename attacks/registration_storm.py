#!/usr/bin/env python3
"""
Registration Storm - Unknown Attack Pattern
Multiple rapid UE registrations - not in training data
"""
import subprocess
import time
import os

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CAPTURE_FILE = os.path.join(BASE_DIR, "captures", "test", "unknown_attack.pcap")
CONFIG_DIR   = os.path.join(BASE_DIR, "config")
ATTEMPTS     = 8

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def main():
    os.makedirs(os.path.join(BASE_DIR, "captures", "test"), exist_ok=True)

    log("=" * 60)
    log("REGISTRATION STORM - Unknown Attack Pattern")
    log(f"Attempts: {ATTEMPTS} | Method: Rapid legitimate registrations")
    log("=" * 60)

    # Start capture
    log("[*] Starting capture...")
    subprocess.run("docker exec open5gs-amf rm -f /tmp/unknown_attack.pcap", shell=True)
    subprocess.Popen(
        "docker exec open5gs-amf tcpdump -i eth0 -w /tmp/unknown_attack.pcap",
        shell=True
    )
    time.sleep(3)

    # Rapid UE registrations with legitimate config
    log("[*] Launching rapid registrations...")
    cids = []
    for i in range(1, ATTEMPTS + 1):
        log(f"[*] UE {i}/{ATTEMPTS}...")
        cid = subprocess.run(
            f"docker run -d --network thesis-5g_5gcore --privileged "
            f"-v {CONFIG_DIR}/ue1.yaml:/etc/ueransim/ue.yaml "
            f"ueransim-custom:3.2.7 ue /etc/ueransim/ue.yaml",
            shell=True, capture_output=True, text=True
        ).stdout.strip()
        if cid:
            cids.append(cid)
        time.sleep(2)

    time.sleep(10)

    # Cleanup
    for cid in cids:
        subprocess.run(f"docker rm -f {cid} 2>/dev/null", shell=True)

    # Stop capture
    log("[*] Stopping capture...")
    subprocess.run("docker exec open5gs-amf pkill tcpdump", shell=True)
    time.sleep(5)
    subprocess.run(
        f"docker cp open5gs-amf:/tmp/unknown_attack.pcap {CAPTURE_FILE}",
        shell=True
    )

    pkt_count = subprocess.run(
        f"tshark -r {CAPTURE_FILE} 2>/dev/null | wc -l",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    log(f"[*] Packets: {pkt_count}")
    log(f"[*] Capture: {CAPTURE_FILE}")
    log("[*] Done — run pipeline to see RF classification")

if __name__ == "__main__":
    main()
