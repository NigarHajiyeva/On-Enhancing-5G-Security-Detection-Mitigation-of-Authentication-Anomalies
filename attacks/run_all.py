#!/usr/bin/env python3
"""
Master Attack Runner
Thesis: On Enhancing 5G Security
Runs all 5 attacks sequentially with cleanup between each
"""
import subprocess
import time
import os
import json

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ATTACKS_DIR  = os.path.join(BASE_DIR, "attacks")
LOG_FILE     = os.path.join(BASE_DIR, "logs", "master_run.log")
COMPOSE_FILE = os.path.join(BASE_DIR, "docker-compose.yml")

def log(msg):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, 'a') as f:
        f.write(line + "\n")

def cleanup():
    log("[CLEANUP] Removing leftover attack containers...")
    containers = [
        "ueransim-ue-supi",
        "ueransim-ue-bidding",
        "ueransim-ue-rogue",
        "ueransim-rogue-gnb"
    ]
    for c in containers:
        subprocess.run(f"docker rm -f {c} 2>/dev/null", shell=True)
    log("[CLEANUP] Done.")

def restart_baseline():
    log("[BASELINE] Restarting gnb + ue1 + ue2 to restore normal state...")
    subprocess.run(
        f"docker compose -f {COMPOSE_FILE} restart gnb",
        shell=True, capture_output=True
    )
    time.sleep(15)
    subprocess.run(
        f"docker compose -f {COMPOSE_FILE} restart ue1 ue2",
        shell=True, capture_output=True
    )
    time.sleep(40)
    result = subprocess.run(
        "docker logs open5gs-amf 2>&1 | grep 'SUPI' | tail -2",
        shell=True, capture_output=True, text=True
    ).stdout
    log(f"[BASELINE] AMF status:\n{result}")

def get_metrics():
    metrics = {}
    queries = {
        "reg_init_req":  "fivegs_amffunction_rm_reginitreq",
        "reg_init_succ": "fivegs_amffunction_rm_reginitsucc",
        "reg_init_fail": "fivegs_amffunction_rm_reginitfail",
        "auth_req":      "fivegs_amffunction_amf_authreq",
        "auth_reject":   "fivegs_amffunction_amf_authreject",
        "auth_fail":     "fivegs_amffunction_amf_authfail",
    }
    for name, query in queries.items():
        result = subprocess.run(
            f'curl -s "http://localhost:9090/api/v1/query?query={query}"',
            shell=True, capture_output=True, text=True
        ).stdout
        try:
            data = json.loads(result)
            if data["data"]["result"]:
                metrics[name] = float(data["data"]["result"][0]["value"][1])
            else:
                metrics[name] = 0.0
        except:
            metrics[name] = 0.0
    return metrics

def run_attack(name, script, use_sudo=False):
    log("=" * 60)
    log(f"STARTING ATTACK: {name}")
    log("=" * 60)

    before = get_metrics()
    log(f"[METRICS BEFORE] reg_req={before['reg_init_req']} "
        f"auth_req={before['auth_req']} "
        f"auth_fail={before['auth_fail']} "
        f"reg_fail={before['reg_init_fail']}")

    prefix = "sudo " if use_sudo else ""
    subprocess.run(
        f"{prefix}python3 {os.path.join(ATTACKS_DIR, script)}",
        shell=True
    )

    after = get_metrics()
    log(f"[METRICS AFTER]  reg_req={after['reg_init_req']} "
        f"auth_req={after['auth_req']} "
        f"auth_fail={after['auth_fail']} "
        f"reg_fail={after['reg_init_fail']}")

    log(f"[DELTA] reg_req=+{after['reg_init_req']-before['reg_init_req']:.0f} "
        f"auth_req=+{after['auth_req']-before['auth_req']:.0f} "
        f"auth_fail=+{after['auth_fail']-before['auth_fail']:.0f} "
        f"reg_fail=+{after['reg_init_fail']-before['reg_init_fail']:.0f}")

    log(f"ATTACK COMPLETED: {name}")
    log("=" * 60)

    cleanup()
    time.sleep(10)
    restart_baseline()
    time.sleep(15)

def main():
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)

    with open(LOG_FILE, 'w') as f:
        f.write("")

    log("=" * 60)
    log("MASTER ATTACK RUNNER")
    log("Thesis: On Enhancing 5G Security")
    log(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 60)

    cleanup()

    log("\n[INIT] Verifying baseline...")
    restart_baseline()

    attacks = [
        ("SUPI Harvesting    - FGT5019",     "supi_harvest.py",  False),
        ("Bidding Down       - FGT5004",     "bidding_down.py",  False),
        ("Brute Force        - FGT1110.001", "brute_force.py",   False),
        ("Replay Attack      - FGT1040",     "replay_attack.py", True),
        ("False Base Station - FGT1588.501", "false_bs.py",      False),
    ]

    results = []
    for name, script, use_sudo in attacks:
        run_attack(name, script, use_sudo)
        results.append(name)
        time.sleep(20)

    log("\n" + "=" * 60)
    log("ALL ATTACKS COMPLETED")
    log("=" * 60)
    for r in results:
        log(f"  ✓ {r}")
    log("=" * 60)
    log(f"[*] Master log: {LOG_FILE}")
    log(f"[*] Check Grafana:  http://localhost:3000")
    log(f"[*] Prometheus:     http://localhost:9090")

if __name__ == "__main__":
    main()
