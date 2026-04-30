# On Enhancing 5G Security: Detection and Mitigation of Authentication Anomalies

This repository contains the complete implementation of a hybrid detection and mitigation framework for authentication anomalies in 5G standalone networks, grounded in the MITRE FiGHT threat taxonomy. The framework deploys a fully containerized 5G testbed, executes five authentication attack scenarios, and evaluates a hybrid rule-based and Random Forest detection pipeline on real AMF-level packet captures.

## Table of Contents

1. [Overview](#overview)
2. [Repository Structure](#repository-structure)
3. [System Requirements](#system-requirements)
4. [Installation](#installation)
5. [Testbed Setup](#testbed-setup)
6. [Subscriber Provisioning](#subscriber-provisioning)
7. [Connectivity Verification](#connectivity-verification)
8. [Attack Execution](#attack-execution)
9. [Detection Pipeline](#detection-pipeline)
10. [Monitoring Setup](#monitoring-setup)
11. [Results](#results)
12. [References](#references)

---

## Overview

### What this project does

- Deploys a fully containerized 5G standalone core using **Open5GS 2.6.6** and **UERANSIM 3.2.7**
- Implements **5 authentication attack scenarios** mapped to **MITRE FiGHT** techniques
- Extracts **15 behavioral features** from AMF-level packet captures using a sliding window approach
- Combines **deterministic rule-based logic** with a **Random Forest classifier** for hybrid detection
- Applies **automated mitigation** per attack class with confidence-based unknown pattern flagging
- Visualizes detection outcomes in real time via **Prometheus** and **Grafana**

### Attack Scenarios

| Attack | MITRE FiGHT ID | Observable Signal | Detection Method |
|--------|---------------|-------------------|-----------------|
| Brute-Force (high-rate) | FGT1110.001 | MAC failures >= 5 | Rule-based |
| Brute-Force (low-rate) | FGT1110.001 | MAC failures 1-4 | Random Forest |
| SUPI/IMSI Harvesting | FGT5019 | NULL SUCI scheme | Rule-based |
| Bidding-Down | FGT5004 | Reg rejects + SMC | Rule-based |
| Replay Attack | FGT1040 | SCTP ABORT | Rule-based |
| False Base Station | FGT1588.501 | Unauthorized NGSetup | Rule-based |
| Unknown Pattern | — | Low RF confidence | Random Forest |

---

## Repository Structure

### Directory Layout

```
thesis-5g/
├── attacks/
│   ├── brute_force.py              # FGT1110.001 - High-rate brute-force (10 attempts)
│   ├── brute_force_slow.py         # Low-rate brute-force variant (3 attempts, 15s interval)
│   ├── supi_harvest.py             # FGT5019 - SUPI/IMSI harvesting (null SUCI scheme)
│   ├── bidding_down.py             # FGT5004 - Bidding-down (null algorithms)
│   ├── replay_attack.py            # FGT1040 - Replay attack (SCTP RAND replay)
│   ├── false_bs.py                 # FGT1588.501 - False base station (rogue gNB)
│   ├── registration_storm.py       # Unknown/out-of-distribution traffic pattern
│   └── run_all.py                  # Run all attacks sequentially
├── detection/
│   ├── pipeline.py                 # End-to-end hybrid detection pipeline (MAIN SCRIPT)
│   ├── feature_extractor_sliding.py  # Sliding window feature extraction
│   ├── detector_final.py           # Standalone detector
│   └── mitigation.py               # Mitigation engine
├── captures/
│   └── test/                       # Unseen test pcap captures for evaluation
├── config/
│   ├── amf.yaml                    # AMF configuration (PLMN 001/01, TAC 1+99)
│   ├── smf.yaml                    # SMF configuration
│   ├── upf.yaml                    # UPF configuration
│   ├── gnb.yaml                    # Legitimate gNB (10.10.0.30, TAC 1)
│   ├── ue1.yaml                    # Legitimate UE 1 (IMSI: 001010000000001)
│   ├── ue2.yaml                    # Legitimate UE 2 (IMSI: 001010000000002)
│   ├── attacker.yaml               # Brute-force UE (IMSI: 099, wrong key FFFF...)
│   ├── ue-supi.yaml                # SUPI harvesting UE (IMSI: 003, null scheme)
│   ├── ue-bidding.yaml             # Bidding-down UE (IMSI: 004, null algorithms)
│   ├── rogue-gnb.yaml              # Rogue gNB (10.10.0.50, TAC 99)
│   └── prometheus.yml              # Prometheus scrape configuration
├── datasets/
│   ├── features.csv                # Raw extracted features (47 labeled windows)
│   └── master_dataset.csv          # SMOTE-augmented training dataset (600 samples)
├── docker-compose.yml              # Full testbed deployment (19 containers)
└── README.md
```

---

## System Requirements

### Hardware

- **RAM:** Minimum 8 GB (16 GB recommended)
- **CPU:** 4+ cores
- **Disk:** 20 GB free space

### Software

- **OS:** Ubuntu 22.04 LTS
- **Docker:** 24.0+
- **Docker Compose:** 2.0+
- **Python:** 3.8+
- **tshark:** 3.6+
- **Git**

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/NigarHajiyeva/On-Enhancing-5G-Security-Detection-Mitigation-of-Authentication-Anomalies.git
cd On-Enhancing-5G-Security-Detection-Mitigation-of-Authentication-Anomalies
```

### Step 2 — Install system dependencies

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 tshark python3-pip git
sudo usermod -aG docker $USER
newgrp docker
```

### Step 3 — Build custom UERANSIM image

The official UERANSIM Docker image does not support ECIES Profile A for SUCI concealment. Build from source at the exact tag used in this thesis:

```bash
git clone https://github.com/aligungr/UERANSIM.git
cd UERANSIM
git checkout v3.2.7
docker build -t ueransim-custom:3.2.7 .
cd ..
```

### Step 4 — Install Python dependencies

```bash
pip3 install pandas numpy scikit-learn imbalanced-learn joblib requests --break-system-packages
```

---

## Testbed Setup

### Network Architecture

The testbed deploys 19 Docker containers on a dedicated bridge network (`10.10.0.0/24`).

| Container | IP Address | Role |
|-----------|-----------|------|
| open5gs-nrf | 10.10.0.10 | Network Repository Function |
| open5gs-scp | 10.10.0.11 | Service Communication Proxy |
| open5gs-amf | 10.10.0.12 | Access and Mobility Management Function |
| open5gs-smf | 10.10.0.13 | Session Management Function |
| open5gs-upf | 10.10.0.14 | User Plane Function |
| open5gs-ausf | 10.10.0.15 | Authentication Server Function |
| open5gs-udm | 10.10.0.16 | Unified Data Management |
| open5gs-udr | 10.10.0.17 | Unified Data Repository |
| open5gs-pcf | 10.10.0.18 | Policy Control Function |
| open5gs-nssf | 10.10.0.19 | Network Slice Selection Function |
| open5gs-bsf | 10.10.0.20 | Binding Support Function |
| mongodb | 10.10.0.2 | Subscriber Repository |
| open5gs-webui | 10.10.0.3 | Web User Interface |
| ueransim-gnb | 10.10.0.30 | Legitimate gNB |
| ueransim-ue1 | 10.10.0.31 | Legitimate UE 1 |
| ueransim-ue2 | 10.10.0.32 | Legitimate UE 2 |
| prometheus | 10.10.0.60 | Metrics Scraper |
| grafana | 10.10.0.61 | Monitoring Dashboard |
| pushgateway | 10.10.0.70 | Pipeline Metrics Receiver |

### Starting the testbed

```bash
# Create Docker bridge network
docker network create --subnet=10.10.0.0/24 thesis-5g_5gcore

# Start all 19 containers
docker compose up -d

# Wait 90 seconds for NRF registration to complete
sleep 90

# Verify all containers are running
docker compose ps
```

All 19 containers must show `Up` status before proceeding.

### Troubleshooting startup issues

If gNB fails to connect after startup:

```bash
docker compose restart amf
sleep 15
docker compose restart gnb ue1 ue2
sleep 30
docker logs ueransim-gnb 2>&1 | tail -5
```

If SCP or NRF connection errors appear:

```bash
docker compose down
sleep 5
docker compose up -d
sleep 90
```

---

## Subscriber Provisioning

### Subscriber Profile Map

| IMSI | Config File | Role | Key |
|------|-------------|------|-----|
| 001010000000001 | ue1.yaml | Legitimate UE 1 | Correct (465B...) |
| 001010000000002 | ue2.yaml | Legitimate UE 2 | Correct (465B...) |
| 001010000000003 | ue-supi.yaml | SUPI Harvesting UE | Correct + null scheme |
| 001010000000004 | ue-bidding.yaml | Bidding-Down UE | Correct + null algorithms |
| 001010000000005 | ue-rogue.yaml | False Base Station UE | Correct |
| 001010000000006 | ue-supi3.yaml | SUPI Harvesting UE 3 | Correct + null scheme |
| 001010000000099 | attacker.yaml | Brute-Force Attacker | Wrong key (FFFF...) |

### Provisioning all subscribers

```bash
docker exec mongodb mongosh open5gs --eval '
db.subscribers.insertMany([
  {
    imsi: "001010000000001",
    security: { k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
                opc: "E8ED289DEBA952E4283B54E88E6183CA",
                amf: "8000", sqn: NumberLong("0") },
    ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
    slice: [{ sst: 1, sd: "000001", default_indicator: true,
      session: [{ name: "internet", type: 3,
        ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
        qos: { index: 9, arp: { priority_level: 8,
          pre_emption_capability: 1, pre_emption_vulnerability: 1 } } }] }]
  },
  {
    imsi: "001010000000002",
    security: { k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
                opc: "E8ED289DEBA952E4283B54E88E6183CA",
                amf: "8000", sqn: NumberLong("0") },
    ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
    slice: [{ sst: 1, sd: "000001", default_indicator: true,
      session: [{ name: "internet", type: 3,
        ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
        qos: { index: 9, arp: { priority_level: 8,
          pre_emption_capability: 1, pre_emption_vulnerability: 1 } } }] }]
  },
  {
    imsi: "001010000000003",
    security: { k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
                opc: "E8ED289DEBA952E4283B54E88E6183CA",
                amf: "8000", sqn: NumberLong("0") },
    ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
    slice: [{ sst: 1, sd: "000001", default_indicator: true,
      session: [{ name: "internet", type: 3,
        ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
        qos: { index: 9, arp: { priority_level: 8,
          pre_emption_capability: 1, pre_emption_vulnerability: 1 } } }] }]
  },
  {
    imsi: "001010000000004",
    security: { k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
                opc: "E8ED289DEBA952E4283B54E88E6183CA",
                amf: "8000", sqn: NumberLong("0") },
    ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
    slice: [{ sst: 1, sd: "000001", default_indicator: true,
      session: [{ name: "internet", type: 3,
        ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
        qos: { index: 9, arp: { priority_level: 8,
          pre_emption_capability: 1, pre_emption_vulnerability: 1 } } }] }]
  },
  {
    imsi: "001010000000005",
    security: { k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
                opc: "E8ED289DEBA952E4283B54E88E6183CA",
                amf: "8000", sqn: NumberLong("0") },
    ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
    slice: [{ sst: 1, sd: "000001", default_indicator: true,
      session: [{ name: "internet", type: 3,
        ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
        qos: { index: 9, arp: { priority_level: 8,
          pre_emption_capability: 1, pre_emption_vulnerability: 1 } } }] }]
  },
  {
    imsi: "001010000000006",
    security: { k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
                opc: "E8ED289DEBA952E4283B54E88E6183CA",
                amf: "8000", sqn: NumberLong("0") },
    ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
    slice: [{ sst: 1, sd: "000001", default_indicator: true,
      session: [{ name: "internet", type: 3,
        ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
        qos: { index: 9, arp: { priority_level: 8,
          pre_emption_capability: 1, pre_emption_vulnerability: 1 } } }] }]
  },
  {
    imsi: "001010000000099",
    security: { k: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                opc: "E8ED289DEBA952E4283B54E88E6183CA",
                amf: "8000", sqn: NumberLong("0") },
    ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
    slice: [{ sst: 1, sd: "000001", default_indicator: true,
      session: [{ name: "internet", type: 3,
        ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
        qos: { index: 9, arp: { priority_level: 8,
          pre_emption_capability: 1, pre_emption_vulnerability: 1 } } }] }]
  }
]);
print("Done!");' 2>/dev/null
```

> **Note:** IMSI `001010000000099` uses an intentionally incorrect key (`FFFF...`) to simulate a brute-force attacker. IMSI `001010000000003` uses null SUCI protection scheme for SUPI harvesting simulation.

---

## Connectivity Verification

Before running any attack, verify the testbed is fully operational.

### Check gNB connection

```bash
docker logs ueransim-gnb 2>&1 | grep "NG Setup procedure is successful"
# Expected: [ngap] [info] NG Setup procedure is successful
```

### Check UE registration

```bash
docker logs open5gs-amf 2>&1 | grep "SUPI" | tail -4
# Expected:
# UE SUPI[imsi-001010000000001] is registered
# UE SUPI[imsi-001010000000002] is registered
```

### Check NRF subscription

```bash
docker logs open5gs-amf 2>&1 | grep "Subscription created" | tail -2
# Expected: Subscription created until <date>
```

---

## Attack Execution

Each attack script automatically handles the full experimental cycle:
1. Resets stateful parameters (e.g. SQN in MongoDB)
2. Starts `tcpdump` on AMF `eth0` interface
3. Executes the attack
4. Stops capture and copies `.pcap` to `captures/test/`
5. Analyzes and reports results

### Brute-Force Authentication (FGT1110.001)

```bash
python3 attacks/brute_force.py
```

Runs 10 authentication attempts using IMSI `001010000000099` with wrong key `FFFF...`.

Expected output:

```
MAC failures (log):    10
Auth rejects (log):    10
Auth fail (pcap):      10
Attack DETECTED ✓
Capture: captures/test/brute_force.pcap
```

### Low-Rate Brute-Force

```bash
python3 attacks/brute_force_slow.py
```

3 attempts with 15-second intervals. Falls below the rule threshold — detected by Random Forest.

Expected output:

```
MAC failures so far: 3
Attack DETECTED ✓
Capture: captures/test/brute_force_slow.pcap
```

### SUPI/IMSI Harvesting (FGT5019)

```bash
python3 attacks/supi_harvest.py
```

Uses IMSI `001010000000003` with `protectionScheme: 0`. Raw SUPI transmitted in plaintext.

Expected output:

```
NULL scheme detected: 1 times
SUPI transmitted in plaintext!
Capture: captures/test/supi_harvest.pcap
```

### Bidding-Down Attack (FGT5004)

```bash
python3 attacks/bidding_down.py
```

Uses IMSI `001010000000004` with only NIA0/NEA0 advertised. AMF rejects registration.

Expected output:

```
PCap rejects (UE security mismatch): 4
AMF rejected NULL algorithms!
Capture: captures/test/bidding_down.pcap
```

### Replay Attack (FGT1040)

```bash
sudo python3 attacks/replay_attack.py
```

> Requires root privileges for raw SCTP socket access.

Captures legitimate RAND value and replays it. AMF detects SQN mismatch and sends SCTP ABORT.

Expected output:

```
RAND extracted: <32-char hex>
Replay sent
AMF SCTP ABORT: Replay detected - SQN validation triggered
Capture: captures/test/replay_capture.pcap
```

### False Base Station (FGT1588.501)

```bash
python3 attacks/false_bs.py
```

Deploys rogue gNB at `10.10.0.50` (TAC 99). Establishes NGSetup from unauthorized IP.

Expected output:

```
Rogue gNB NG Setup accepted: YES
UE Authentication via rogue gNB: YES
Attack DETECTED
Capture: captures/test/false_bs.pcap
```

### Registration Storm (unknown pattern)

```bash
python3 attacks/registration_storm.py
```

Rapid legitimate registrations — out-of-distribution pattern flagged as unknown by pipeline.

Expected output:

```
Packets: 301
Capture: captures/test/unknown_attack.pcap
```

### Run All Attacks

```bash
python3 attacks/run_all.py
```

---

## Detection Pipeline

### How it works

```
Input: pcap file
  │
  ├── Full-pcap pre-checks
  │     ├── SCTP ABORT scan      (replay detection)
  │     ├── Auth failure count   (brute-force across windows)
  │     └── NGSetup IP check     (false base station)
  │
  ├── Sliding window feature extraction
  │     ├── Window size: 30 seconds
  │     ├── Step size:   10 seconds
  │     └── 15 features per window
  │
  ├── Best window selection (priority scoring)
  │
  ├── Rule-based classification (Stage 1)
  │     ├── suci_unencrypted == 1          → supi_harvest
  │     ├── reg_rejects >= 1 AND           → bidding_down
  │     │   sec_mode_cmds >= 1
  │     ├── auth_failures >= 5             → brute_force
  │     ├── sctp_abort >= 1                → replay
  │     └── ng_setup_req == 99             → false_bs
  │
  └── Random Forest (Stage 2, if no rule match)
        ├── confidence >= 0.65  → predicted class
        └── confidence <  0.65  → unknown (operator alert)
```

### Running the pipeline

Place test pcap files in `captures/test/`. The pipeline auto-discovers all `.pcap` files:

```bash
python3 detection/pipeline.py
```

### Expected pipeline output

```
Capture              Detected         Method     Conf     Time
--------------------------------------------------------------
bidding_down         bidding_down     rule       1.00    20.5s
brute_force          brute_force      rule       1.00    78.6s
brute_force_slow     brute_force      rf         0.77    32.6s
false_bs             false_bs         rule       1.00    33.3s
normal_traffic       normal           rf         0.79    25.1s
replay_capture       replay           rule       1.00    33.8s
supi_harvest         supi_harvest     rule       1.00    17.2s
unknown_attack       unknown          rf         0.54    17.0s

Total captures: 8   Avg response time: 32.3s
```

---

## Monitoring Setup

### Prometheus

Access: `http://localhost:9090`

Scrapes AMF metrics every 5 seconds. Key metrics:

| Metric | Description |
|--------|-------------|
| `fivegs_amffunction_rm_reginitreq` | Total registration requests |
| `fivegs_amffunction_amf_authreq` | Total authentication requests |
| `fivegs_amffunction_amf_authfail` | Authentication failures (MAC) |
| `detection_confidence` | Detection confidence per capture |
| `detection_prediction` | Predicted class (0=normal, 1=brute_force, 2=supi_harvest, 3=bidding_down, 4=replay, 5=false_bs, -1=unknown) |
| `detection_response_time` | End-to-end response time (seconds) |

### Grafana Setup

Access: `http://localhost:3000`
Credentials: `admin` / `12345`

#### Step 1 — Add Prometheus datasource

```bash
curl -s -X POST http://admin:12345@localhost:3000/api/datasources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Prometheus",
    "type": "prometheus",
    "url": "http://10.10.0.60:9090",
    "access": "proxy",
    "isDefault": true
  }'
```

#### Step 2 — Get datasource UID

```bash
curl -s http://admin:12345@localhost:3000/api/datasources \
  | python3 -m json.tool | grep uid
```

Note the `uid` value — needed for dashboard creation.

#### Step 3 — Create dashboard

Replace `YOUR_DS_UID` with the uid from Step 2:

```bash
curl -s -X POST http://admin:12345@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d '{
    "dashboard": {
      "title": "5G Authentication Anomaly Detection",
      "timezone": "browser",
      "panels": [
        {
          "id": 1,
          "title": "Detection Confidence per Capture",
          "type": "bargauge",
          "gridPos": {"h": 10, "w": 24, "x": 0, "y": 0},
          "fieldConfig": {
            "defaults": {
              "min": 0, "max": 1, "unit": "percentunit",
              "thresholds": {"mode": "absolute", "steps": [
                {"color": "red",    "value": null},
                {"color": "yellow", "value": 0.65},
                {"color": "green",  "value": 0.85}
              ]}
            }
          },
          "options": {
            "orientation": "horizontal",
            "reduceOptions": {"calcs": ["lastNotNull"]},
            "displayMode": "gradient",
            "showUnfilled": true
          },
          "targets": [{"expr": "detection_confidence",
                       "legendFormat": "{{capture}}", "instant": true}],
          "datasource": {"type": "prometheus", "uid": "YOUR_DS_UID"}
        },
        {
          "id": 2,
          "title": "Detected Attack Class",
          "type": "stat",
          "gridPos": {"h": 10, "w": 12, "x": 0, "y": 10},
          "fieldConfig": {
            "defaults": {
              "mappings": [
                {"type": "value", "options": {"0":  {"text": "Normal",       "color": "green"}}},
                {"type": "value", "options": {"1":  {"text": "Brute Force",  "color": "red"}}},
                {"type": "value", "options": {"2":  {"text": "SUPI Harvest", "color": "orange"}}},
                {"type": "value", "options": {"3":  {"text": "Bidding Down", "color": "orange"}}},
                {"type": "value", "options": {"4":  {"text": "Replay",       "color": "red"}}},
                {"type": "value", "options": {"5":  {"text": "False BS",     "color": "red"}}},
                {"type": "value", "options": {"-1": {"text": "Unknown",      "color": "purple"}}}
              ],
              "thresholds": {"mode": "absolute",
                             "steps": [{"color": "blue", "value": null}]}
            }
          },
          "options": {"reduceOptions": {"calcs": ["lastNotNull"]},
                      "colorMode": "background"},
          "targets": [{"expr": "detection_prediction",
                       "legendFormat": "{{capture}}", "instant": true}],
          "datasource": {"type": "prometheus", "uid": "YOUR_DS_UID"}
        },
        {
          "id": 3,
          "title": "End-to-End Response Time (s)",
          "type": "bargauge",
          "gridPos": {"h": 10, "w": 12, "x": 12, "y": 10},
          "fieldConfig": {
            "defaults": {
              "unit": "s", "min": 0,
              "thresholds": {"mode": "absolute", "steps": [
                {"color": "green",  "value": null},
                {"color": "yellow", "value": 30},
                {"color": "red",    "value": 60}
              ]}
            }
          },
          "options": {
            "orientation": "horizontal",
            "reduceOptions": {"calcs": ["lastNotNull"]},
            "displayMode": "gradient",
            "showUnfilled": true
          },
          "targets": [{"expr": "detection_response_time",
                       "legendFormat": "{{capture}}", "instant": true}],
          "datasource": {"type": "prometheus", "uid": "YOUR_DS_UID"}
        }
      ],
      "time": {"from": "now-5y", "to": "now"},
      "refresh": "30s"
    },
    "overwrite": true,
    "folderId": 0
  }'
```

---

## Results

### Detection Accuracy

| Configuration | Accuracy |
|--------------|----------|
| Rule-based only | 80.0% |
| Random Forest only | 85.7% |
| **Hybrid (Rules + RF)** | **88.6%** |
| Cross-validation (training set) | 96.7% ± 1.8% |

### End-to-End Pipeline Results

| Capture | Detected | Method | Confidence | Response Time |
|---------|----------|--------|------------|---------------|
| normal_traffic | normal | Random Forest | 0.79 | 25.1s |
| brute_force | brute_force | Rule-based | 1.00 | 78.6s |
| brute_force_slow | brute_force | Random Forest | 0.77 | 32.6s |
| supi_harvest | supi_harvest | Rule-based | 1.00 | 17.2s |
| bidding_down | bidding_down | Rule-based | 1.00 | 20.5s |
| replay_capture | replay | Rule-based | 1.00 | 33.8s |
| false_bs | false_bs | Rule-based | 1.00 | 33.3s |
| unknown_attack | unknown | Random Forest | 0.54 | 17.0s |

**Average response time:** 32.3s | **End-to-end accuracy:** 100%

---

## References

- [Open5GS](https://open5gs.org)
- [UERANSIM](https://github.com/aligungr/UERANSIM)
- [MITRE FiGHT](https://fight.mitre.org)
- [3GPP TS 33.501](https://www.3gpp.org/dynareport/33501.htm)
- [3GPP TS 23.501](https://www.3gpp.org/dynareport/23501.htm)

---

## PORTAL_METADATA

```portal
slug: on-enhancing-5g-security-detection-mitigation
title: On Enhancing 5G Security: Detection and Mitigation of Authentication Anomalies
summary: A hybrid rule-based and Random Forest detection framework for 5G authentication anomalies, implemented on a fully containerized Open5GS and UERANSIM testbed with MITRE FiGHT-aligned attack scenarios and automated mitigation.
startDate: 2026-01-15
endDate: 2026-04-30
repositoryUrl: https://github.com/NigarHajiyeva/On-Enhancing-5G-Security-Detection-Mitigation-of-Authentication-Anomalies
logos:
  - open5gs.png
  - ueransim.png
```

