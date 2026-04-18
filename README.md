# 5G Security Testbed — Attack Simulation & Hybrid Detection Framework

> Open5GS 2.6.6 + UERANSIM 3.2.7 · 5 MITRE FiGHT attacks · Hybrid ML detection · Prometheus + Grafana

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Running the Attacks](#running-the-attacks)
6. [Detection Pipeline](#detection-pipeline)
7. [Monitoring](#monitoring)
8. [Project Structure](#project-structure)
9. [Network & Subscriber Reference](#network--subscriber-reference)
10. [Troubleshooting](#troubleshooting)

---

## Overview

A Docker-based 5G network security framework for simulating, detecting, and mitigating authentication anomalies. Five attack techniques mapped to the **MITRE FiGHT** framework are implemented against a software-defined 5G core, and a hybrid detection pipeline (deterministic rules + Random Forest) achieves **88.6% accuracy** on real unseen captures and **100% accuracy** in the end-to-end pipeline.

| Attack | FiGHT ID | Method |
|--------|----------|--------|
| Brute-force Authentication | FGT1110.001 | Wrong cryptographic key (10 attempts) |
| SUPI/IMSI Harvesting | FGT5019 | NULL SUCI protection scheme |
| Bidding-down | FGT5004 | UE advertises NULL security algorithms |
| Replay Attack | FGT1040 | Captured RAND replayed via SCTP |
| False Base Station | FGT1588.501 | Rogue gNB accepted by AMF |

---

## Architecture

![5G Testbed Architecture](architecture.svg)

---

## Prerequisites

- Ubuntu 22.04 (tested on VMware Workstation)
- Docker Engine 24+ and Docker Compose v2
- Python 3.10+
- tshark / Wireshark
- 8 GB RAM, 4 CPU cores, 40 GB disk minimum

```bash
sudo apt update && sudo apt install -y \
  docker.io docker-compose-v2 \
  python3 python3-pip \
  tshark wireshark \
  git curl

sudo usermod -aG docker $USER
newgrp docker

pip install -r requirements.txt
pip install scapy   # required for replay attack
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/NigarHajiyeva/On-Enhancing-5G-Security-Detection-Mitigation-of-Authentication-Anomalies.git
cd On-Enhancing-5G-Security-Detection-Mitigation-of-Authentication-Anomalies
```

### 2. Build the custom UERANSIM image

UERANSIM must be built from source to support ECIES Profile A:

```bash
git clone https://github.com/aligungr/UERANSIM.git
cd UERANSIM && git checkout v3.2.7
docker build -t ueransim-custom:3.2.7 .
cd ..
```

### 3. Create required directories

```bash
mkdir -p captures logs datasets
```

### 4. Start the 5G core

```bash
docker compose up -d
sleep 60
docker compose ps
```

All containers should show status `Up`.

### 5. Add subscribers to MongoDB

```bash
docker exec mongodb mongosh open5gs --eval '
db.subscribers.insertMany([
  {imsi:"001010000000001",msisdn:[],security:{k:"465B5CE8B199B49FAA5F0A2EE238A6BC",op:null,opc:"E8ED289DEBA952E4283B54E88E6183CA",amf:"8000",sqn:NumberLong("0")},ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},slice:[{sst:1,sd:"000001",default_indicator:true,session:[{name:"internet",type:3,ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},qos:{index:9,arp:{priority_level:8,pre_emption_capability:1,pre_emption_vulnerability:1}}}]}],access_restriction_data:32,subscriber_status:0,operator_determined_barring:0,network_access_mode:0,schema_version:1},
  {imsi:"001010000000002",msisdn:[],security:{k:"465B5CE8B199B49FAA5F0A2EE238A6BC",op:null,opc:"E8ED289DEBA952E4283B54E88E6183CA",amf:"8000",sqn:NumberLong("0")},ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},slice:[{sst:1,sd:"000001",default_indicator:true,session:[{name:"internet",type:3,ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},qos:{index:9,arp:{priority_level:8,pre_emption_capability:1,pre_emption_vulnerability:1}}}]}],access_restriction_data:32,subscriber_status:0,operator_determined_barring:0,network_access_mode:0,schema_version:1},
  {imsi:"001010000000003",msisdn:[],security:{k:"465B5CE8B199B49FAA5F0A2EE238A6BC",op:null,opc:"E8ED289DEBA952E4283B54E88E6183CA",amf:"8000",sqn:NumberLong("0")},ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},slice:[{sst:1,sd:"000001",default_indicator:true,session:[{name:"internet",type:3,ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},qos:{index:9,arp:{priority_level:8,pre_emption_capability:1,pre_emption_vulnerability:1}}}]}],access_restriction_data:32,subscriber_status:0,operator_determined_barring:0,network_access_mode:0,schema_version:1},
  {imsi:"001010000000004",msisdn:[],security:{k:"465B5CE8B199B49FAA5F0A2EE238A6BC",op:null,opc:"E8ED289DEBA952E4283B54E88E6183CA",amf:"8000",sqn:NumberLong("0")},ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},slice:[{sst:1,sd:"000001",default_indicator:true,session:[{name:"internet",type:3,ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},qos:{index:9,arp:{priority_level:8,pre_emption_capability:1,pre_emption_vulnerability:1}}}]}],access_restriction_data:32,subscriber_status:0,operator_determined_barring:0,network_access_mode:0,schema_version:1},
  {imsi:"001010000000005",msisdn:[],security:{k:"465B5CE8B199B49FAA5F0A2EE238A6BC",op:null,opc:"E8ED289DEBA952E4283B54E88E6183CA",amf:"8000",sqn:NumberLong("0")},ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},slice:[{sst:1,sd:"000001",default_indicator:true,session:[{name:"internet",type:3,ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},qos:{index:9,arp:{priority_level:8,pre_emption_capability:1,pre_emption_vulnerability:1}}}]}],access_restriction_data:32,subscriber_status:0,operator_determined_barring:0,network_access_mode:0,schema_version:1},
  {imsi:"001010000000099",msisdn:[],security:{k:"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",op:null,opc:"E8ED289DEBA952E4283B54E88E6183CA",amf:"8000",sqn:NumberLong("0")},ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},slice:[{sst:1,sd:"000001",default_indicator:true,session:[{name:"internet",type:3,ambr:{downlink:{value:1,unit:3},uplink:{value:1,unit:3}},qos:{index:9,arp:{priority_level:8,pre_emption_capability:1,pre_emption_vulnerability:1}}}]}],access_restriction_data:32,subscriber_status:0,operator_determined_barring:0,network_access_mode:0,schema_version:1}
]);print("Done!");' 2>/dev/null
```

### 6. Verify UE connectivity

```bash
docker logs ueransim-ue1 --tail 5
# Expected: PDU Session establishment is successful
#           TUN interface[uesimtun0, 10.45.0.x] is up
```

---

## Running the Attacks

Each script starts a tcpdump capture inside the AMF container, runs the attack, and saves the resulting pcap to `captures/`.

### Attack 1 — Brute-force (FGT1110.001)

Reset SQN before each run:

```bash
docker exec mongodb mongosh open5gs --eval '
db.subscribers.updateOne(
  {imsi: "001010000000099"},
  {$set: {"security.sqn": NumberLong("0")}}
);print("Done!");' 2>/dev/null

python3 attacks/brute_force.py
```

Expected:
```
Total attempts:    10
AMF MAC failures:  10
AMF Auth rejects:  10
Attack DETECTED ✓
```

### Attack 2 — SUPI Harvesting (FGT5019)

```bash
python3 attacks/supi_harvest.py
```

Verify:
```bash
tshark -r captures/supi_harvest.pcap -d "sctp.port==38412,ngap" -V 2>/dev/null \
  | grep -A2 "Protection scheme"
# Protection scheme Id: NULL scheme (0)
# MSIN: 0000000003
```

### Attack 3 — Bidding-down (FGT5004)

```bash
python3 attacks/bidding_down.py
```

Expected:
```
PCap rejects (UE security mismatch): 3-4
AMF log rejects: 4
AMF rejected NULL algorithms! ✓
```

### Attack 4 — Replay (FGT1040)

```bash
sudo python3 attacks/replay_attack.py
```

Expected:
```
RAND extracted: <32-char hex>
Replay sent: ✓
AMF SCTP ABORT: ✓ Replay detected — SQN validation triggered
```

### Attack 5 — False Base Station (FGT1588.501)

```bash
python3 attacks/false_bs.py
```

Expected:
```
Rogue gNB NG Setup accepted:     YES ✓
UE Authentication via rogue gNB: YES ✓
```

### Run all attacks sequentially

```bash
python3 attacks/run_all.py
```

---

## Detection Pipeline

### Step 1 — Feature Extraction

Extracts 15 features from 30-second sliding windows (10-second step, 66% overlap):

```bash
python3 detection/feature_extractor_sliding.py
# → datasets/features_sliding.csv
```

| Feature | Source |
|---------|--------|
| `total_packets` | All NGAP/SCTP packets in window |
| `auth_requests` | NAS type `0x56` |
| `auth_failures` | NAS type `0x59` — MAC failure |
| `reg_requests` | NAS type `0x41` |
| `reg_rejects` | NAS type `0x44` |
| `sec_mode_cmds` | NAS type `0x5D` |
| `ng_setup_req` | NGAP procedureCode `21` |
| `suci_unencrypted` | NULL scheme + source IP `10.10.0.41` |
| `sctp_abort` | `sctp.chunk_type == 6` (no NGAP decode) |
| `rand_repeat` | Duplicate RAND values in window |
| `auth_rate` | auth_requests / duration |
| `reg_rate` | reg_requests / duration |
| `reject_rate` | reg_rejects / max(reg_requests, 1) |
| `auth_success_rate` | (auth − rejects) / max(auth, 1) |
| `duration` | Window length in seconds |

### Step 2 — Dataset Generation (SMOTE)

```bash
python3 detection/synthetic_data.py
# → datasets/master_dataset.csv (600 samples, 100 per class, k=2)
```

### Step 3 — Train & Evaluate

```bash
python3 detection/detector_final.py
```

```
Simple Rule-based:    80.0%
Advanced Rule-based:  80.0%
Random Forest:        85.7%   (200 trees, max_depth=10, balanced)
Hybrid Pipeline:      88.6%
CV Score (train):     96.7% ± 1.8%
```

Per-class F1 scores (Hybrid):

| Class | F1 |
|-------|----|
| bidding_down | 1.00 |
| brute_force | 0.98 |
| replay | 1.00 |
| false_bs | 0.75 |
| supi_harvest | 0.67 |
| normal | 0.60 |

### Step 4 — End-to-End Pipeline

```bash
python3 detection/pipeline.py
```

```
normal       → normal        ✓
brute_force  → brute_force   ✓
supi_harvest → supi_harvest  ✓
bidding_down → bidding_down  ✓
replay       → replay        ✓
false_bs     → false_bs      ✓

Pipeline accuracy:  100.0%
Avg response time:  ~14s
```

### Hybrid Detection Logic

Deterministic rules are applied first; ambiguous cases fall through to Random Forest:

```
suci_unencrypted == 1                    → supi_harvest
reg_rejects >= 1 AND sec_mode_cmds >= 1  → bidding_down
auth_failures > 0                        → brute_force
sctp_abort == 1                          → replay
ng_setup_req == 99 (rogue IP detected)   → false_bs
else                                     → Random Forest
```

Full-pcap checks run before window-level detection:
- **SCTP ABORT**: scanned across the entire pcap (not just the best window)
- **Rogue gNB**: NGSetup source IPs checked against known IPs (`10.10.0.30`, `10.10.0.12`)

Best window is selected by priority score:
```python
score = suci_unencrypted * 1000 + sctp_abort * 1000 +
        auth_failures * 500 + reg_rejects * 300 +
        sec_mode_cmds * 200 + ng_setup_req * 150 +
        auth_requests * 2 + total_packets
```

### Mitigation Actions

| Attack | Action |
|--------|--------|
| `brute_force` | Attacker UE container removed, rate limiting applied |
| `supi_harvest` | NULL scheme rejected, SUCI encryption enforced |
| `bidding_down` | NIA0/NEA0 registration blocked |
| `replay` | SQN strict mode, RAND replay detection |
| `false_bs` | Rogue gNB container removed, IP flagged |

---

## Monitoring

### Start monitoring stack

```bash
cat > /tmp/prom.yml << EOF
global:
  scrape_interval: 5s
scrape_configs:
  - job_name: 'open5gs-amf'
    fallback_scrape_protocol: PrometheusText0.0.4
    static_configs:
      - targets: ['10.10.0.12:9090']
  - job_name: 'pushgateway'
    honor_labels: true
    static_configs:
      - targets: ['10.10.0.70:9091']
EOF

docker run -d --name prometheus --network thesis-5g_5gcore \
  --ip 10.10.0.60 -p 9091:9090 \
  -v /tmp/prom.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus:latest

docker run -d --name pushgateway --network thesis-5g_5gcore \
  --ip 10.10.0.70 -p 9092:9091 \
  prom/pushgateway:latest

docker run -d --name grafana --network thesis-5g_5gcore \
  --ip 10.10.0.80 -p 3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=12345 \
  grafana/grafana:latest
```

### Add Prometheus datasource to Grafana

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

Access Grafana at `http://localhost:3000` (admin / 12345).

### Key AMF metrics

| Metric | Description |
|--------|-------------|
| `fivegs_amffunction_rm_reginitreq` | Total registration requests |
| `fivegs_amffunction_amf_authreq` | Authentication requests |
| `fivegs_amffunction_amf_authfail` | Authentication failures (MAC failure) |
| `fivegs_amffunction_amf_authreject` | Authentication rejects |
| `fivegs_amffunction_rm_reginitfail` | Registration failures |

---

## Project Structure

```
.
├── attacks/
│   ├── brute_force.py            # FGT1110.001
│   ├── supi_harvest.py           # FGT5019
│   ├── bidding_down.py           # FGT5004
│   ├── replay_attack.py          # FGT1040
│   ├── false_bs.py               # FGT1588.501
│   └── run_all.py
├── detection/
│   ├── feature_extractor_sliding.py
│   ├── synthetic_data.py
│   ├── detector_final.py
│   ├── mitigation.py
│   └── pipeline.py
├── config/
│   ├── gnb.yaml
│   ├── rogue-gnb.yaml
│   ├── ue-supi.yaml
│   ├── ue-bidding.yaml
│   ├── ue-rogue.yaml
│   └── attacker.yaml
├── captures/                     # gitignored — pcap files
│   └── test/                     # unseen test captures
├── datasets/                     # gitignored — ML datasets
├── docker-compose.yml
└── requirements.txt
```

---

## Network & Subscriber Reference

### IP Addresses

| Container | IP | Role |
|-----------|-----|------|
| open5gs-amf | 10.10.0.12 | AMF (NGAP :38412, metrics :9090) |
| ueransim-gnb | 10.10.0.30 | Legitimate gNB |
| ueransim-ue1 | 10.10.0.31 | Normal UE (imsi-001) |
| ueransim-ue2 | 10.10.0.32 | Normal UE (imsi-002) |
| Attacker UE | 10.10.0.41 | Brute force / SUPI harvest |
| Rogue gNB | 10.10.0.50 | False base station |
| Prometheus | 10.10.0.60 | Metrics scraper |
| Pushgateway | 10.10.0.70 | Pipeline metrics receiver |
| Grafana | 10.10.0.80 | Dashboard |

### Subscribers

| IMSI | Purpose | Key | Scheme |
|------|---------|-----|--------|
| 001010000000001 | Legitimate UE1 | Correct | ECIES Profile A |
| 001010000000002 | Legitimate UE2 | Correct | ECIES Profile A |
| 001010000000003 | SUPI Harvest UE | Correct | NULL (0x00) |
| 001010000000004 | Bidding-down UE | Correct | NULL algorithms |
| 001010000000005 | False BS UE | Correct | ECIES Profile A |
| 001010000000099 | Brute-force attacker | FFFF...FF (wrong) | NULL (0x00) |

---

## Troubleshooting

**UE not connecting after restart:**
```bash
docker compose restart gnb && sleep 20
docker logs ueransim-ue1 --tail 3
```

**Brute-force giving "Semantically incorrect" instead of MAC failure:**
```bash
docker exec mongodb mongosh open5gs --eval '
db.subscribers.updateOne(
  {imsi: "001010000000099"},
  {$set: {"security.sqn": NumberLong("0")}}
);' 2>/dev/null
docker compose restart udr udm ausf && sleep 15
```

**Full system reset:**
```bash
docker compose down && docker compose up -d
sleep 60
# Re-add subscribers (see Installation step 5)
```

**IP address conflict when starting attack containers:**
```bash
docker network inspect thesis-5g_5gcore \
  --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'
docker rm -f <conflicting_container_name>
```

**Grafana shows "No data" after restart:**
```bash
# Re-add Prometheus datasource using the curl command in the Monitoring section
# Restart pipeline to push fresh metrics:
python3 detection/pipeline.py
```
