# Wireless Deauthentication Detector

Offline 802.11 deauthentication attack detector: parses management frames, recognizes deauth/disassociation frames, tracks per-BSSID rates, and flags bursts consistent with deauth floods. Pure packet analysis - no radio hardware required. Educational tool for WiFi intrusion detection research.

## Educational Purpose

**Important:** This tool is intended solely for educational and authorized security research purposes. WiFi deauthentication attack detection is a fundamental skill in understanding wireless network security and intrusion detection. This tool should only be used on packet captures you own or have explicit written permission to analyze.

### Authorized Use Only

- Only analyze packet captures on networks you own or administer
- Obtain explicit written permission before analyzing any wireless network environment
- Report any discovered attack patterns or security findings to the appropriate network owners
- Never analyze captures you do not have explicit authorization for

### Educational Value

Understanding deauthentication attack detection helps security professionals:
- Identify and classify 802.11 management frame attacks
- Design proper wireless intrusion detection systems (WIDS)
- Implement effective deauth flood detection and alerting
- Build more secure wireless network monitoring architectures

### Legal Compliance

- Unauthorized packet capture analysis may violate Computer Fraud and Abuse Act (CFAA)
- Wiretap Act and wireless communications privacy laws
- Always obtain explicit written permission before analyzing any wireless network environment

### Responsible Use

- This project is provided for educational purposes only
- Results should be verified with proper security tools for real-world use
- Never use discovered techniques for unauthorized network surveillance

## Features

- **Frame parsing** - Parses 802.11 management frames (deauthentication, disassociation)
- **BSSID tracking** - Per-BSSID deauth/disassociation rate monitoring
- **Burst detection** - Flags deauth floods using configurable rate thresholds
- **Offline analysis** - Works on PCAP files, no radio hardware needed
- **Pure Python** - Standard library only, no external dependencies

## Installation

```bash
# Clone the repository
git clone https://github.com/OpKnock/wireless-deauth-detector.git
cd wireless-deauth-detector

# No installation required - pure Python standard library
```

## Usage

```bash
# Analyze a PCAP file
python -m deauth_detector capture.pcap

# With custom threshold (deauths per second)
python -m deauth_detector capture.pcap --threshold 10

# JSON output for automation
python -m deauth_detector capture.pcap --json

# Run tests
python -m pytest
```

## Detection Logic

The detector identifies:
1. **Deauthentication frames** (type=00, subtype=12)
2. **Disassociation frames** (type=00, subtype=10)
3. **Per-BSSID rate calculation** - Counts frames per second per BSSID
4. **Burst flagging** - Alerts when rate exceeds threshold (default: 5/sec)

## Output Example

```
Analyzing: capture.pcap
Threshold: 5 deauths/sec per BSSID

[ALERT] BSSID aa:bb:cc:dd:ee:ff - 47 deauths in 2.3s (20.4/sec)
[ALERT] BSSID 11:22:33:44:55:66 - 12 deauths in 1.1s (10.9/sec)

Summary: 2 BSSIDs flagged, 59 total deauth frames
```

## License

MIT - This project is free software: you can redistribute it and/or modify it under the terms of the MIT License. See the LICENSE file for full terms and conditions.