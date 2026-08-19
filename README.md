# Wireless Deauth Detector

Offline 802.11 deauthentication attack detector: parses management frames,
recognizes deauth/disassociation frames, tracks per-BSSID rates, and flags
bursts consistent with deauth floods. Pure packet analysis - no radio.

Educational tool for intrusion detection research.

Run tests: `python -m pytest`
