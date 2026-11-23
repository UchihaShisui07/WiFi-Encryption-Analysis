# WiFi-Encryption-Analysis
Overview
A Python-based Wi-Fi security analysis and monitoring tool designed for Windows.
The project evaluates reported Wi-Fi encryption settings, identifies potential security weaknesses, monitors access point changes, and generates security reports.
Key Features
Wi-Fi encryption analysis (WPA2, WPA3, WEP, Open, OWE)
Security risk classification
BSSID monitoring for unfamiliar access points
Gateway security auditing
Connection history logging
HTML security report generation
Technologies Used
Python
Windows Netsh
IPConfig and ARP
HTML and CSV
Wireshark (for packet capture verification)
How It Works
Collects Wi-Fi connection information from Windows.
Identifies reported authentication and encryption protocols.
Evaluates potential security weaknesses.
Monitors changes in access point identifiers.
Generates security findings and reports.
Limitations
The tool analyzes information available through Windows and cannot independently guarantee network security or confirm every type of attack.
Purpose
To provide an accessible way to understand and audit Wi-Fi encryption security without requiring specialized wireless hardware.
