# Pegasus-Spyware-Network-Detection-Simulation

An advanced cybersecurity project to monitor and analyze mobile network traffic for potential spyware activity (inspired by Pegasus).

## 🚀 Overview
This project demonstrates how network forensics can be used to detect "silent" spyware. By routing mobile traffic through a Linux-based gateway, we analyze DNS queries and data upload patterns in real-time.

## 🛠️ Tech Stack
- OS: Ubuntu (Linux) via VMware
- Network Tool: Wireshark
- Language: Python 3
- Library: Scapy
- Analysis: VirusTotal API for IP Reputation

## 📊 Project Workflow
1. Traffic Interception: Routed mobile traffic via USB Tethering.
2. Monitoring: Captured DNS packets using Wireshark to identify destinations.
3. Detection: Developed a Python script to flag suspicious domains and large data exfiltration.
4. Verification: Validated external IPs using VirusTotal.

## 🛡️ Key Features
- Real-time DNS Inquiry logging.
- Automated alerts for suspicious domain keywords.
- Idle-time data upload monitoring.

## 📝 Disclaimer
This project is for educational purposes only. It is intended to teach network security and forensic analysis.
