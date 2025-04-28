# smart-packet-inspector-dashboard

## Project Overview
This project is a live network packet sniffer and dashboard built in Python using **Scapy**, **Tkinter**, **Counter**, and **Matplotlib**.  
It captures real-time IP packets, logs them to a CSV file, shows a live feed of the packets, charts protocol usage, and includes an alert system for suspicious activity.

## Setup Instructions

### Install the Required Python Libraries:
```bash
pip install scapy matplotlib
```
> Note: Tkinter comes with Python by default.

### Run the Dashboard:
```bash
python packet_sniff_dash.py
```
This opens the live packet sniffer window.

### CSV Logging:
- Packets are automatically logged to `live_packet_log.csv`.
- The packet_sniff_dash.py file runs the dashboard and logs them to a csv file while it runs.

## Key Features
- **Real-time packet capture and live updates.**
- **Packet information is saved to a CSV file.**
- Live dashboard shows:
  - A table with the latest 20 packets.
  - A bar graph showing the number of packets by protocol.
- **Alert system** detects if an IP sends more than 10 packets within 60 seconds.
- Background thread runs the packet sniffing without freezing the dashboard.

## Challenges Encountered
- Keeping the dashboard updating live without freezing.
- Writing to CSV during live packet capture safely.
- Making the project simple but still useful for beginners.
- Understanding the need for threading.
- Adding an alert system without creating too many false alarms.

## Future Improvements
- Show pop-up alerts inside the dashboard.
- Allow users to select filters (TCP, UDP, ICMP) manually.
- Save protocol usage history to a separate CSV file.
- Add a summary report after capture.

## Project Structure
```plaintext
packet_sniff_dash.py         # Main dashboard code with logger and alert system included
live_packet_log.csv          # Captured packet log
filteres_packet_sniff.py     # Created the .pcap file
live_dashboard.pcap          # pcap file to be viewed in Wireshark
README.md                    # Project description
```

## Authors
- [Elyssa Ratliff]  
- [Karla Robles]
