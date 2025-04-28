import csv
import threading
import time
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# Global counters
packet_list = []
protocol_counter = Counter()

# Alert system counter
ip_counter = {}
ip_timestamps = {}

# Setup CSV file
csv_filename = "live_packet_log.csv"
headers = ["Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"]

with open(csv_filename, mode='w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(headers)

# Detect protocol
def detect_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return str(packet.proto)

# Log packet function
def process_packet(packet):
    if packet.haslayer(IP):
        timestamp = packet.time
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = detect_protocol(packet)

        src_port = packet.sport if hasattr(packet, 'sport') else ''
        dst_port = packet.dport if hasattr(packet, 'dport') else ''

        # Add to packet list (for live feed)
        packet_list.append((timestamp, src_ip, dst_ip, protocol, src_port, dst_port))
        protocol_counter[protocol] += 1

        # Write to CSV
        with open(csv_filename, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, protocol, src_port, dst_port])

        current_time = time.time()

        if src_ip not in ip_counter:
            ip_counter[src_ip] = 0
            ip_timestamps[src_ip] = current_time

        #Updates counter for the source IP
        ip_counter[src_ip] += 1

        # Check if the IP has sent more than 10 packets in the last 60 seconds
        ip_timestamps[src_ip] = current_time
        if ip_counter[src_ip] > 10:
            if current_time - ip_timestamps[src_ip] < 60:
                print(f"Alert: {src_ip} has sent more than 10 packets in the last 60 seconds!")
                # Reset counter to avoid repeated alerts
                ip_counter[src_ip] = 0

# Background sniffing thread
def start_sniffing():
    sniff(filter="ip", prn=process_packet, store=False)

# Update the GUI live
def update_gui():
    # Clear packet feed
    packet_feed.delete(*packet_feed.get_children())

    # Display last 20 packets
    for pkt in packet_list[-20:]:
        packet_feed.insert("", "end", values=pkt)

    # Update protocol chart
    protocols = list(protocol_counter.keys())
    counts = list(protocol_counter.values())

    ax.clear()
    ax.bar(protocols, counts, color=["blue", "green", "red", "purple"])
    ax.set_title("Protocol Usage")
    ax.set_ylabel("Count")

    canvas.draw()

    # Refresh every 1 second
    root.after(1000, update_gui)

# GUI Setup
root = tk.Tk()
root.title("Live Packet Dashboard")
root.geometry("1000x700")

# Packet feed (table)
packet_feed = ttk.Treeview(root, columns=("Time", "Src IP", "Dst IP", "Protocol", "Src Port", "Dst Port"), show="headings")
for col in packet_feed["columns"]:
    packet_feed.heading(col, text=col)
    packet_feed.column(col, width=140)

packet_feed.pack(fill=tk.BOTH, expand=True)

# Protocol chart (matplotlib)
fig, ax = plt.subplots(figsize=(5,4))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()

# Start sniffing in a new thread
threading.Thread(target=start_sniffing, daemon=True).start()

# Start GUI updates
update_gui()

# Start GUI
root.mainloop()

