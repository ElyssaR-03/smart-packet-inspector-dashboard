from scapy.all import sniff, wrpcap

packets = sniff(filter="tcp port 80", count=50)
wrpcap("live_dashboard.pcap", packets)