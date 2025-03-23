import threading
import time
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
from scapy.all import sniff, Ether, IP, TCP, UDP
import numpy as np

# Shared Data for tracking network activity
event_log = defaultdict(list)
protocol_throughput = defaultdict(int)
throughput_timeline = defaultdict(list)
latency_records = {"TCP": [], "UDP": []}
unique_ips = set()
unique_macs = set()
protocol_connections = defaultdict(int)
total_packet_count = 0
stop_sniffing = threading.Event()

# File for logging captured packets
LOG_FILE = "network_events.log"

# Function to print captured packet details
def display_packet_details(protocol, src, dest, size):
    print(f"{protocol} | Source: {src}, Destination: {dest}, Packet Size: {size} bytes")

# Function to log packet details to a file
def save_to_log(protocol, src, dest, size, timestamp):
    with open(LOG_FILE, "a") as log_file:
        log_entry = f"{datetime.fromtimestamp(timestamp)} | {protocol} | Source: {src}, Destination: {dest}, Size: {size} bytes\n"
        log_file.write(log_entry)
    display_packet_details(protocol, src, dest, size)

# Function to update the data structures with new packet information
def record_packet_info(protocol, src_addr, dest_addr, size, timestamp):
    global total_packet_count
    event_log[protocol].append(size)
    protocol_throughput[protocol] += size
    protocol_connections[protocol] += 1
    total_packet_count += 1

    # Update unique MAC or IP addresses
    if protocol == "Ethernet":
        unique_macs.update([src_addr, dest_addr])
    else:
        unique_ips.update([src_addr, dest_addr])

    # Track latency for specific protocols
    if protocol in ["TCP", "UDP"]:
        latency_records[protocol].append(timestamp)

# Function to handle packets as they are captured
def handle_packet(packet):
    if stop_sniffing.is_set():
        return False

    current_time = time.time()

    # Process Ethernet packets
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dest_mac = packet[Ether].dst
        size = len(packet)
        save_to_log("Ethernet", src_mac, dest_mac, size, current_time)
        record_packet_info("Ethernet", src_mac, dest_mac, size, current_time)

    # Process IP packets
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        size = len(packet)

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            save_to_log("TCP", f"{src_ip}:{src_port}", f"{dest_ip}:{dest_port}", size, current_time)
            record_packet_info("TCP", src_ip, dest_ip, size, current_time)

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            save_to_log("UDP", f"{src_ip}:{src_port}", f"{dest_ip}:{dest_port}", size, current_time)
            record_packet_info("UDP", src_ip, dest_ip, size, current_time)

# Function to compute throughput statistics
def compute_throughput(interval=10):
    print("\n--- Throughput (in bps) ---")
    for protocol, byte_count in protocol_throughput.items():
        throughput = (byte_count * 8) / interval
        throughput_timeline[protocol].append(throughput)
        print(f"{protocol}: {throughput:.2f} bps")
        protocol_throughput[protocol] = 0
    print("---------------------------")

# Function to calculate average latency for TCP and UDP
def compute_latency():
    avg_latency = {}
    for protocol in ["TCP", "UDP"]:
        timestamps = latency_records[protocol]
        if len(timestamps) > 1:
            latencies = [
                (timestamps[i + 1] - timestamps[i]) * 1000
                for i in range(len(timestamps) - 1)
            ]
            avg_latency[protocol] = sum(latencies) / len(latencies)
        else:
            avg_latency[protocol] = 0
        print(f"Average {protocol} Latency: {avg_latency[protocol]:.2f} ms")
        print('\n')
    return avg_latency

# Function to display statistics periodically
def show_statistics():
    print("\n--- Network Monitoring Summary ---")
    for protocol, sizes in event_log.items():
        connection_count = len(sizes)
        avg_size = sum(sizes) / connection_count if connection_count > 0 else 0
        print(f"{protocol}: {connection_count} connections, Avg Size: {avg_size:.2f} bytes")
    print(f"Unique IP Addresses: {len(unique_ips)}, Unique MAC Addresses: {len(unique_macs)}")
    print(f"Total Packets: {total_packet_count}")
    print("-----------------------------------")

# Function to generate visual reports
def generate_visuals():
    # Plot throughput trends
    plt.figure(figsize=(10, 6))
    for protocol, throughput_data in throughput_timeline.items():
        plt.plot(throughput_data, label=f"{protocol} Throughput")
    plt.title("Throughput Trends Over Time")
    plt.xlabel("Time (Intervals)")
    plt.ylabel("Throughput (bps)")
    plt.legend()
    plt.grid()
    plt.savefig("throughput_trends.png")
    plt.show()

    # Plot latency distribution
    tcp_latencies = [
        (latency_records["TCP"][i + 1] - latency_records["TCP"][i]) * 1000
        for i in range(len(latency_records["TCP"]) - 1)
    ]
    udp_latencies = [
        (latency_records["UDP"][i + 1] - latency_records["UDP"][i]) * 1000
        for i in range(len(latency_records["UDP"]) - 1)
    ]

    plt.figure(figsize=(10, 6))
    if tcp_latencies:
        plt.hist(tcp_latencies, bins=20, color="lightblue", edgecolor="black", alpha=0.7, label="TCP Latency")
    if udp_latencies:
        plt.hist(udp_latencies, bins=20, color="darkblue", edgecolor="black", alpha=0.7, label="UDP Latency")
    plt.title("Latency Distribution")
    plt.xlabel("Latency (ms)")
    plt.ylabel("Frequency")
    plt.legend()
    plt.grid()
    plt.savefig("latency_distribution.png")
    plt.show()

    # Plot protocol usage and unique address stats
    plt.figure(figsize=(12, 6))
    categories = list(protocol_connections.keys()) + ["Unique IPs", "Unique MACs"]
    counts = list(protocol_connections.values()) + [len(unique_ips), len(unique_macs)]
    plt.bar(categories, counts, color=["orange"] * len(protocol_connections) + ["green", "blue"])
    plt.title("Protocol Usage and Address Statistics")
    plt.xlabel("Category")
    plt.ylabel("Counts")
    plt.xticks(rotation=45)
    plt.grid()
    plt.tight_layout()
    plt.savefig("protocol_usage.png")
    plt.show()

# Function to start packet sniffing
def start_packet_capture():
    sniff(filter="ip or tcp or udp", prn=handle_packet, store=0, stop_filter=lambda _: stop_sniffing.is_set())

# Main execution logic
if __name__ == "__main__":
    capture_thread = threading.Thread(target=start_packet_capture)
    capture_thread.start()

    try:
        while not stop_sniffing.is_set():
            for _ in range(3):
                time.sleep(10)
                compute_throughput(interval=10)
                compute_latency()
            show_statistics()
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        stop_sniffing.set()
    finally:
        capture_thread.join()
        print("\n--- Final Report ---")
        show_statistics()
        generate_visuals()
        print("Monitoring ended. Results saved.")
