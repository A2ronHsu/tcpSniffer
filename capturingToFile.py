import pyshark
import time

# Target IP and capture file name
target_ip = '143.255.142.82'
interface = 'Wi-Fi'
capture_file = 'conversation.pcapng'

# Use a live capture to sniff and save packets to a file
# The display filter ensures we only save relevant packets
live_capture = pyshark.LiveCapture(interface=interface, output_file=capture_file, display_filter=f'ip.addr == {target_ip}')

print(f"Capturing packets from {interface} for conversation with IP '{target_ip}' to '{capture_file}'...")
print("Capturing for 30 seconds. Press Ctrl+C to stop early.")

# Sniff for a specific duration or until a certain number of packets are captured
live_capture.sniff(timeout=120)
live_capture.close()
print("Capture complete.")