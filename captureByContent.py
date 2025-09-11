import pyshark

# The target IP and the string you're looking for
target_ip = '143.255.142.82'
target_content = "123456789samestring"

# Construct the display filter to combine IP and content filtering
# The 'and' operator allows you to combine multiple filter conditions
display_filter = f'ip.addr == {target_ip} and tcp contains "{target_content}"'

print(f"Starting to capture packets for IP '{target_ip}' that contain '{target_content}'...")
print("Press Ctrl+C to stop the capture.")

# Create the LiveCapture object with the new display filter
capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter=display_filter)

try:
    for packet in capture.sniff_continuously():
        # Because of the filter, every packet in this loop is a packet of interest
        if 'TCP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport

            print("-" * 50)
            print(f"✅ Found a packet of interest!")
            print(f"   Stream ID: {packet.tcp.stream}")
            print(f"   {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            print(f"   Flags: {packet.tcp.flags_str}")
            print(f"   Seq: {packet.tcp.seq}, Ack: {packet.tcp.ack}")

            # You can now safely print the payload since you know it contains your string
            if hasattr(packet.tcp, 'payload'):
                hex_payload = packet.tcp.payload.replace(':', '')
                try:
                    decoded_payload = bytes.fromhex(hex_payload).decode('utf-8', errors='ignore')
                    print("   Payload:", decoded_payload)
                except UnicodeDecodeError:
                    print("   Payload: [could not decode]")

except KeyboardInterrupt:
    print("\nStopping capture...")
finally:
    capture.close()
    print("Capture process finished.")