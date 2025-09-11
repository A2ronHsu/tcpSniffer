import pyshark

# The target IP and the string you're looking for
target_ip = '143.255.142.82'
start_signature = "123456789samestring"
end_signature = "]}]}"

# Construct the display filter to combine IP and content filtering
# The 'and' operator allows you to combine multiple filter conditions
display_filter = f'ip.src == {target_ip} and tcp'

print(f"Starting to capture packets for IP '{target_ip}'")
print("Press Ctrl+C to stop the capture.")

# Create the LiveCapture object with the new display filter
capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter=display_filter)
i = 1
try:
    for packet in capture.sniff_continuously():
        if 'TCP' in packet:
            if hasattr(packet.tcp, 'payload'):
                hex_payload = packet.tcp.payload
                if hex_payload in start_signature:
                    tcp_seq = packet.tcp.seq
                    tcp_ack = packet.tcp.ack
                    tcp_len = packet.length
                    print(f'{i}"-" * 50')
                    print(f"   Flags: {packet.tcp.flags_str}")
                    print(f"   Seq: {packet.tcp.seq}, Ack: {packet.tcp.ack}")
                    try:
                        decoded_payload = bytes.fromhex(hex_payload).decode('utf-8', errors='ignore')
                        print("   Payload:", decoded_payload)
                    except UnicodeDecodeError:
                        print("   Payload: [could not decode]")
        i=i+1

except KeyboardInterrupt:
    print("\nStopping capture...")
finally:
    capture.close()
    print("Capture process finished.")