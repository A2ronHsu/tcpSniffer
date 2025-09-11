import pyshark
import os

# Create a directory to store the conversation files
output_dir = "conversations_by_hex"
os.makedirs(output_dir, exist_ok=True)

# The target IP address for the conversation
target_ip = '143.255.142.82'

# The hexadecimal pattern that signals the end of the data of interest
end_hex_pattern = b'\x5d\x7d\x5d\x7d'

# Use a live capture to sniff and process packets
# We use a broad TCP filter here since we need to inspect payloads manually
capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter=f'ip.addr == {target_ip} and tcp')

print(f"Starting to monitor conversations with IP '{target_ip}' until hex pattern '{end_hex_pattern.hex()}' is found.")
print("Press Ctrl+C to stop the capture.")

# Dictionary to hold active conversations (packets are stored here)
active_conversations = {}

try:
    for packet in capture.sniff_continuously():
        if 'TCP' in packet:
            stream_id = int(packet.tcp.stream)
            
            # Start tracking a new conversation if it's the first packet
            if stream_id not in active_conversations:
                active_conversations[stream_id] = []
            
            # Append the current packet to the conversation's list
            active_conversations[stream_id].append(packet)

            # Check if the packet contains the termination pattern
            if hasattr(packet.tcp, 'payload'):
                try:
                    # Pyshark's payload is a colon-separated hex string; we convert it to bytes
                    hex_payload = packet.tcp.payload.replace(':', '')
                    payload_bytes = bytes.fromhex(hex_payload)
                    
                    if end_hex_pattern in payload_bytes:
                        print("-" * 50)
                        print(f"✅ Found termination pattern in Stream ID: {stream_id}")
                        print("Exporting conversation to file...")

                        # Get the complete list of packets for this conversation
                        convo_packets = active_conversations[stream_id]
                        
                        # Create a unique filename
                        filename = os.path.join(output_dir, f'convo_{stream_id}_ended.pcapng')
                        
                        # Write all the collected packets to the file
                        with open(filename, 'wb') as f:
                            for p in convo_packets:
                                f.write(p.get_raw_packet())

                        print(f"Exported {len(convo_packets)} packets to {filename}")
                        
                        # Clean up memory by removing the finished conversation
                        del active_conversations[stream_id]
                
                except (ValueError, AttributeError):
                    # Handle cases where the payload is malformed or missing
                    pass

except KeyboardInterrupt:
    print("\nStopping capture...")
finally:
    capture.close()
    print("Capture process finished.")