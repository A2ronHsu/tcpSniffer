import pyshark
import os

# Create a directory to store the conversation files
output_dir = "conversations"
os.makedirs(output_dir, exist_ok=True)

# The target IP address for the conversation
target_ip = '143.255.142.82'

# Use a live capture to sniff and process packets
# The filter 'ip.addr' is crucial to focus on the target IP
capture = pyshark.LiveCapture(interface='Wi-Fi', display_filter=f'ip.addr == {target_ip} and tcp')

print(f"Starting to monitor TCP conversations with IP '{target_ip}'...")
print("Press Ctrl+C to stop the capture.")

# Dictionary to hold active conversations
active_conversations = {}

try:
    for packet in capture.sniff_continuously():
        if 'TCP' in packet:
            # Get the unique TCP stream ID
            stream_id = int(packet.tcp.stream)

            # Add the packet to the conversation's list
            if stream_id not in active_conversations:
                active_conversations[stream_id] = []
            
            active_conversations[stream_id].append(packet)

            # Check for FIN or RST flags to identify a finished conversation
            is_fin = '1' == packet.tcp.flags_fin
            is_rst = '1' == packet.tcp.flags_rst

            if is_fin or is_rst:
                print("-" * 50)
                print(f"Conversation {stream_id} finished. Exporting to file...")

                # Get the conversation data
                convo_packets = active_conversations[stream_id]
                
                # Create a unique filename for the conversation
                filename = os.path.join(output_dir, f'convo_{stream_id}.pcapng')
                
                # Write the packets to the file
                with pyshark.FileCapture(filename, display_filter='tcp') as temp_capture:
                    for p in convo_packets:
                        temp_capture.write_packet(p)
                
                print(f"✅ Exported {len(convo_packets)} packets to {filename}")
                
                # Clean up memory by removing the finished conversation
                del active_conversations[stream_id]
                
except KeyboardInterrupt:
    print("\nStopping capture...")
    print("Exporting any remaining active conversations...")
    
    # Export any conversations that were in progress when the script was stopped
    for stream_id, convo_packets in active_conversations.items():
        if convo_packets:
            print(f"Exporting incomplete conversation {stream_id}...")
            filename = os.path.join(output_dir, f'convo_incomplete_{stream_id}.pcapng')
            with pyshark.FileCapture(filename, display_filter='tcp') as temp_capture:
                for p in convo_packets:
                    temp_capture.write_packet(p)
            print(f"Exported {len(convo_packets)} packets to {filename}")

finally:
    capture.close()
    print("Capture process finished.")