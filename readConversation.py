import pyshark

# The capture file we just created
capture_file = 'conversation.pcapng'

# Create a FileCapture object
# Pyshark automatically handles reassembly for you
capture = pyshark.FileCapture(capture_file)

# A dictionary to store reassembled conversations
conversations = {}

print(f"\nProcessing capture file '{capture_file}' to reassemble conversations...")

# Iterate through the packets in the capture file
for packet in capture:
    if 'TCP' in packet:
        stream_id = int(packet.tcp.stream)
        
        # Initialize a new conversation entry if it doesn't exist
        if stream_id not in conversations:
            conversations[stream_id] = {
                'packets': [],
                'source': f"{packet.ip.src}:{packet.tcp.srcport}",
                'destination': f"{packet.ip.dst}:{packet.tcp.dstport}"
            }
        
        # Append the packet to the correct conversation
        conversations[stream_id]['packets'].append(packet)

# Now, iterate through the conversations and print them
for stream_id, convo in conversations.items():
    print("=" * 60)
    print(f"✅ Reassembled Conversation (Stream ID: {stream_id})")
    print(f"   -> {convo['source']} <-> {convo['destination']}")
    print("-" * 60)
    
    # Check if there is a higher-level protocol layer (like HTTP)
    # Pyshark will reassemble this for you
    first_packet = convo['packets'][0]
    if hasattr(first_packet, 'http'):
        print("Protocol: HTTP")
        try:
            # You can access the complete HTTP request and response here
            # Wireshark's dissector has already reassembled the content
            if hasattr(first_packet.http, 'request_full_uri'):
                print("Request URI:", first_packet.http.request_full_uri)
            if hasattr(first_packet.http, 'response'):
                print("Response:", first_packet.http.response)
            
            # This is where the magic happens: get the reassembled data
            # The 'get_packet_by_stream_index' method is a powerful feature of FileCapture
            full_stream_bytes = capture.get_packet_by_stream_index(stream_id)
            if full_stream_bytes:
                # You can then decode and work with the full stream of data
                decoded_stream = full_stream_bytes.decode('utf-8', errors='ignore')
                print("\nFull Decoded Stream:")
                print(decoded_stream)

        except Exception as e:
            print(f"Error processing HTTP stream: {e}")
    else:
        print("Protocol: Unknown (TCP)")
        # For non-HTTP traffic, you can manually combine the payloads
        full_payload = b''
        for packet in convo['packets']:
            if hasattr(packet.tcp, 'payload'):
                hex_payload = packet.tcp.payload.replace(':', '')
                full_payload += bytes.fromhex(hex_payload)
        
        try:
            print("\nCombined Decoded Payload:")
            print(full_payload.decode('utf-8', errors='ignore'))
        except Exception:
            print("\nCould not decode combined payload with UTF-8.")
            print("Payload (hex):", full_payload.hex())

capture.close()