import pyshark

# Specify the network interface to listen on (e.g., 'Ethernet' or 'Wi-Fi')
# You can find the interface name by running `tshark -D`.
# For example, if your Wi-Fi interface is named "Wi-Fi", you would use that name.
interface_name = 'Wi-Fi' 

# The target IP address for the conversation
target_ip = '143.255.142.82'

# Create a LiveCapture object
# The 'display_filter' option works just like Wireshark's display filter
capture = pyshark.LiveCapture(interface=interface_name, display_filter=f'ip.addr == {target_ip}')

print(f"Starting to capture TCP packets on interface '{interface_name}' for conversartion with {target_ip}...")
print("Press Ctrl+C to stop the capture.")

i = 0;

# Start the capture and iterate over the packets
for packet in capture.sniff_continuously():
    try:
        # Access the TCP layer and print some basic information
        if 'TCP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            # Print a summary of the packet
            print(i, f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            print(f"     Flags: {packet.tcp.flags_str}")
            print(f"     Seq: {packet.tcp.seq}")
            print(f"     Ack: {packet.tcp.ack}")

            # Check for a payload and print it
            if hasattr(packet.tcp, 'payload'):
                # Get the hexadecimal string
                hex_payload = packet.tcp.payload.replace(':','')
                # Convert hex string to a byte array
                byte_payload = bytes.fromhex(hex_payload)
                
                # Decode the byte array to a string (e.g., using UTF-8)
                try:
                    decoded_payload = byte_payload.decode('latin-1')
                    print("Decoded Payload:")
                    print(decoded_payload)
                except UnicodeDecodeError:
                    print("Could not decode payload with UTF-8.")
            elif 'Http' in packet:
                # For HTTP traffic, the payload is often in the HTTP layer
                print("HTTP Payload Found:")
                print(packet.http.html) # Or other relevant HTTP fields
            print("-" * 30)
        i += 1;

    except AttributeError:
        # This handles packets that might not have an IP or TCP layer
        # which can sometimes happen with a broad filter
        pass