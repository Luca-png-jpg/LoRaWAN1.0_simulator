import socket

while True:
    # Insert intercepted unconfirmed uplink packet as hex string copied from Wireshark capture (no spaces)
    hex_str = input("Insert intercepted unconfirmed uplink packet from Wireshark: ")

    # Convert hex string to raw bytes
    replayed_pkt = bytes.fromhex(hex_str)

    # Print the intercepted packet as a list of bytes
    print(f"[REPLAYER] Intercepted packet: {list(replayed_pkt)}")

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Replay the packet by sending it to the Network Server (port 9000)
    sock.sendto(replayed_pkt, ("127.0.0.1", 9000))
    print("[REPLAYER] Sending replayed packet to NS")
    print("-------------------------------------------------")





