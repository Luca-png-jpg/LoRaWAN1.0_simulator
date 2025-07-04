import socket

while True:
    # Inserisci l'FRMPayload estrapolato da Wireshark (senza spazi)
    hex_str = input("Insert FRMPayload from Wireshark: ")

    # Converte la stringa esadecimale in bytes
    replayed_pkt = bytes.fromhex(hex_str)

    # Visualizza i byte in formato lista
    print(f"[REPLAYER] Intercepted packet: {list(replayed_pkt)}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(replayed_pkt, ("127.0.0.1", 9000))
    print("[REPLAYER] Sending replayed packet to NS")
    print("-------------------------------------------------")





