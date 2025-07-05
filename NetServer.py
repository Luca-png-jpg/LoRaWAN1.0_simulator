import socket
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Returns factory-initialized network parameters and session tables
def factory_settings():
    NetID = bytes.fromhex('000013')  # 3-byte network identifier
    registered_DevAddr = []          # List of authorized DevAddr
    NwkSKey_table = {}               # Mapping: DevAddr → NwkSKey
    FCnt_table = {}                  # Mapping: DevAddr → last known FCnt
    return NetID, registered_DevAddr, NwkSKey_table, FCnt_table

# Computes a 4-byte MIC using AES-CMAC
def generate_MIC(AESKey, payload):
    cmac_obj = CMAC.new(AESKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]  # LoRaWAN uses only first 4 bytes
    return MIC

# Verifies MIC authenticity by comparing computed and received values
def authentication(MIC_request, new_MIC):
    if MIC_request == new_MIC:
        print("[NS] End Device successfully authenticated.")
        return True
    else:
        print("[NS] End Device authentication failed.")
        return False

# Builds B0 block used in MIC computation for uplink/downlink frames
def generate_block0(direction, DevAddr, FCnt, MACPayload):
    B0 = (
        b'\x49' +                         # Block type = MIC
        b'\x00\x00\x00\x00' +             # Padding
        bytes([direction & 0xFF]) +       # 0 = uplink, 1 = downlink
        DevAddr[::-1] +                   # DevAddr in little-endian
        FCnt.to_bytes(4, 'little') +      # 4-byte frame counter
        b'\x00' +                         # Padding
        bytes([len(MACPayload)])          # Length of MACPayload
    )
    return B0

# Reconstructs full FCnt from the 2 LSBs and previous known counter
def reconstruct_fcnt(DevAddr, FCnt_LSB_bytes, fcnt_table):
    FCnt_LSB = int.from_bytes(FCnt_LSB_bytes, 'little')
    FCnt_prev = fcnt_table.get(DevAddr, 0)

    MSB = FCnt_prev & 0xFFFF0000
    FCnt_candidate = MSB | FCnt_LSB

    if FCnt_candidate < FCnt_prev:  # Handle overflow
        FCnt_candidate += 0x10000

    return FCnt_candidate

#################################################################
# === Network Server Main Loop ===

NetID, registered_DevAddr, NwkSKey_table, FCnt_table = factory_settings()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
sock.bind(("127.0.0.1", 9000))  # Bind to port 9000 (NS)
print("[NS] Listening for Join Requests on port 9000...")
print("-------------------------------------------------")

while True:
    data, addr = sock.recvfrom(1024)  # Receive packet from any component
    MHDR = data[0]

    if MHDR == 0x00:  # Join Request from ED
        print("[NS] Join Request received from ", addr)
        EDAddr = addr  # Save ED address for later response

        sock.sendto(data, ("127.0.0.1", 9001))  # Forward to Join Server
        print("[NS] Join Accept forwarded to JS")
        print("-------------------------------------------------")

    elif MHDR == 0x20:  # Join Accept from JS
        print("[NS] Join Accept received from ", addr)

        join_accept_pkt = data[:17]     # Encrypted Join Accept
        DevAddr = data[17:21]           # Extract DevAddr
        registered_DevAddr.append(DevAddr)

        NwkSKey = data[21:37]           # Extract NwkSKey
        NwkSKey_table[DevAddr] = NwkSKey
        FCnt_table[DevAddr] = 0         # Initialize counter for ED

        sock.sendto(join_accept_pkt, EDAddr)  # Send to ED
        print("[NS] Join Accept forwarded to ", EDAddr)
        print("-------------------------------------------------")

    elif MHDR == 0x40:  # Unconfirmed Uplink from ED
        print("[NS] Unconfirmed Uplink received from", addr)
        direction = 0  # Uplink = 0

        DevAddr = data[1:5]  # Extract DevAddr from FHDR
        if DevAddr in registered_DevAddr:
            print("[NS] DevAddr is valid")
        else:
            print("[NS] Unconfirmed Uplink received from an unregistered DevAddr")

        NwkSKey = NwkSKey_table[DevAddr]
        FCnt_LSB_bytes = data[6:8]
        FCnt = reconstruct_fcnt(DevAddr, FCnt_LSB_bytes, FCnt_table)

        MACPayload = data[1:-4]
        received_MIC = data[-4:]
        MHDR = MHDR.to_bytes(1, 'big')

        B0 = generate_block0(direction, DevAddr, FCnt, MACPayload)
        input_block = B0 + MHDR + MACPayload
        MIC = generate_MIC(NwkSKey, input_block)

        if authentication(received_MIC, MIC):
            FCnt_table[DevAddr] = FCnt  # Update FCnt only if MIC is valid

            sock.sendto(data, ("127.0.0.1", 9002))  # Forward to AS
            print("[NS] Join Accept forwarded to AS")
            print("-------------------------------------------------")
        else:
            print("[NS] Packet rejected")
            print("-------------------------------------------------")

    else:
        print("[NS] Unidentified message received from", addr)
        print("-------------------------------------------------")