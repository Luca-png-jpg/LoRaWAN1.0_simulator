import random
import socket
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def factory_settings():
    # Return the factory provisioned identifiers and root key
    DevEUI = bytes.fromhex('0011223344556677')
    AppEUI = bytes.fromhex('8877665544332211')
    AppKey = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
    return DevEUI, AppEUI, AppKey

def generate_DevNonce():
    # Generate a 2-byte random DevNonce (little-endian), per LoRaWAN 1.0.x
    DevNonce_hex = random.randint(0, 0xFFFF)
    DevNonce = DevNonce_hex.to_bytes(2, 'little')
    return DevNonce

def generate_MIC(AESKey, payload):
    # Compute a 4-byte MIC using AES-CMAC
    cmac_obj = CMAC.new(AESKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]  # Truncate to 4 bytes as per LoRaWAN spec
    return MIC

def join_request(MHDR, AppEUI, DevEUI, DevNonce, MIC):
    # Construct the Join Request packet
    return MHDR + AppEUI + DevEUI + DevNonce + MIC

def decrypt_join_accept(pkt, AppKey):
    # Decrypt the Join Accept payload using AES-ECB with AppKey
    MHDR = pkt[0:1]
    encrypted_payload = pkt[1:]
    cipher = AES.new(AppKey, AES.MODE_ECB)
    decrypted_payload = cipher.decrypt(encrypted_payload)
    return MHDR + decrypted_payload

def derive_session_key(key_type, AppKey, AppNonce, NetID, DevNonce):
    # Derive NwkSKey (0x01) or AppSKey (0x02) using key derivation block
    block = (
        bytes([key_type]) +
        AppNonce[::-1] +  # Little-endian format
        NetID[::-1] +
        DevNonce[::-1] +
        bytes(7)
    )
    cipher = AES.new(AppKey, AES.MODE_ECB)
    return cipher.encrypt(block)

def extract_AppNonce_NetID_DevAddr(message):
    # Extract AppNonce, NetID, and DevAddr from decrypted Join Accept
    AppNonce = message[1:4]
    NetID = message[4:7]
    DevAddr = message[7:11]
    return AppNonce, NetID, DevAddr

def uncofirmed_uplink(AppSKey, NwkSKey, DevAddr, FCnt, msg):
    MHDR = b'\x40'  # Unconfirmed Data Up
    FCtrl = b'\x00'
    FCnt += 1  # Increment frame counter
    FHDR = DevAddr + FCtrl + FCnt.to_bytes(2, 'little')  # Frame header
    FPort = b'\x01'  # Application port
    direction = 0  # 0 = uplink

    FRMPayload = encrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, msg)
    MACPayload = FHDR + FPort + FRMPayload

    B0 = generate_block0(direction, DevAddr, FCnt, MACPayload)
    input_block = B0 + MHDR + MACPayload
    MIC = generate_MIC(NwkSKey, input_block)

    to_transmit_pkt = MHDR + MACPayload + MIC
    sock.sendto(to_transmit_pkt, ("127.0.0.1", 9000))
    return FCnt

def encrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, plaintext):
    # Encrypt the FRMPayload using CTR-like AES mode as per LoRaWAN spec
    text_in_bytes = plaintext.encode()
    aes = AES.new(AppSKey, AES.MODE_ECB)
    block_size = 16
    n_blocks = (len(text_in_bytes) + block_size - 1) // block_size
    encrypted = b''

    for i in range(1, n_blocks + 1):
        Ai = (  # Counter block for AES-CTR, varies per block (i)
            b'\x01' +                      # Encryption block header
            b'\x00\x00\x00\x00' +          # Padding
            bytes([direction & 0xFF]) +    # Direction byte (0 uplink, 1 downlink)
            DevAddr[::-1] +                # DevAddr in little-endian
            FCnt.to_bytes(4, 'little') +   # 4-byte frame counter
            b'\x00' +                      # Reserved
            bytes([i])                     # Block sequence number
        )
        Si = aes.encrypt(Ai)  # Keystream block obtained by encrypting Ai
        block = text_in_bytes[(i - 1)*block_size: i*block_size]  # Extract the current plaintext block (16 bytes)
        encrypted += bytes(a ^ b for a, b in zip(block, Si))  # XOR plaintext block with keystream block Si

    return encrypted

def generate_block0(direction, DevAddr, FCnt, MACPayload):
    # Generate the B0 block used in MIC computation for data frames
    B0 = (
        b'\x49' +                         # B0 block identifier
        b'\x00\x00\x00\x00' +             # Padding
        bytes([direction & 0xFF]) +       # Direction byte (0 uplink - 1 downlink)
        DevAddr[::-1] +                   # DevAddr (little-endian)
        FCnt.to_bytes(4, 'little') +      # Frame counter
        b'\x00' +                         # Padding
        bytes([len(MACPayload)])          # Length of MACPayload
    )
    return B0


##############################################################

# === JOIN PROCEDURE ===
MHDR = b'\x00'  # Join Request MAC header
DevEUI, AppEUI, AppKey = factory_settings()
DevNonce = generate_DevNonce()

payload = MHDR + AppEUI + DevEUI + DevNonce
MIC = generate_MIC(AppKey, payload)

pkt = join_request(MHDR, AppEUI, DevEUI, DevNonce, MIC)

print("[ED] Sending Join Request...")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP (SOCK_DGRAM) socket using IPv4 (AF_INET)
sock.sendto(pkt, ("127.0.0.1", 9000))  # Send to NS
print("[ED] Join Request sent to NS")
print("-------------------------------------------------")

# === WAIT FOR JOIN ACCEPT ===
join_accept_pkt = None
while join_accept_pkt is None:
    join_accept_pkt, addr = sock.recvfrom(1024)
    join_accept_pkt = decrypt_join_accept(join_accept_pkt, AppKey)
    print("[ED] Join Accept received")

    pkt_MIC = join_accept_pkt[-4:]
    AppNonce, NetID, DevAddr = extract_AppNonce_NetID_DevAddr(join_accept_pkt)
    payload = join_accept_pkt[1:-4]
    calculate_MIC = generate_MIC(AppKey, payload)

    if pkt_MIC == calculate_MIC:
        print("[ED] MIC authenticated")
        print("[ED] Deriving session keys (NwkSKey, AppSKey)...")
        NwkSKey = derive_session_key(0x01, AppKey, AppNonce, NetID, DevNonce)
        AppSKey = derive_session_key(0x02, AppKey, AppNonce, NetID, DevNonce)
    else:
        print("[ED] MIC authentication failed")

print("-------------------------------------------------")

# === APPLICATION MESSAGE LOOP ===
FCnt = 0
while True:
    msg = input("[ED] Send a message to the AS: ")
    print("-------------------------------------------------")
    FCnt = uncofirmed_uplink(AppSKey, NwkSKey, DevAddr, FCnt, msg)
    print(FCnt)

sock.close()