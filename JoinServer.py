import random
import socket
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

# Return static Join Server parameters
def factory_settings():
    NetID = bytes.fromhex('000013')  # 3-byte Network ID
    AppEUI = bytes.fromhex('8877665544332211')  # Join Server ID
    AppKey = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')  # 128-bit root key
    return NetID, AppEUI, AppKey

# Computes a 4-byte MIC using AES-CMAC
def generate_MIC(AppKey, payload):
    cmac_obj = CMAC.new(AppKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]
    return MIC

# Splits incoming message into payload and MIC
def split_message(message):
    payload = message[:19]
    MIC = message[19:]
    return payload, MIC

# Extracts DevNonce from the Join Request
def extract_DevNonce(message):
    DevNonce = message[17:19]
    return DevNonce

# Verifies that received MIC matches the computed one
def authentication(MIC_request, new_MIC):
    if MIC_request == new_MIC:
        print("[JS] End Device successfully authenticated.")
        return True
    else:
        print("[JS] End Device authentication failed.")
        return False

# Generates a random 3-byte AppNonce (little-endian)
def generate_AppNonce():
    AppNonce_hex = random.randint(0, 0xFFFFFF)
    AppNonce = AppNonce_hex.to_bytes(3, 'little')
    return AppNonce

# Generates a random 4-byte DevAddr (little-endian)
def generate_DevAddr():
    DevAddr_hex = random.randint(0, 0xFFFFFFFF)
    DevAddr = DevAddr_hex.to_bytes(4, 'little')
    return DevAddr

# Derives either NwkSKey or AppSKey using the AppKey and input values
def derive_session_key(key_type, AppKey, AppNonce, NetID, DevNonce):
    block = (
        bytes([key_type]) +
        AppNonce[::-1] +  # Convert to little-endian
        NetID[::-1] +
        DevNonce[::-1] +
        bytes(7)  # 7-byte padding
    )
    cipher = AES.new(AppKey, AES.MODE_ECB)
    return cipher.encrypt(block)

#################################################################

NetID, AppEUI, AppKey = factory_settings()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
sock.bind(("127.0.0.1", 9001))  # Bind to Join Server port
print("[JS] Listening for Join Requests on port 9001...")
print("-------------------------------------------------")

while True:
    data, addr = sock.recvfrom(1024)
    print(f"[JS] Received a Join Request: {list(data)} from {addr}")

    payload, MIC = split_message(data)  # Separate payload and MIC
    new_MIC = generate_MIC(AppKey, payload)  # Compute expected MIC
    authenticated = authentication(MIC, new_MIC)

    DevNonce = extract_DevNonce(data)  # Extract DevNonce from payload

    if authenticated:
        MHDR = b'\x20'  # Join Accept MAC header
        AppNonce = generate_AppNonce()
        DevAddr = generate_DevAddr()
        DLSettings = bytes([0x00])  # Default downlink settings
        RxDelay = bytes([0x01])     # Delay for RX1 window
        Settings = DLSettings + RxDelay

        # Message to be encrypted and returned to the ED
        message = AppNonce + NetID + DevAddr + Settings
        MIC = generate_MIC(AppKey, message)
        plaintext_payload = message + MIC

        cipher = AES.new(AppKey, AES.MODE_ECB)
        encrypted_payload = cipher.encrypt(plaintext_payload)

        join_accept_pkt = MHDR + encrypted_payload  # Join Accept frame

        # Derive session keys for the authenticated ED
        NwkSKey = derive_session_key(0x01, AppKey, AppNonce, NetID, DevNonce)
        AppSKey = derive_session_key(0x02, AppKey, AppNonce, NetID, DevNonce)

        # Send Join Accept and NwkSKey to NS
        response_to_NS = join_accept_pkt + DevAddr + NwkSKey
        sock.sendto(response_to_NS, ("127.0.0.1", 9000))
        print("[JS] Sent JoinAccept, NwkSKey and DevAddr to NS")

        # Send AppSKey to AS
        response_to_AS = AppSKey + DevAddr
        sock.sendto(response_to_AS, ("127.0.0.1", 9002))
        print("[JS] Sent AppSKey and DevAddr to AS")
        print("-------------------------------------------------")