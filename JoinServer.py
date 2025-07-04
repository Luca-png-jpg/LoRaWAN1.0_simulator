import random
import socket
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def factory_settings():
    NetID = bytes.fromhex('000013') # 3 byte
    AppKey = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')  # 16 byte
    return NetID, AppKey

def generate_MIC(AppKey, payload):
    cmac_obj = CMAC.new(AppKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]
    return MIC

def split_message(message):
    payload = message[:19]
    MIC = message[19:]
    return payload,MIC

def extract_DevNonce(message):
    DevNonce = message[17:19]
    return DevNonce

def authentication(MIC_request, new_MIC):
    if MIC_request==new_MIC:
        print("[JS] End Device successfully authenticated.")
        return True
    else:
        print("[JS] End Device authentication failed.")
        return False

def generate_AppNonce():
    AppNonce_hex = random.randint(0, 0xFFFFFF)
    AppNonce = AppNonce_hex.to_bytes(3, 'little')
    return AppNonce

def generate_DevAddr():
    DevAddr_hex = random.randint(0, 0xFFFFFFFF)
    DevAddr = DevAddr_hex.to_bytes(4, 'little')
    return DevAddr

def derive_session_key(key_type, AppKey, AppNonce, NetID, DevNonce):
    # key_type: 0x01 (NwkSKey), 0x02 (AppSKey)
    block = (
        bytes([key_type]) +
        AppNonce[::-1] +  # little-endian
        NetID[::-1] +
        DevNonce[::-1] +
        bytes(7)  # padding
    )
    cipher = AES.new(AppKey, AES.MODE_ECB)
    return cipher.encrypt(block)


#################################################################

NetID, AppKey = factory_settings()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 9001))
print("[JS] Listening for Join Requests on port 9001...")
print("-------------------------------------------------")

while True:
    data, addr = sock.recvfrom(1024)
    print(f"[JS] Received a Join Request: {list(data)} from {addr}")

    payload, MIC = split_message(data)
    new_MIC = generate_MIC(AppKey, payload)
    authenticated = authentication(MIC, new_MIC)

    DevNonce = extract_DevNonce(data)

    if authenticated:
        MHDR = b'\x20'    # Join Accept MAC HEADER
        AppNonce = generate_AppNonce()
        DevAddr = generate_DevAddr()
        DLSettings = bytes([0x00])
        RxDelay = bytes([0x01])
        Settings = DLSettings + RxDelay
        message = AppNonce + NetID + DevAddr + Settings
        MIC = generate_MIC(AppKey, message)

        plaintext_payload = AppNonce + NetID + DevAddr + Settings + MIC

        # plaintext_payload cypher
        cipher = AES.new(AppKey, AES.MODE_ECB)
        encrypted_payload = cipher.encrypt(plaintext_payload)

        join_accept_pkt = MHDR + encrypted_payload    # Join Accept

        NwkSKey = derive_session_key(0x01, AppKey, AppNonce, NetID, DevNonce)
        AppSKey = derive_session_key(0x02, AppKey, AppNonce, NetID, DevNonce)

        #print("NwkSKey:", NwkSKey.hex())
        #print("AppSKey:", AppSKey.hex())

        response_to_NS = join_accept_pkt + DevAddr + NwkSKey
        sock.sendto(response_to_NS, ("127.0.0.1", 9000))
        print("[JS] Sent JoinAccept, NwkSKey and DevAddr to NS")

        response_to_AS = AppSKey + DevAddr
        sock.sendto(response_to_AS, ("127.0.0.1", 9002))
        print("[JS] Sent AppSKey and DevAddr to AS")
        print("-------------------------------------------------")


