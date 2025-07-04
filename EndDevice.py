import random
import socket
import time
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def factory_settings():
    DevEUI = bytes.fromhex('0011223344556677')  # 8 bytes
    AppEUI = bytes.fromhex('8877665544332211')  # 8 bytes
    AppKey = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')  # 16 byte
    return DevEUI, AppEUI, AppKey


def generate_DevNonce():
    DevNonce_hex = random.randint(0, 0xFFFF)  # due byte, in 1.0.x è random e quindi possono verificarsi delle collisioni
    DevNonce = DevNonce_hex.to_bytes(2, 'little')  # LoRaWAN usa formato little-endian
    return DevNonce


def generate_MIC(AESKey, payload):
    cmac_obj = CMAC.new(AESKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]  # Nel contesto LoRaWAN, il MIC è di 4 byte, quindi lo standard specifica di usare solo i primi 4 byte dei 16 generati dall'AES-CMAC
    return MIC

def join_request(MHDR, AppEUI, DevEUI, DevNonce, MIC):
    return MHDR + AppEUI + DevEUI + DevNonce + MIC

def decrypt_join_accept(pkt, AppKey):
    MHDR = pkt[0:1]
    encrypted_payload = pkt[1:]

    cipher = AES.new(AppKey, AES.MODE_ECB)
    decrypted_payload = cipher.decrypt(encrypted_payload)

    return MHDR + decrypted_payload

def derive_session_key(key_type, AppKey, AppNonce, NetID, DevNonce):
    # key_type: 0x01 (NwkSKey), 0x02 (AppSKey)
    block = (
        bytes([key_type]) +
        AppNonce[::-1] +  # little-endian
        NetID[::-1] +
        DevNonce[::-1] +
        bytes(7)
    )
    cipher = AES.new(AppKey, AES.MODE_ECB)
    return cipher.encrypt(block)

def extract_AppNonce_NetID_DevAddr(message):
    AppNonce= message[1:4]
    NetID = message[4:7]
    DevAddr = message[7:11]
    return AppNonce, NetID, DevAddr

def uncofirmed_uplink(AppSKey, NwkSKey, DevAddr, FCnt, msg):
    MHDR = b'\x40'
    FCtrl = b'\x00'
    FCnt += 1
    FOpts = None
    FHDR = DevAddr + FCtrl + FCnt.to_bytes(2, 'little')  # + FOpts
    FPort = b'\x01'  # App Default
    direction = 0

    FRMPayload = encrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, msg)
    MACPayload = FHDR + FPort + FRMPayload

    B0 = generate_block0(direction, DevAddr, FCnt, MACPayload)
    input_block = B0 + MHDR + MACPayload
    MIC = generate_MIC(NwkSKey, input_block)

    to_transmit_pkt = MHDR + MACPayload + MIC

    sock.sendto(to_transmit_pkt, ("127.0.0.1", 9000))

    return FCnt


def encrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, plaintext):
    text_in_bytes = plaintext.encode()

    aes = AES.new(AppSKey, AES.MODE_ECB)
    block_size = 16
    n_blocks = (len(text_in_bytes) + block_size - 1) // block_size
    encrypted = b''

    for i in range(1, n_blocks + 1):
        Ai = (
            b'\x01' +                      # Byte 0: sempre 0x01 (indica CTR-like mode)
            b'\x00\x00\x00\x00' +          # Byte 1-4: sempre 0 (padding)
            bytes([direction & 0xFF]) +    # Byte 5: uplink = 0, downlink = 1
            DevAddr[::-1] +                # Byte 6-9: DevAddr in little endian
            FCnt.to_bytes(4, 'little') +   # Byte 10-13: FCnt (contatore) in LE
            b'\x00' +                      # Byte 14: padding
            bytes([i])                     # Byte 15: numero del blocco
        )

        Si = aes.encrypt(Ai)
        block = text_in_bytes[(i - 1)*block_size: i*block_size]
        encrypted += bytes(a ^ b for a, b in zip(block, Si))

    return encrypted

def generate_block0(direction, DevAddr, FCnt, MACPayload):
    B0 = (
            b'\x49' +  # 0: tipo MIC
            b'\x00\x00\x00\x00' +  # 1–4: padding
            bytes([direction & 0xFF]) +  # 5: 0 uplink, 1 downlink
            DevAddr[::-1] +  # 6–9: DevAddr LE
            FCnt.to_bytes(4, 'little') +  # 10–13: FCnt
            b'\x00' +  # 14: padding
            bytes([len(MACPayload)])  # 15: lunghezza messaggio
    )

    return B0




##############################################################

MHDR = b'\x00'    #Join Request MAC HEADER
DevEUI, AppEUI, AppKey = factory_settings()
DevNonce = generate_DevNonce()

payload = MHDR + AppEUI + DevEUI + DevNonce
MIC = generate_MIC(AppKey, payload)

pkt = join_request(MHDR, AppEUI, DevEUI, DevNonce, MIC)    # Join Request

print("[ED] Sending Join Request...")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # IPv4 and UDP
sock.sendto(pkt, ("127.0.0.1", 9000))
print("[ED] Join Request sent to NS")
print("-------------------------------------------------")

join_accept_pkt = None
while join_accept_pkt is None:
    join_accept_pkt, addr = sock.recvfrom(1024)
    #print(f"[ED] Received encrypted: {list(join_accept_pkt)} from {addr}")

    join_accept_pkt = decrypt_join_accept(join_accept_pkt, AppKey)
    #print(f"[ED] Decrypted join accept: {list(join_accept_pkt)}")

    print("[ED] Join Accept received")

    pkt_MIC = join_accept_pkt[-4:]
    AppNonce, NetID, DevAddr = extract_AppNonce_NetID_DevAddr(join_accept_pkt)
    payload = join_accept_pkt[1:-4]
    calculate_MIC = generate_MIC(AppKey, payload)

    if pkt_MIC==calculate_MIC:
        print("[ED] MIC authenticated")

        print("[ED] Deriving session keys (NwkSKey, AppSKeys) ...")
        NwkSKey = derive_session_key(0x01, AppKey, AppNonce, NetID, DevNonce)
        AppSKey = derive_session_key(0x02, AppKey, AppNonce, NetID, DevNonce)
    else:
        print("[ED] MIC authentication failed")

print("-------------------------------------------------")

#############################
# Inizio scambio dei messaggi

FCnt = 0

while True:
    msg = input("[ED] Send a message to the AS: ")
    print("-------------------------------------------------")

    FCnt = uncofirmed_uplink(AppSKey, NwkSKey, DevAddr, FCnt, msg)

sock.close()



