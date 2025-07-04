import socket
from Crypto.Cipher import AES

def factory_settings():
    AppSKey_table = {}

    return AppSKey_table

def decrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, ciphertext):

    #print("TESTO CRIPTATO", ciphertext)
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

        #print("CHIAVE ", AppSKey)
        #print("TESTO IN BYTES", decrypted)
    return decrypted

###################################################################################

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 9002))
print("[AS] Listening for Join Accepts on port 9002...")
print("-------------------------------------------------")

AppSKey_table = factory_settings()

while True:
    data, addr = sock.recvfrom(1024)


    if addr[1] == 9001: # Ricevuta AppSKey dal JS dopo che un ED si è associato
        AppSKey = data[:16]
        DevAddr = data[16:]
        AppSKey_table[DevAddr] = AppSKey
        print(f"[AS] Received AppSKey from JS")
        print("-------------------------------------------------")


    else: # Riceve un messaggio

        #print("MSG IN ARRIVO", data)
        DevAddr = data[1:5]
        FOptsLen = data[5] & 0x0F  # estrazione della lunghezza FOpts dai 4 bit bassi di FCtrl
        FRMPayload_start = 8 + FOptsLen  # FPort è subito dopo FHDR
        FRMPayload = data[FRMPayload_start + 1:-4]

        FCnt = data[6:8]
        FCnt = int.from_bytes(FCnt, 'little')
        direction = 0
        AppSKey = AppSKey_table[DevAddr]

        # print(AppSKey) # per fare check eavesdropping

        decrypted = decrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, FRMPayload)
        try:
            print(f"[AS] Received message from an ED ({DevAddr.hex()}): '{decrypted.decode()}'")
            print("-------------------------------------------------")

        except UnicodeDecodeError:
            print(f"[AS] Received message (invalid UTF-8) from an ED ({DevAddr.hex()}): '{decrypted.hex()}'")
            print("-------------------------------------------------")



