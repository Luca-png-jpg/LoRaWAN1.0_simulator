from Crypto.Cipher import AES

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

while True:
    # Inserisci il FRMPayload estrapolato da Wireshark (senza spazi)
    hex_str = input("Insert FRMPayload from Wireshark: ")

    # Converte la stringa esadecimale in bytes
    data = bytes.fromhex(hex_str)

    # Visualizza i byte in formato lista
    print(f"[EAVESDROPPER] Intercepted packet: {list(data)}")

    DevAddr = data[1:5]
    FOptsLen = data[5] & 0x0F  # estrazione della lunghezza FOpts dai 4 bit bassi di FCtrl
    FRMPayload_start = 8 + FOptsLen  # FPort è subito dopo FHDR
    FRMPayload = data[FRMPayload_start + 1:-4]

    FCnt = data[6:8]
    FCnt = int.from_bytes(FCnt, 'little')
    direction = 0

    decrypted = decrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, FRMPayload)
    try:
        print("[EAVESDROPPER] Decrypted payload:", decrypted.decode())
        print("-------------------------------------------------")

    except UnicodeDecodeError:
        print("[EAVESDROPPER] Decrypted payload (invalid UTF-8):", decrypted.hex())
        print("-------------------------------------------------")

