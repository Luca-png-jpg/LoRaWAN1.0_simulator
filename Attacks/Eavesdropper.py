from Crypto.Cipher import AES

# Decrypts the FRMPayload using AES in CTR-like mode (LoRaWAN specification)
def decrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, ciphertext):
    aes = AES.new(AppSKey, AES.MODE_ECB)
    block_size = 16
    n_blocks = (len(ciphertext) + block_size - 1) // block_size
    decrypted = b''

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
        block = ciphertext[(i - 1) * block_size: i * block_size]
        decrypted += bytes(a ^ b for a, b in zip(block, Si))

    return decrypted

###################################################################################

AppSKey = bytes.fromhex('62EF6DC0FA4FF9A0B73E358E9EF7A5C3')  # Random AppSKey used to decrypt intercepted packets

while True:
    # Insert intercepted unconfirmed uplink packet as hex string copied from Wireshark capture (no spaces)
    hex_str = input("Insert intercepted unconfirmed uplink packet from Wireshark: ")

    data = bytes.fromhex(hex_str)  # Convert input hex string to bytes

    print(f"[EAVESDROPPER] Intercepted packet: {list(data)}")

    DevAddr = data[1:5]  # Extract DevAddr from FHDR
    FOptsLen = data[5] & 0x0F  # Extract FOpts length from FCtrl (lower 4 bits)
    FRMPayload_start = 8 + FOptsLen  # Compute start of FPort
    FRMPayload = data[FRMPayload_start + 1:-4]  # Extract actual FRMPayload (skip FPort and MIC)

    FCnt = data[6:8]  # Extract frame counter (2 LSB)
    FCnt = int.from_bytes(FCnt, 'little')  # Convert to integer
    direction = 0  # Uplink

    # Attempt to decrypt the payload
    decrypted = decrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, FRMPayload)

    try:
        print("[EAVESDROPPER] Decrypted payload:", decrypted.decode())
        print("-------------------------------------------------")
    except UnicodeDecodeError:
        # In case the payload is not UTF-8 encoded, this can often happen due to decrypting with a wrong AppSKey
        print("[EAVESDROPPER] Decrypted payload (invalid UTF-8):", decrypted.hex())
        print("-------------------------------------------------")