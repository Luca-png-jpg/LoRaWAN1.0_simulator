import socket
from Crypto.Cipher import AES

# Initializes the table used to store AppSKeys per DevAddr
def factory_settings():
    AppSKey_table = {}  # Mapping: DevAddr → AppSKey
    return AppSKey_table

# Decrypts FRMPayload using AES in CTR-like mode (LoRaWAN-compliant)
def decrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, ciphertext):
    aes = AES.new(AppSKey, AES.MODE_ECB)
    block_size = 16
    n_blocks = (len(ciphertext) + block_size - 1) // block_size
    decrypted = b''

    for i in range(1, n_blocks + 1):
        Ai = (
            b'\x01' +                      # Block type for CTR-like encryption
            b'\x00\x00\x00\x00' +          # Padding
            bytes([direction & 0xFF]) +    # Direction: 0 = uplink, 1 = downlink
            DevAddr[::-1] +                # DevAddr in little-endian
            FCnt.to_bytes(4, 'little') +   # Frame counter (FCnt)
            b'\x00' +                      # Reserved
            bytes([i])                     # Block sequence number
        )
        Si = aes.encrypt(Ai)
        block = ciphertext[(i - 1) * block_size: i * block_size]
        decrypted += bytes(a ^ b for a, b in zip(block, Si))

    return decrypted

###################################################################################

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
sock.bind(("127.0.0.1", 9002))  # Bind to AS port
print("[AS] Listening for Join Accepts on port 9002...")
print("-------------------------------------------------")

AppSKey_table = factory_settings()

while True:
    data, addr = sock.recvfrom(1024)

    if addr[1] == 9001:
        # Received AppSKey from the Join Server after a successful Join
        AppSKey = data[:16]
        DevAddr = data[16:]
        AppSKey_table[DevAddr] = AppSKey
        print(f"[AS] Received AppSKey from JS")
        print("-------------------------------------------------")

    else:
        # Received an uplink message from the Network Server
        DevAddr = data[1:5]  # Extract DevAddr from FHDR

        FOptsLen = data[5] & 0x0F  # Extract FOptsLen from FCtrl (4 LSB)
        FRMPayload_start = 8 + FOptsLen  # Compute start index of FPort
        FRMPayload = data[FRMPayload_start + 1:-4]  # Extract FRMPayload (skip FPort and MIC)

        FCnt = data[6:8]
        FCnt = int.from_bytes(FCnt, 'little')
        direction = 0  # Uplink

        AppSKey = AppSKey_table[DevAddr]  # Retrieve the session key

        decrypted = decrypt_FRMPayload(AppSKey, DevAddr, FCnt, direction, FRMPayload)

        try:
            # Attempt to decode and print plaintext message
            print(f"[AS] Received message from an ED ({DevAddr.hex()}): '{decrypted.decode()}'")
            print("-------------------------------------------------")

        except UnicodeDecodeError:
            # Handle non-UTF8 binary payloads
            print(f"[AS] Received message (invalid UTF-8) from an ED ({DevAddr.hex()}): '{decrypted.hex()}'")
            print("-------------------------------------------------")