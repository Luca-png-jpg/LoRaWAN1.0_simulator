import random
import socket
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def factory_settings():
    NetID = bytes.fromhex('000013') # 3 byte
    registered_DevAddr = []
    NwkSKey_table = {}
    FCnt_table = {}

    return NetID, registered_DevAddr, NwkSKey_table, FCnt_table

def generate_MIC(AESKey, payload):
    cmac_obj = CMAC.new(AESKey, ciphermod=AES)
    cmac_obj.update(payload)
    MIC = cmac_obj.digest()[:4]
    return MIC

def authentication(MIC_request, new_MIC):
    if MIC_request == new_MIC:
        print("[NS] End Device successfully authenticated.")
        return True
    else:
        print("[NS] End Device authentication failed.")
        return False

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

def reconstruct_fcnt(DevAddr, FCnt_LSB_bytes, fcnt_table):
    FCnt_LSB = int.from_bytes(FCnt_LSB_bytes, 'little')
    FCnt_prev = fcnt_table.get(DevAddr, 0)

    # Ricostruisci FCnt candidate
    MSB = FCnt_prev & 0xFFFF0000
    FCnt_candidate = MSB | FCnt_LSB

    # Rileva rollover
    if FCnt_candidate < FCnt_prev:
        FCnt_candidate += 0x10000

    return FCnt_candidate

#################################################################

NetID, registered_DevAddr, NwkSKey_table, FCnt_table = factory_settings()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 9000))
print("[NS] Listening for Join Requests on port 9000...")
print("-------------------------------------------------")


while True:
    data, addr = sock.recvfrom(1024)

    MHDR = data[0]

    if MHDR == 0x00:  # Ricevo la Join Request dall'ED
        print("[NS] Join Request received from ", addr)
        EDAddr = addr

        #print(f"[NS] Received: {list(data)} from {addr}")

        sock.sendto(data, ("127.0.0.1", 9001))  # Inoltro la Join Request al JS
        print("[NS] Join Accept forwarded to JS")
        print("-------------------------------------------------")


    elif MHDR == 0x20:
        print("[NS] Join Accept received from ", addr)

        join_accept_pkt = data[:17]
        DevAddr = data[17:21]
        registered_DevAddr.append(DevAddr)
        NwkSKey = data[21:37]

        NwkSKey_table[DevAddr] = NwkSKey
        FCnt_table[DevAddr] = 0

        sock.sendto(join_accept_pkt, EDAddr)
        print("[NS] Join Accept forwarded to ", EDAddr)
        print("-------------------------------------------------")


    elif MHDR == 0x40:
        print("[NS] Unconfirmed Uplink received from", addr)
        direction = 0

        DevAddr = data[1:5]
        if DevAddr in registered_DevAddr:
            print("[NS] DevAddr is valid")
        else:
            print("[NS] Unconfirmed Uplink received from an unregistered DevAddr")
        NwkSKey = NwkSKey_table[DevAddr]
        FCnt_table[DevAddr] += 1
        FCnt = FCnt_table[DevAddr]
        MACPayload = data[1:-4]
        received_MIC = data[-4:]
        MHDR = MHDR.to_bytes(1, 'big')

        FCnt_LSB_bytes = data[6:8]
        FCnt = reconstruct_fcnt(DevAddr, FCnt_LSB_bytes, FCnt_table)

        B0 = generate_block0(direction, DevAddr, FCnt, MACPayload)
        input_block = B0 + MHDR + MACPayload
        MIC = generate_MIC(NwkSKey, input_block)

        if(authentication(received_MIC, MIC)):
            FCnt_table[DevAddr] = FCnt  # aggiorna solo dopo verifica MIC

            sock.sendto(data, ("127.0.0.1", 9002))
            print("[NS] Join Accept forwarded to AS")
            print("-------------------------------------------------")
        else:
            print("[NS] Packet rejected")
            print("-------------------------------------------------")


    else:
        print("[NS] Unidentified message received from", addr)
        print("-------------------------------------------------")


