from scapy.all import *
import binascii

# helpfull commands in scapy
# packet.do_summary(): gives back the names of layers a packet has
# packet.hashlayer("layername"): returns true if the layer is present in the packet

# isakmp layer names
# ISAKMP: packet contains an ISAKMP packet
# ISAKMP_payload_SA: contains the SA proposal
# ISAKMP_payload_KE: contains the key exchange data
# ISAKMP_payload_Nonce: contains the nonce data
# ISAKMP_payload_ID: contains the identification data (ip address)
# e.g.: packet[ISAKMP_ID_NAME] gets you the corresponding layer (without " or ' is correct)

KEX = ISAKMP_payload_KE
NONCE= ISAKMP_payload_Nonce
SAPAYLOAD = ISAKMP_payload_SA


def getIniatorSAPacket(packets):
    for packet in packets:
        if(packet.haslayer(ISAKMP)):
            if binascii.hexlify(bytes(packet[ISAKMP].resp_cookie)) == b'0000000000000000':
                return packet

def getResponderSAPacket(packets):
    for packet in packets:
        if (packet.haslayer(ISAKMP)):
            if binascii.hexlify(bytes(packet[ISAKMP].resp_cookie)) != b'0000000000000000':
                return packet

def getInitiatorIP(packets):
    packet = getIniatorSAPacket(packets)
    return packet[IP].src

def getResponderIP(packets):
    packet = getIniatorSAPacket(packets)
    return packet[IP].dst

# layerName should not be a string
# e.g ISAKMP_payload_SA instead "ISAKMP_payload_SA"
def getISAKMPPayloadFromPackets(packets, senderIP, layerName):
    for packet in packets:
        if(packet[IP].src == senderIP):
            if(packet.haslayer(layerName)):
                return packet[layerName].load

def getCookieFromPackets(packets, responder):
    if(responder):
        return getResponderSAPacket(packets).resp_cookie
    else:
        for packet in packets:
            if(packet.haslayer("ISAKMP")):
                return packet[ISAKMP].init_cookie


