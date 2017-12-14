from pathlib import Path
from scapy.all import *

def openPCAPFile(path):
    if Path(path).is_file():
        return rdpcap(path)
    else:
        exit("Filepath or filename unknown.")

def getISAKMPPackets(packets):
    isakmpPackets = []
    for packet in packets:
        if packet.haslayer('ISAKMP'):
            # get the ISAKMP payload which is the 4. layer Ether||IP||UDP||ISAKMP
            isakmpPackets.append(packet[3])
    return isakmpPackets

#packets = openPCAPFile('./pcaps/ikev1-psk-aggressive-mode.pcapng')
#ikePackets = getISAKMPPackets(packets)

