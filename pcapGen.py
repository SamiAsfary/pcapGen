from GenericCRC import GenericCRC
from myNetwork import *
STDOUT = "test.pcap"

ENDIAN = 'little'

MagicNumMicro = b'\xA1\xB2\xC3\xD4'
MagicNumNano = b'\xA1\xB2\x3C\x4D'

Version = b'\x00\x04\x00\x02'

Reserved = b'\x00\x00\x00\x00'

SnapLen = b'\x00\x00\xFF\xFF'

LinkType = b'\x00\x00\x00\x01'

def ReturnBytes(Bytes):
    if(ENDIAN == "big"):
        return Bytes
    Bytes = Bytes[::-1]
    return Bytes

def pcapHeader(isTmpsNano : bool = False):
    Header = b''
    if(isTmpsNano):
        MagicNum = MagicNumNano
    else:
        MagicNum = MagicNumMicro
    Header += ReturnBytes(MagicNum)
    Header += ReturnBytes(Version)
    Header += ReturnBytes(Reserved)
    Header += ReturnBytes(Reserved)
    Header += ReturnBytes(SnapLen)
    Header += ReturnBytes(LinkType)
    return Header

def pcapFrame(sTime,xsTime):
    frame = b''
    frame += sTime.to_bytes(4, byteorder = ENDIAN)
    frame += sTime.to_bytes(4, byteorder = ENDIAN)
    packet = pcapEthernetII(mySrcMAC,myDstMAC)
    frame += len(packet).to_bytes(4, byteorder = ENDIAN) 
    frame += len(packet).to_bytes(4, byteorder = ENDIAN) 
    frame += packet
    return frame

def pcapEthernetII(srcMAC,dstMAC):
    frame = b''
    frame += srcMAC
    frame += dstMAC
    frame += b'\x08\x00'
    return frame

with open(STDOUT, "wb") as f:
    f.write(pcapHeader(False))
    f.write(pcapFrame(1672839502,165922))













