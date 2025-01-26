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

def checksumIP(headerIP):
    checksum = 0
    for loop in range(len(headerIP)):
        checksum += int.from_bytes(headerIP[loop*2:loop*2+1],'big')
    return (checksum%65536).to_bytes(2,'big')

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
    frame += pcapIPv4(mySrcIP,myDstIP)
    return frame

def pcapIPv4(srcIP, dstIP):
    lengthHeader = 5
    lengthData = lengthHeader*4 #suppose 0 options
    data = pcapUDP(mySrcPort,myDstPort)
    lengthData += len(data) #suppose 0 data
    frame = b''
    octetBuffer = b'\x40'
    octetBuffer = octetBuffer[0] | lengthHeader.to_bytes(1)[0]
    type(octetBuffer)
    type(frame)
    frame += octetBuffer.to_bytes(1,'big')
    frame += b'\x00'
    frame += lengthData.to_bytes(2, byteorder = 'big')
    frame += b'\x1F\xCA' # Identification
    frame += b'\x00\x00' # flag + fragment
    frame += b'\x40\x11' # TTL + Protocol UDP
    frameAddr = srcIP + dstIP
    frame += checksumIP(frame + b'\x00\x00' + frameAddr)
    frame += frameAddr
    frame += data
    return frame

def pcapUDP(srcPort,dstPort):
    frame = b''
    frame += srcPort
    frame += dstPort
    data = b''
    frame += (len(data)+4).to_bytes(2, byteorder = 'big')
    crc = b'\x00\x00'
    frame += crc
    return frame

with open(STDOUT, "wb") as f:
    f.write(pcapHeader(False))
    f.write(pcapFrame(1672839502,165922))













