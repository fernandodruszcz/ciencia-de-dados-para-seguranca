# Fernando Francisco Druszcz
# Ciencia da Computacao
# GRR20182570

from scapy import all as scapy
import sys
import base64 
import binascii

IPV4 = 2048
IPV6 = 34525
UDP = 17
TCP = 6


# ================= Inicio do programa

if(len(sys.argv) > 1):
    fileName = sys.argv[1]
    print(f'Nome Arquivo: {fileName}')
else:
    fileName = "splitaa"
    print(f'Nome padrao do arquivo {fileName}')

totalCounter = 0

pkts = scapy.rdpcap(fileName, 100)
for p in pkts:
    totalCounter += 1
    print(p.summary())
    #print(p.show(dump=True))
 
    decoded_data ="" 
    decoded_data = base64.b64decode(str(p['TCP'].payload)) 
    print(decoded_data)


print(totalCounter)

