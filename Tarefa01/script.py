# Fernando Francisco Druszcz
# Ciencia da Computacao
# GRR20182570

from scapy import all as scapy
import sys

IPV4 = 2048
IPV6 = 34525
UDP = 17
TCP = 6

totalCounter = 0
ipCounter = 0
ipv4Counter = 0
ipv6Counter = 0
tcpCounter = 0
udpCounter = 0
tcpSessionsCounter = 0
udpSessionsCounter = 0
tcpSessions = []
udpSessions = []

def contaPacoteIPV4(p):
    global ipv4Counter
    ipv4Counter += 1
    if p.proto == UDP:
        contaPacoteUDP(p, 'IP')
    elif p.proto == TCP:
        contaPacoteTCP(p, 'IP')

def contaPacoteIPV6(p):
    global ipv6Counter
    ipv6Counter += 1
    if p.nh == UDP:
        contaPacoteUDP(p, 'IPv6')
    elif p.nh == TCP:
        contaPacoteTCP(p, 'IPv6')

def contaPacoteUDP(p, ip):
    global udpCounter, udpSessions, udpSessionsCounter
    udpCounter += 1
    if ((p[ip].src, p[ip].dst, p['UDP'].sport, p['UDP'].dport) not in udpSessions) and ((p[ip].dst, p[ip].src, p['UDP'].dport, p['UDP'].sport) not in udpSessions):
        udpSessionsCounter += 1
        udpSessions.append((p[ip].src, p[ip].dst, p['UDP'].sport, p['UDP'].dport))

def contaPacoteTCP(p, ip):
    global tcpCounter, tcpSessions, tcpSessionsCounter
    tcpCounter += 1
    if ((p[ip].src, p[ip].dst, p['TCP'].sport, p['TCP'].dport) not in tcpSessions) and ((p[ip].dst, p[ip].src, p['TCP'].dport, p['TCP'].sport) not in tcpSessions):
        tcpSessionsCounter += 1
        tcpSessions.append((p[ip].src, p[ip].dst, p['TCP'].sport, p['TCP'].dport))

# ================= Inicio do programa

if(len(sys.argv) > 1):
    fileName = sys.argv[1]
    print(f'Nome Arquivo: {fileName}')
else:
    fileName = "trace.pcap"
    print(f'Nome padrao do arquivo {fileName}')

pkts = scapy.rdpcap(fileName)
for p in pkts:
    totalCounter += 1
    if (p.type == IPV4) or (p.type == IPV6):
        ipCounter += 1
        if (p.type == IPV4):
            contaPacoteIPV4(p)
        elif (p.type == IPV6):
            contaPacoteIPV6(p)


print(f'{totalCounter} pacotes no total')
print(f'{ipCounter} pacotes IP')
print(f'{ipv4Counter} pacotes IPv4')
print(f'{ipv6Counter} pacotes IPv6')
print(f'{tcpCounter} pacotes TCP')
print(f'{udpCounter} pacotes UDP')
print(f'{tcpSessionsCounter} sessões TCP')
print(f'{udpSessionsCounter} sessões UDP')
print(f'{totalCounter - ipCounter} pacotes não-IP')