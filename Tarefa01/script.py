# Fernando Francisco Druszcz
# Ciencia da Computacao
# GRR20182570

from scapy import all as scapy

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

fileName = "trace.pcap"

pkts = scapy.rdpcap(fileName)
for p in pkts:
    totalCounter += 1
    if (p.type == IPV4) or (p.type == IPV6):
        ipCounter += 1
        if (p.type == IPV4):
            contaPacoteIPV4(p)
        elif (p.type == IPV6):
            contaPacoteIPV6(p)

# import dpkt
# import socket

# f = open("trace.pcap", 'rb')
# trace = dpkt.pcap.Reader(f)
# for t,p in trace:
#     totalCounter += 1

#     eth = dpkt.ethernet.Ethernet(p)
#     if eth.type == dpkt.ethernet.ETH_TYPE_IP:
#         ipCounter += 1
#         ip = eth.data
#         if ip.p == dpkt.ip.IP_PROTO_TCP:
#             tcpCounter += 1
#             if ((ip.src, ip.data.sport, ip.dst, ip.data.dport) not in tcpSessions) and ((ip.dst, ip.data.dport, ip.src, ip.data.sport) not in tcpSessions):
#                 # print("New TCP session")
#                 # print(f'{socket.inet_ntoa(ip.src)}:{ip.data.sport}')
#                 # print(f'{socket.inet_ntoa(ip.dst)}:{ip.data.dport}')
#                 tcpSessions.append((ip.src, ip.data.sport, ip.dst, ip.data.dport))
#                 tcpSessionsCounter += 1
#         elif ip.p == dpkt.ip.IP_PROTO_UDP:
#             udpCounter += 1
#             if ((ip.src, ip.data.sport, ip.dst, ip.data.dport) not in udpSessions) and ((ip.dst, ip.data.dport, ip.src, ip.data.sport) not in udpSessions):
#                 # print("New UDP session")
#                 # print(f'{socket.inet_ntoa(ip.src)}:{ip.data.sport}')
#                 # print(f'{socket.inet_ntoa(ip.dst)}:{ip.data.dport}')
#                 udpSessions.append((ip.src, ip.data.sport, ip.dst, ip.data.dport))
#                 udpSessionsCounter += 1
#     # IP if end



print(f'{totalCounter} pacotes no total')
print(f'{ipCounter} pacotes IP')
print(f'{ipv4Counter} pacotes IPv4')
print(f'{ipv6Counter} pacotes IPv6')
print(f'{tcpCounter} pacotes TCP')
print(f'{udpCounter} pacotes UDP')
print(f'{tcpSessionsCounter} sessões TCP')
print(f'{udpSessionsCounter} sessões UDP')
print(f'{totalCounter - ipCounter} pacotes não-IP')