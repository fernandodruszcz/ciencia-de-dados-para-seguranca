import dpkt
import socket


fileName = "trace.pcap"

totalCounter = 0
ipCounter = 0
tcpCounter = 0
udpCounter = 0
tcpSessionsCounter = 0
udpSessionsCounter = 0
tcpSessions = []
udpSessions = []


f = open("trace.pcap", 'rb')
trace = dpkt.pcap.Reader(f)
for t,p in trace:
    totalCounter += 1

    eth = dpkt.ethernet.Ethernet(p)
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ipCounter += 1
        ip = eth.data
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcpCounter += 1
            if ((ip.src, ip.data.sport, ip.dst, ip.data.dport) not in tcpSessions) and ((ip.dst, ip.data.dport, ip.src, ip.data.sport) not in tcpSessions):
                print("New TCP session")
                print(f'{socket.inet_ntoa(ip.src)}:{ip.data.sport}')
                print(f'{socket.inet_ntoa(ip.dst)}:{ip.data.dport}')
                tcpSessions.append((ip.src, ip.data.sport, ip.dst, ip.data.dport))
                tcpSessionsCounter += 1
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udpCounter += 1
            if ((ip.src, ip.data.sport, ip.dst, ip.data.dport) not in udpSessions) and ((ip.dst, ip.data.dport, ip.src, ip.data.sport) not in udpSessions):
                print("New UDP session")
                print(f'{socket.inet_ntoa(ip.src)}:{ip.data.sport}')
                print(f'{socket.inet_ntoa(ip.dst)}:{ip.data.dport}')
                udpSessions.append((ip.src, ip.data.sport, ip.dst, ip.data.dport))
                udpSessionsCounter += 1
    # IP if end



print(f'{totalCounter} pacotes no total')
print(f'{ipCounter} pacotes IP')
print(f'{tcpCounter} pacotes TCP')
print(f'{udpCounter} pacotes UDP')
print(f'{tcpSessionsCounter} sessões TCP')
print(f'{udpSessionsCounter} sessões UDP')
print(f'{totalCounter - ipCounter} pacotes não-IP')