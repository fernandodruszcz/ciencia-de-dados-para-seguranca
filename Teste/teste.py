fileName = "../../../syn-dos.pcap"

f = open(fileName, 'rb')
for i in range(4):
    dataLine = f.readline()
    
print(dataLine)