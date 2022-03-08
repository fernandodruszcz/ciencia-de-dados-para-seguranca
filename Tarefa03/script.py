# Script para contar a quantidade de amostras de cada dispositivo
import csv
from numpy import NAN
import pandas
import os

macToDevice = {
    "ec1a59832811" : "WEMO Motion Sensor",
    "ec1a5979f489" : "WEMO Power Switch",
    "00166cab6b88" : "Samsung Camera",
    "50c7bf005639" : "TP Link Plug",
    "70ee50183443" : "Netatmo Camera",
    "0017882b9a25" : "Huebulb",
    "44650d56ccd3" : "AmazonEcho",
    "f4f5d88f0a3c" : "chromecast",
    "74c63b29d71d" : "ihome",
    "d073d5018308" : "lifx"
}


# ======== Inicio programa ======== #


# ----- Pega so os arquivos csv de ./flowdata/
arqs = os.scandir('./flowdata/')
csvs = []

for i in arqs:
    if(i.name[-3:] == 'csv'):
        csvs.append(i.name)

# ----- Le a quantidade de amostras de cada dispositivo
firstRead = 1
for i in csvs:
    f = open('./flowdata/' + i)
    reader = csv.reader(f)
    mac = i[:-14]
    if(firstRead):
        print("*** Dados da primeira linha do primeiro dispositivo como exemplo ***")
        firstRead = 0
        params = reader.__next__()
        firstLine = reader.__next__()
        k = 0
        for p in range(len(params)):
            k += 1
            print(f'{params[p]} : {firstLine[p]}')
        print("FIM Dados da primeira linha do primeiro dispositivo como exemplo ***")
        print(f'As amostras têm {k} atributos')
    print(f'Dispositivo {macToDevice[mac.lower()]} tem {len(list(reader))} amostras')
    f.close()

# ----- Le e imprime os ataques feitos

atkInfoReader = pandas.read_excel('attackinfo.xlsx', 'Experiments')
atkInfo = pandas.DataFrame(atkInfoReader, columns=['Attack'])

atkTypes = []
for row in range(atkInfo.shape[0]):
    if atkInfo.at[row, 'Attack'] not in atkTypes:
        atkTypes.append(atkInfo.at[row, 'Attack'])
atkTypes.remove(NAN)
atkTypes.remove('Attack')


print("*** Tipos de ataques ***")
for atk in atkTypes:
    print(atk)
print("FIM Tipos de ataques ***")

