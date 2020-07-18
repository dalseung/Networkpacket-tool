from winreg import *
import dpkt, pcap, protocol

devs = pcap.findalldevs()
net = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"
reg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
key = OpenKey(reg, net)
lst = []
for i in range(1024):
    try:
        keyname = EnumKey(key,i)
        try:
            for j in range(1024):
                route = net +"\\" + str(keyname)
                key2 = OpenKey(reg, route)
                a,b,c = EnumValue(key2,j)
                if 'Wireless' in str(b):
                    lst.append('WIFI')
                elif 'Realtek PCIe GbE Family Controller' in str(b):
                    lst.append('Ethernet')
                else:
                    lst.append(b)
        except:
            pass
    except:
        pass

for i in range(len(devs)):
    # print(devs[i][12:])
    for j in range(0,len(lst),2):
        if lst[j] == devs[i][12:]:
            print(str(i) + " : " + str(devs[i]) + '  (' + str(lst[j+1]) + ')')
    

index = int(input("네트워크 인터페이스를 고르시오 : "))

pc = pcap.pcap(name=devs[index])

for t, p in pc:
    protocol.ether(p)
