from scapy.all import  sniff , IP ,Raw




def packetsniffed(packet):
    if IP in packet:
        ip_sorce=packet[IP].src
        ip_dest=packet[IP].dst
        protocall = packet[IP].proto
        payload = packet[IP].payload 
        print(f"source ip :{ip_sorce}")
        print(f"destinatio ip :{ip_dest}")
        print(f"ptotocal is : {protocall}")
        print(f"payload is : { payload}")

        if packet.haslayer(Raw) and b"POST" in packet[Raw].load:
            print("POST request detected")
            
            data=packet[Raw].load.decode('utf-8', errors='ignore')
            term=['uname', 'username', 'pass', 'password', 'user', 'upass', 'email', 
                    'pwd', 'pswd', 'login', 'usr', 'passwd', 'user_id', 'uid', 
                    'session_key', 'auth', 'token', 'access_token', 'secret', 
                    'pin', 'code','number','num','cookie','USER','admin','administrator','name','POST'] # i have added post so that if the payload title is not faund we can get the post data . may be we can get the payload from there 
            for i in term:
                if i in data:
                    print(f"\033[92mPossible credentials detected : {data}\033[m")
                    break




iface = "Realtek RTL8852AE WiFi 6 802.11ax PCIe Adapter"
print(f"Starting packet sniffer on interface: {iface}")
sniff(iface=iface, prn=packetsniffed, store=False)



