from scapy.all import *

scapy_cap = rdpcap('Node1.pcap')
a=0
b=0
c=0
d=0
e=0
f=0
g=0
h=0
i=0
j=0
k=0
l=0
m=0
n=0
p=0
q=0
count1=0
count2=0
count3=0
count4=0
count5=0
count6=0
RTT=0
list1=[]
for packet in scapy_cap:
    if(packet.haslayer('ICMP')):
        list1.append(packet)
        if(packet[ICMP].type == 8):
##            if(packet[IP].dst == '192.168.100.2'):
##                a=a+1
##                b=b+len(packet)
##                c=packet['IP'].len
##                c=c-20-8
##                d=d+c
##            elif(packet[IP].dst == '192.168.200.1'):
##                a=a+1
##                b=b+len(packet)
##                c=packet['IP'].len
##                c=c-20-8
##                d=d+c
##            elif(packet[IP].dst == '192.168.200.2'):
##                a=a+1
##                b=b+len(packet)
##                c=packet['IP'].len
##                c=c-20-8
##                d=d+c
            if(packet[IP].src == '192.168.100.1' and packet[IP].dst == '192.168.100.2'):
                a=a+1
                b=b+len(packet)
                c=packet['IP'].len
                c=c-20-8
                d=d+c
                i=i+1
                count1=count1+packet.time
            elif(packet[IP].src == '192.168.100.1' and packet[IP].dst == '192.168.200.1'):
                a=a+1
                b=b+len(packet)
                c=packet['IP'].len
                c=c-20-8
                d=d+c
                j=j+1
                count3=count3+packet.time
            elif(packet[IP].src == '192.168.100.1' and packet[IP].dst == '192.168.200.2'):
                a=a+1
                b=b+len(packet)
                c=packet['IP'].len
                c=c-20-8
                d=d+c
                k=k+1
                count5=count5+packet.time
            if(packet[IP].dst == '192.168.100.1'):
                e=e+1
                f=f+len(packet)
                g=packet['IP'].len
                g=g-20-8
                h=h+g
            if(packet[IP].src == '192.168.100.2'):
                l=l+1
            if(packet[IP].src == '192.168.200.1'):
                m=m+1
            if(packet[IP].src == '192.168.200.2'):
                n=n+1
##            if(packet[IP].src == '192.168.100.1'):
##                q=q+1
            
        if(packet[ICMP].type == 0):
##             if(packet[IP].dst == '192.168.100.1'):
##                 p=p+1
             if(packet[IP].src == '192.168.100.2' and packet[IP].dst == '192.168.100.1'):
                count2=count2+packet.time
             if(packet[IP].src == '192.168.200.1' and packet[IP].dst == '192.168.100.1'):
                count4=count4+packet.time
             if(packet[IP].src == '192.168.200.2' and packet[IP].dst == '192.168.100.1'):
                count6=count6+packet.time
        
                 
RTT=(count2-count1+count4-count3+count6-count5)/a          
                
print("Echo requests sent = "+str(a))
print("Echo request bytes sent = "+str(b))
print("Echo request data sent = "+str(d))
print("Echo requests received = "+str(e))
print("Echo request bytes received = "+str(f))
print("Echo request data received = "+str(h))
print("Echo requests sent to Node 2 = "+str(i))
print("Echo requests sent to Node 3 = "+str(j))
print("Echo requests sent to Node 4 = "+str(k))
print("Echo requests received from Node 2 = "+str(l))
print("Echo requests received from Node 3 = "+str(m))
print("Echo requests received from Node 4 = "+str(n))
##print("Number of echo replies to node 1 is "+str(p))
##print("Number of echo requests by node 1 is "+str(q))
print("Avgerage Echo Request RTT = "+str(RTT*1000))


