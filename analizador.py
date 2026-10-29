import json
from pathlib import Path

LOG_PATH = Path("/var/log/suricata/eve.json")

def analizar_alertas():
    if not LOG_PATH.exists():
        print("[-] No se encontró el archivo eve.json de Suricata.")
        return

    print("[*] Leyendo alertas de Suricata...")
    print("-" * 60)

    with open(LOG_PATH, "r") as f:
        lines = f.readlines()[-10:]
        for line in lines:
            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    sig = data.get("alert", {}).get("signature", "Desconocida")
                    src = data.get("src_ip", "N/A")
                    dst = data.get("dest_ip", "N/A")
                    print(f"[ALERTA DETECTADA]")
                    print(f"  - Origen -> Destino : {src} -> {dst}")
                    print(f"  - Firma / Ataque    : {sig}")
                    print("-" * 60)
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    analizar_alertas()
