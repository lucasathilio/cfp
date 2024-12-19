import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse  # Importando a biblioteca argparse para capturar argumentos

# Dicionário para armazenar os hosts ativos e suas portas abertas
scan_results = {}

def scan_host(ip):
    try:
        # Tenta abrir uma conexão TCP na porta 80 (HTTP)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)  # Timeout de 100ms para acelerar a detecção
            result = s.connect_ex((ip, 80))  # Retorna 0 se a conexão for bem-sucedida
            if result == 0:
                print(f"[+] Host ativo: {ip}")
                scan_results[ip] = []  # Inicializa a lista de portas abertas para o host
    except Exception:
        pass  # Ignorar erros silenciosamente

def port_scan(ip, max_threads):
    """Escaneia as portas de um IP ativo usando múltiplas threads para acelerar."""
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Escaneia portas de 1 até 65536, por exemplo
        executor.map(lambda port: check_port(ip, port), range(1, 65536))

def check_port(ip, port):
    """Verifica uma porta específica em um host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)  # Timeout de 100ms
            result = s.connect_ex((ip, port))
            if result == 0:
                scan_results[ip].append(port)  # Adiciona a porta aberta ao host
                print(f"    [+] Port {port}")
    except Exception:
        pass

def main():
    # Configuração do parser de argumentos
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument('--threads', type=int, default=200, help='Número de threads para a varredura (padrão: 200)')
    args = parser.parse_args()
    max_threads = args.threads  # Obter o número de threads do argumento

    # Obtém o IP local
    local_ip = get_local_ip()
    print("=" * 59)
    print(" Network Scan")
    print("=" * 59)
    print(f"IP desta máquina: {local_ip}\n")
    print("=" * 59)
    t1 = datetime.now()
    # Calcula a sub-rede
    base_ip = ".".join(local_ip.split(".")[:3]) + "."
    print(f"Iniciando varredura para {base_ip}0/24 às {t1}")
    print("=" * 59)

    # Usar ThreadPoolExecutor para paralelizar a verificação de hosts
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for i in range(1, 255):  # Varredura de 1 a 254
            ip = base_ip + str(i)
            executor.submit(scan_host, ip)

    t2 = datetime.now()
    num_hosts = len(scan_results)  # Quantidade de hosts ativos descobertos
    print("=" * 45)
    print(f"{num_hosts} Hosts descobertos em: {t2 - t1}")
    print("=" * 45)

    # Escaneamento de portas nos hosts ativos
    if scan_results:
        print("\nIniciando varredura de portas nos hosts ativos...")
        print("=" * 59)
        
        for ip in scan_results.keys():
            print(f"\n [!] Host {ip}")
            port_scan(ip, max_threads)  # Passa o número de threads como argumento
    else:
        print("Nenhum host ativo encontrado!")

    # Exibir os resultados da varredura
    print("\n[+] Resultados da varredura:")
    print("=" * 59)
    for ip, ports in scan_results.items():
        if ports:
            print(f"[!] Host: {ip.ljust(15)}  [*] Ports: " + ", ".join(map(str, ports)))
        else:
            print(f"[!] Host: {ip.ljust(15)}  Nenhuma porta aberta detectada")
    print("=" * 59)

    t3 = datetime.now()
    print("Varredura completa em: ", t3 - t1)
    print("=" * 45)

def get_local_ip():
    """Obtém o IP local usando um socket."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))  # Conecta ao DNS público
        return s.getsockname()[0]

if __name__ == "__main__":
    main()
