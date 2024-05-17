import utils
import shodan
import hasard
import json
import uuid
import paramiko
import threading
import time
import sys
import os
import requests
import ftplib
import subprocess
import nmap

class ToolBox():
    def __init__(self):
        self.API_KEY = "gh8Ixz0zc2YxQXARZqay75sR7vxeTz6H"
        self.API_KEY_SHODAN = shodan.Shodan(self.API_KEY)
        self.results = []
        self.host = None
        self.username = None
        self.input_file = None
        self.stop_flag = 0



####### Fonction Menu #######
    def man(self):
        while True:
            print(utils.Couleur.ORANGE + "******************************" + utils.Couleur.FIN + " ToolBox " + utils.Couleur.ORANGE + "******************************" + utils.Couleur.FIN + "\n")
            print(utils.Couleur.MAGENTA + "[1] " + utils.Couleur.FIN + "Recherche hôte par mot clé")
            print(utils.Couleur.MAGENTA + "[2] " + utils.Couleur.FIN + "Scan hôte")
            print(utils.Couleur.MAGENTA + "[3] " + utils.Couleur.FIN + "Recherche d'exploit par CVE")
            print(utils.Couleur.MAGENTA + "[4] " + utils.Couleur.FIN + "Test d'authentification")
            print(utils.Couleur.MAGENTA + "[5] " + utils.Couleur.FIN + "Exploitation de vulnérabilités")
            print(utils.Couleur.MAGENTA + "[6] " + utils.Couleur.FIN + "Reporting")
            print(utils.Couleur.MAGENTA + "[7] " + utils.Couleur.FIN + "Scan les adresses sur le réseau\n")
            print(utils.Couleur.MAGENTA + "[info] " + utils.Couleur.FIN + "Information concernant l'utilisation de la Toolbox")
            print(utils.Couleur.MAGENTA + "[quit] " + utils.Couleur.FIN + "Pour quitter l'outil\n")

            choice = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer une commande: ")

            if choice == '1':
                entryKeyWord = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer le mot clé: ")
                self.shearchByKeyWord(entryKeyWord)
            elif choice == '2':
                    self.host_scan_menu()
            elif choice == '3':
                ip_address = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer l'adresse IP cible: ")
                self.find_cve_details(ip_address=ip_address)
            elif choice == '4':
                self.authentification_menu()
            elif choice == '5':
                self.exploitation_menu()
            elif choice == '6':
                self.reportingMenu()
            elif choice == '7':
                subnet = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer le subnet: ")
                self.scan_local_network(subnet)
            elif choice.lower() == 'info':
                print("voici les info")
            elif choice.lower() == 'quit':
                break
            else:
                print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "Option invalide, veuillez réessayer.")

    def reportingMenu(self):
        while True:
            print(utils.Couleur.ORANGE + "******** Reporting Menu ********" + utils.Couleur.FIN)
            print(utils.Couleur.MAGENTA + "[1] " + utils.Couleur.FIN + "Generate Shodan Report")
            print(utils.Couleur.MAGENTA + "[2] " + utils.Couleur.FIN + "Generate Nmap Report")
            print(utils.Couleur.MAGENTA + "[0] " + utils.Couleur.FIN + "Back to Main Menu")

            choice = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Please enter an option: ")

            if choice == '1':
                self.reportingShodan()
            elif choice == '2':
                self.reportingNmap()
            elif choice == '0':
                break
            else:
                print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "Invalid option, please try again.")

    def reportingShodan(self):
        ip_address = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Enter the IP address for the report: ")
        data = self.find_ip_data("shodan_results.json", ip_address)
        if data:
            self.create_html_report_shodan(data, f"Shodan_Report_{ip_address}.html")
        else:
            print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "No data found for this IP address.")

    def reportingNmap(self):
        ip_address = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Entrez l'adresse IP pour le rapport: ")
        data = self.find_ip_data("nmap_scan_results.json", ip_address)
        if data:
            self.create_html_report_nmap(data, f"Nmap_Report_{ip_address}.html")
        else:
            print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "Aucune donnée trouvée pour cette adresse IP.")

    def host_scan_menu(self):
        while True:
            print("\n" + utils.Couleur.ORANGE + "******* Scan Hôte *******" + utils.Couleur.FIN)
            print(utils.Couleur.MAGENTA + "[1] " + utils.Couleur.FIN + "Scan avec Shodan")
            print(utils.Couleur.MAGENTA + "[2] " + utils.Couleur.FIN + "Scan avec Nmap")
            print(utils.Couleur.MAGENTA + "[0] " + utils.Couleur.FIN + "Retour au menu principal")

            choice = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer une option: ")

            if choice == '1':
                ip_address = input(
                    utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Entrez l'adresse IP à scanner: ")
                self.scan_host_shodan(ip_address)
                break  # Sortie après le scan
            elif choice == '2':
                ip_address = input(
                    utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Entrez l'adresse IP à scanner: ")
                self.scan_host_nmap(ip_address)
                break  # Sortie après le scan
            elif choice == '0':
                break
            else:
                print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "Option invalide, veuillez réessayer.")

    def exploitation_menu(self):
        while True:
            print("\n" + utils.Couleur.ORANGE + "******* Exploitation de Vulnérabilités *******" + utils.Couleur.FIN)
            print(utils.Couleur.MAGENTA + "[1] " + utils.Couleur.FIN + "Shellcode")
            print(utils.Couleur.MAGENTA + "[2] " + utils.Couleur.FIN + "Reverse TCP")
            print(utils.Couleur.MAGENTA + "[3] " + utils.Couleur.FIN + "Ecouteur")
            print(utils.Couleur.MAGENTA + "[0] " + utils.Couleur.FIN + "Retour au menu principal")

            choice = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer une option: ")

            if choice == '1':
                self.run_exploit_x()
            elif choice == '2':
                self.run_exploit_y()
            elif choice == '3':
                self.run_exploit_z()
            elif choice == '0':
                break
            else:
                print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "Option invalide, veuillez réessayer.")

    def authentification_menu(self):
        while True:
            print("\n" + utils.Couleur.ORANGE + "******* Test d'authification *******" + utils.Couleur.FIN)
            print(utils.Couleur.MAGENTA + "[1] " + utils.Couleur.FIN + "Brute force SSH")
            print(utils.Couleur.MAGENTA + "[2] " + utils.Couleur.FIN + "Ftp Anonymous")
            print(utils.Couleur.MAGENTA + "[3] " + utils.Couleur.FIN + "Auth_Z")
            print(utils.Couleur.MAGENTA + "[0] " + utils.Couleur.FIN + "Retour au menu principal")

            choice = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer une option: ")
            if choice == '1':
                self.start_bruteforce()
            elif choice == '2':
                ftp_host = input(
                    utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Entrez l'adresse du serveur FTP à tester : ")
                self.test_ftp_anonymous(ftp_host)
            elif choice == '3':
                self.start_ftpBruteForce()
            elif choice == '0':
                break
            else:
                print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "Option invalide, veuillez réessayer.")

    def scan_host_nmap(self, ip_adress, output_file='nmap_scan_results.json'):
        nm = nmap.PortScanner()  # Création d'un objet PortScanner
        nm.scan(hosts=ip_adress, arguments='-sV')  # -sV pour scanner avec détection de version des services

        scan_results = {}
        for host in nm.all_hosts():
            if nm[host].state() == 'up':  # Vérifie si l'hôte est actif
                host_data = {
                    'hostname': nm[host].hostname(),
                    'state': nm[host].state(),
                    'protocols': {}
                }
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    host_data['protocols'][proto] = {}
                    for port in ports:
                        service_info = nm[host][proto][port]
                        host_data['protocols'][proto][port] = {
                            'state': service_info['state'],
                            'service': service_info.get('name', ''),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'extra_info': service_info.get('extrainfo', '')
                        }
                scan_results[host] = host_data

        # Sauvegarde des résultats dans un fichier JSON
        with open(output_file, 'w') as file:
            json.dump(scan_results, file, indent=4)

        print(f"Results saved to {output_file}")

    def scan_local_network(self, subnet):
        nm = nmap.PortScanner()  # Crée un objet PortScanner
        nm.scan(hosts=subnet, arguments='-sn')  # -sn pour le scan de découverte sans scan de ports

        active_hosts = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(f"Host {host} is up.")
                active_hosts.append(host)

        return active_hosts

    def test_ftp_anonymous(self, host):
        try:
            with ftplib.FTP(host) as ftp:
                ftp.login()  # login anonyme
                print(f"Connexion FTP anonyme réussie à {host}")
                ftp.dir()  # Affiche les contenus du répertoire par défaut
        except ftplib.all_errors as e:
            print(f"Échec de la connexion FTP anonyme à {host}: {e}")

    def shearchByKeyWord(self, KEY_WORD):
        try:
            infoByKeyWord = self.API_KEY_SHODAN.search(KEY_WORD)
            print(utils.Couleur.VERT + "[+] " + utils.Couleur.FIN, "Le total d'adresse IP trouvé est de : ", infoByKeyWord["total"], "\n")
            for info in infoByKeyWord["matches"]:
                print(utils.Couleur.VERT + "[+] " + utils.Couleur.FIN, info["ip_str"]+"")

        except Exception as e:
            print(utils.Couleur.ROUGE + "[-] " + utils.Couleur.FIN + "Voici l'erreur renvoyé :\n", e)

    def check_exploit(cve_id):
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        response = requests.get(url)
        data = response.json()
        if 'exploit' in data:
            return data['exploit']
        elif 'summary' in data:
            return data['summary']  # Retourner le résumé si aucun exploit n'est listé
        return "No detailed information available"

    def find_cve_details(self, ip_address, filename='shodan_results.json'):
        try:
            with open(filename, 'r') as file:
                data = json.load(file)
        except FileNotFoundError:
            print(f"[!] Le fichier {filename} n'existe pas.")
            return
        except json.JSONDecodeError:
            print("[!] Erreur de décodage JSON : Le fichier est vide ou mal formé.")
            return
        # Recherche de l'adresse IP dans les données chargées
        for entry in data:
            if entry.get('ip') == ip_address:
                print(f"Exploits trouvés pour l'adresse {ip_address}:")
                for port_info in entry.get('ports', []):
                    cve_details = port_info.get('cve_details', {})
                    if cve_details:
                        print(f"Port {port_info['port']}:")
                        for cve, details in cve_details.items():
                            print(f"  {cve} - {details}")
                    else:
                        print(f"Port {port_info['port']}: Aucun CVE trouvé.")
                break
        else:
            print(f"Aucune information trouvée pour l'adresse IP {ip_address}.")
        print("Aucun format compatible à l'injection trouvé")

    def ssh_connect(self, password):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(self.host, port=22, username=self.username, password=password)
            self.stop_flag = 1
            print(utils.Couleur.VERT + "[*] Mot de passe trouvé: " + password + " pour le compte: "+ self.username + utils.Couleur.FIN)
        except:
            print(utils.Couleur.ROUGE +"[-] Login incorrecte: " + password + utils.Couleur.FIN)
        finally:
            ssh.close()

    def start_bruteforce(self):
        self.host = input('[+] Target Address: ')
        self.username = input('[+] SSH Username: ')
        self.input_file = input('[+] Passwords File: ')
        print('\n')

        if not os.path.exists(self.input_file):
            print('[!!] That File/Path Does Not Exist')
            sys.exit(1)

        print('Brute force sur ' + self.host + ' avec comme user: ' + self.username + ' * * *')

        with open(self.input_file, 'r') as file:
            for line in file.readlines():
                if self.stop_flag == 1:
                    break
                password = line.strip()
                t = threading.Thread(target=self.ssh_connect, args=(password,))
                t.start()
                time.sleep(1)

    def scan_host_shodan(self, IP_CIBLE):
        try:
            results = self.API_KEY_SHODAN.host(IP_CIBLE)
            print(f"Adresse IP : {results['ip_str']}")
            print(f"Organisation : {results.get('org', 'N/A')}")
            print(f"Système d'exploitation : {results.get('os', 'N/A')}")
            print(f"Ports : {', '.join(str(port) for port in results['ports'])}")

            # Création d'un identifiant unique pour les résultats de ce scan
            unique_id = str(uuid.uuid4())

            # Affiche les services associés aux ports
            for service in results['data']:
                print(
                    f"Port {service['port']} ({service.get('transport', 'N/A')}): {service.get('product', 'N/A')} {service.get('version', '')}")
                if 'vulns' in service:
                    vulns_info = service['vulns']
                    cve_details = []
                    for cve in vulns_info.keys():
                        if cve.startswith('CVE-'):
                            cve_details.append({cve: vulns_info[cve]['summary']})
                    print(f"CVEs: {cve_details}")

            # Ajoute les informations à la liste des résultats
            self.results.append({
                'id': unique_id,
                'ip': results['ip_str'],
                'org': results.get('org', 'N/A'),
                'os': results.get('os', 'N/A'),
                'ports': [{'port': service['port'], 'cve_details': service.get('vulns', {})} for service in
                          results['data']]
            })
        except shodan.APIError as e:
            print(f"Erreur : {e}")

    def save_results_to_json(self, filename):
        existing_data = []  # Initialiser à une liste vide par défaut
        # Vérifie si le fichier existe et contient des données
        if os.path.exists(filename):
            with open(filename, 'r') as json_file:
                try:
                    existing_data = json.load(json_file)  # Tente de charger les données JSON
                except json.JSONDecodeError:
                    print("Le fichier JSON est vide ou mal formé, il sera réinitialisé.")
                    existing_data = []  # Réinitialiser si le fichier est corrompu ou vide

        # Fusionne les nouveaux résultats avec les données existantes
        existing_data.extend(self.results)  # Utilise extend pour ajouter les éléments de la liste

        # Sauvegarde les résultats au format JSON dans un fichier
        with open(filename, 'w') as json_file:
            json.dump(existing_data, json_file, indent=4)  # Indente pour une meilleure lisibilité

    def find_ip_data(self, filename, ip_address):
        try:
            with open(filename, 'r') as file:
                data = json.load(file)
                if isinstance(data, dict):  # Vérifiez si les données sont un dictionnaire
                    if ip_address in data:
                        return data[ip_address]
                elif isinstance(data, list):  # Si c'est une liste, parcourez-la
                    for entry in data:
                        if entry.get('ip') == ip_address:
                            return entry
        except json.JSONDecodeError:
            print("Erreur de lecture du fichier JSON")
        except FileNotFoundError:
            print("Fichier non trouvé")
        return None

    def create_html_report_shodan(self, data, output_filename):
        if not data:
            print("Aucune donnée disponible pour cette IP")
            return

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Scan Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 40px;
                    color: #333;
                    background: #f4f4f9;
                }}
                .container {{
                    max-width: 800px;
                    margin: auto;
                    padding: 20px;
                    background: #fff;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                h1, h2 {{
                    color: #0056b3;
                    text-align: center;
                }}
                .summary {{
                    margin-top: 20px;
                    font-size: 1.2em;
                    line-height: 1.4;
                }}
                .summary strong {{
                    color: #0056b3;
                }}
                table {{
                    width: 100%;
                    margin-top: 20px;
                    border-collapse: collapse;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                th, td {{
                    padding: 12px 15px;
                    border: 1px solid #ddd;
                    text-align: left;
                }}
                th {{
                    background-color: #007bff;
                    color: #ffffff;
                }}
                tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                .cve-links a {{
                    color: #d9534f;
                    text-decoration: none;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>TOOL BOX REPORT</h1>
                <h2>IP Address: {data.get('ip', 'Unknown')}</h2>
                <div class="summary">
                    <p><strong>Location:</strong> {data.get('location', 'Unknown')}</p>
                    <p><strong>Date:</strong> {data.get('date', 'Unknown')}</p>
                </div>

                <h2>PORTS</h2>
                <table>
                    <tr>
                        <th>PORT</th>
                        <th>SERVICE</th>
                        <th>VERSION</th>
                        <th>STATUS</th>
                    </tr>
        """

        for port_info in data.get('ports', []):
            port_number = port_info.get('port', 'N/A')
            service = port_info.get('service', 'N/A')
            version = port_info.get('version', 'N/A')
            state = port_info.get('state', 'open')
            html_content += f"""
                <tr>
                    <td>{port_number}</td>
                    <td>{service}</td>
                    <td>{version}</td>
                    <td>{state}</td>
                </tr>
            """

        html_content += """
                </table>

                <h2>CVEs</h2>
                <table>
                    <tr>
                        <th>CVE</th>
                        <th>LINK</th>
                        <th>IMPACT</th>
                        <th>EXPLOIT</th>
                    </tr>
        """

        for port_info in data.get('ports', []):
            cve_details = port_info.get('cve_details', {})
            for cve, details in cve_details.items():
                link = details.get('link', 'N/A')
                impact = details.get('impact', 'N/A')
                exploit = details.get('exploit', 'N/A')
                html_content += f"""
                    <tr>
                        <td>{cve}</td>
                        <td class="cve-links"><a href="{link}">{link}</a></td>
                        <td>{impact}</td>
                        <td class="cve-links"><a href="{exploit}">{exploit}</a></td>
                    </tr>
                """

        html_content += """
                </table>
            </div>
        </body>
        </html>
        """

        with open(output_filename, 'w') as file:
            file.write(html_content)
        print(f"Rapport HTML sauvegardé sous {output_filename}")

    def create_html_report_nmap(self, data, output_filename):
        if not data:
            print("Aucune donnée disponible pour cette IP")
            return

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Scan Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 40px;
                    color: #333;
                    background: #f4f4f9;
                }}
                .container {{
                    max-width: 800px;
                    margin: auto;
                    padding: 20px;
                    background: #fff;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                h1, h2 {{
                    color: #0056b3;
                    text-align: center;
                }}
                .summary {{
                    margin-top: 20px;
                    font-size: 1.2em;
                    line-height: 1.4;
                }}
                .summary strong {{
                    color: #0056b3;
                }}
                table {{
                    width: 100%;
                    margin-top: 20px;
                    border-collapse: collapse;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                th, td {{
                    padding: 12px 15px;
                    border: 1px solid #ddd;
                    text-align: left;
                }}
                th {{
                    background-color: #007bff;
                    color: #ffffff;
                }}
                tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                .cve-links a {{
                    color: #d9534f;
                    text-decoration: none;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>TOOL BOX REPORT</h1>
                <h2>IP Address: {data.get('ip', 'Unknown')}</h2>
                <div class="summary">
                    <p><strong>Location:</strong> {data.get('location', 'Unknown')}</p>
                    <p><strong>Date:</strong> {data.get('date', 'Unknown')}</p>
                </div>

                <h2>PORTS</h2>
                <table>
                    <tr>
                        <th>PORT</th>
                        <th>SERVICE</th>
                        <th>VERSION</th>
                        <th>STATUS</th>
                    </tr>
        """

        for proto, ports in data.get('protocols', {}).items():
            for port, port_data in ports.items():
                service = port_data.get('service', 'N/A')
                version = port_data.get('version', 'N/A')
                state = port_data.get('state', 'open')
                html_content += f"""
                    <tr>
                        <td>{port}</td>
                        <td>{service}</td>
                        <td>{version}</td>
                        <td>{state}</td>
                    </tr>
                """

        html_content += """
                </table>

                <h2>CVEs</h2>
                <table>
                    <tr>
                        <th>CVE</th>
                        <th>LINK</th>
                        <th>IMPACT</th>
                        <th>EXPLOIT</th>
                    </tr>
        """

        for proto, ports in data.get('protocols', {}).items():
            for port, port_data in ports.items():
                cve_details = port_data.get('cve_details', {})
                for cve, details in cve_details.items():
                    link = details.get('link', 'N/A')
                    impact = details.get('impact', 'N/A')
                    exploit = details.get('exploit', 'N/A')
                    html_content += f"""
                        <tr>
                            <td>{cve}</td>
                            <td class="cve-links"><a href="{link}">{link}</a></td>
                            <td>{impact}</td>
                            <td class="cve-links"><a href="{exploit}">{exploit}</a></td>
                        </tr>
                    """

        html_content += """
                </table>
            </div>
        </body>
        </html>
        """

        with open(output_filename, 'w') as file:
            file.write(html_content)
        print(f"Rapport HTML sauvegardé sous {output_filename}")

    #Partie logique
    def main(self):
        hasard.hasardFunction.randomDesign(self)
        toolbox.man()

if __name__ == "__main__":
    toolbox = ToolBox()
    toolbox.main()
    toolbox.save_results_to_json("shodan_results.json")
    print("Les résultats ont été sauvegardés dans shodan_results.json")