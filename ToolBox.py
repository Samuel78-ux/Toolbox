import utils
import shodan
import hasard
import json
import uuid
from pwn import *
import paramiko
import threading
import time
import sys
import os
import requests



class ToolBox():
    def __init__(self):
        self.API_KEY = "gh8Ixz0zc2YxQXARZqay75sR7vxeTz6H"
        self.API_KEY_SHODAN = shodan.Shodan(self.API_KEY)
        self.host = '192.168.1.10'  # Default listener IP
        self.port = 4444  # Default listener port
        self.results = []
        self.host = None
        self.username = None
        self.input_file = None
        self.stop_flag = 0

####### Fonction Menu #######
    def man(self):
        while True:
            print(utils.Couleur.ORANGE + "******************************" + utils.Couleur.FIN + " ToolBox " + utils.Couleur.ORANGE + "******************************" + utils.Couleur.FIN + "\n")
            print(utils.Couleur.MAGENTA + "[1] " + utils.Couleur.FIN + "Scan hôte")
            print(utils.Couleur.MAGENTA + "[2] " + utils.Couleur.FIN + "Exploitation de vulnérabilités")
            print(utils.Couleur.MAGENTA + "[3] " + utils.Couleur.FIN + "Reporting")
            print(utils.Couleur.MAGENTA + "[4] " + utils.Couleur.FIN + "Test d'authentification")
            print(utils.Couleur.MAGENTA + "[info] " + utils.Couleur.FIN + "Information concernant l'utilisation de la Toolbox")
            print(utils.Couleur.MAGENTA + "[quit] " + utils.Couleur.FIN + "Pour quitter l'outil\n")

            choice = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer une commande: ")

            if choice == '1':
                entryIP = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer l'adresse IP cible: ")
                self.scan_host(entryIP)
            elif choice == '2':
                self.exploitation_menu()
            elif choice == '3':
                self.reporting()
            elif choice.lower() == 'quit':
                break
            elif choice == '4':
                self.authentification_menu()
            else:
                print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "Option invalide, veuillez réessayer.")
    def exploitation_menu(self):
        while True:
            print("\n" + utils.Couleur.ORANGE + "******* Exploitation de Vulnérabilités *******" + utils.Couleur.FIN)
            print(utils.Couleur.MAGENTA + "[1] " + utils.Couleur.FIN + "Exploit_x")
            print(utils.Couleur.MAGENTA + "[2] " + utils.Couleur.FIN + "Exploit_Y")
            print(utils.Couleur.MAGENTA + "[3] " + utils.Couleur.FIN + "Exploit Z")
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
            print(
                "\n" + utils.Couleur.ORANGE + "******* Test d'authification *******" + utils.Couleur.FIN)
            print(utils.Couleur.MAGENTA + "[1] " + utils.Couleur.FIN + "Brute force SSH")
            print(utils.Couleur.MAGENTA + "[2] " + utils.Couleur.FIN + "Auth_Y")
            print(utils.Couleur.MAGENTA + "[3] " + utils.Couleur.FIN + "Auth_Z")
            print(utils.Couleur.MAGENTA + "[0] " + utils.Couleur.FIN + "Retour au menu principal")

            choice = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer une option: ")
            if choice == '1':
                self.start_bruteforce()
            elif choice == '2':
                self.run_auth_y()
            elif choice == '3':
                self.run_auth_z()
            elif choice == '0':
                break
            else:
                print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "Option invalide, veuillez réessayer.")



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
                time.sleep(0.5)  # Adjust sleep time as necessary

    def scan_host(self, IP_CIBLE):
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
                for entry in data:
                    if entry['ip'] == ip_address:
                        return entry
        except json.JSONDecodeError:
            print("Erreur de lecture du fichier JSON")
        except FileNotFoundError:
            print("Fichier non trouvé")
        return None

    from fpdf import FPDF

    def create_html_report(self, data, output_filename):
        if not data:
            print("Aucune donnée disponible pour cette IP")
            return

        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Rapport de Scan</title>
            <style>
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid black; padding: 5px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Rapport de Scan</h1>
            <p><strong>IP:</strong> {ip}</p>
            <p><strong>OS:</strong> {os}</p>
            <p><strong>Organisation:</strong> {org}</p>
            <table>
                <tr>
                    <th>PORT</th>
                    <th>CVE</th>
                </tr>
        """.format(ip=data['ip'], os=data.get('os', 'N/A'), org=data.get('org', 'N/A'))

        for port in data['ports']:
            if isinstance(port, dict):
                port_number = port['port']
                cve_list = port.get('cve_details', {})
                cve_text = ', '.join([f"{cve}: {desc['summary']}" for cve, desc in
                                      cve_list.items()]) if cve_list else "No CVEs associated"
            else:
                port_number = port
                cve_text = "No CVEs associated"

            html_content += f"""
                <tr>
                    <td>{port_number}</td>
                    <td>{cve_text}</td>
                </tr>
            """

        html_content += """
            </table>
        </body>
        </html>
        """

        with open(output_filename, 'w') as file:
            file.write(html_content)
        print(f"Rapport HTML sauvegardé sous {output_filename}")


    def reporting(self):
        ip_address = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Entrez l'adresse IP pour le rapport: ")
        data = self.find_ip_data("shodan_results.json", ip_address)
        if data:
            self.create_html_report(data, f"Rapport_{ip_address}.html")  # Modifier ici pour appeler la création de HTML
        else:
            print(utils.Couleur.ROUGE + "[!] " + utils.Couleur.FIN + "Aucune donnée trouvée pour cette adresse IP.")


#Partie logique
    def main(self):
        hasard.hasardFunction.randomDesign(self)
        toolbox.man()

if __name__ == "__main__":
    toolbox = ToolBox()
    toolbox.main()
    toolbox.save_results_to_json("shodan_results.json")
    print("Les résultats ont été sauvegardés dans shodan_results.json")