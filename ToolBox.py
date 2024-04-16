import utils
import shodan
import os
import hasard
import json
import uuid

class ToolBox():
    def __init__(self):
        self.API_KEY = "gh8Ixz0zc2YxQXARZqay75sR7vxeTz6H"
        self.API_KEY_SHODAN = shodan.Shodan(self.API_KEY)
        self.results = []

#Fonction Menu
    def man(self):
        print(utils.Couleur.ORANGE + "******************************" + utils.Couleur.FIN + " Welcome Challenger " + utils.Couleur.ORANGE + "******************************" + utils.Couleur.FIN + "\n")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "1 - Scan hôte")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "2 - Tests d'authentification")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "3 - Exploitation de vulnéranilités")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "4 - Reporting")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "'info' - Information concernant l'utilisation de la Toolbox")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "'quit' - pour quitter l'outil\n")

    def manExploit(self):
        print(utils.Couleur.ORANGE + "******************************" + utils.Couleur.FIN + " Welcome Challenger " + utils.Couleur.ORANGE + "******************************" + utils.Couleur.FIN + "\n")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "1 - Scan hôte")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "2 - Tests d'authentification")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "3 - Exploitation de vulnéranilités")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "4 - Reporting")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "'info' - Information concernant l'utilisation de la Toolbox")
        print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "'quit' - pour quitter l'outil\n")


    def scanPort(self, IP_CIBLE):
        try:
            # Effectue une recherche Shodan pour l'adresse IP donnée
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
        bol = True

        while bol:
            userEntry = input(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer une commande\n")

            if userEntry == "quit":
                break

            elif userEntry == "5":
                self.reporting()

            elif userEntry == "1":
                entryHost = input(
                utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Veuillez entrer l'adresse ip de destination\n")
                print(utils.Couleur.MAGENTA + "[*] " + utils.Couleur.FIN + "Recherche d'information sur... %s" % entryHost, "\n")
                toolbox.scanPort(entryHost)



if __name__ == "__main__":
    toolbox = ToolBox()
    toolbox.main()
    toolbox.save_results_to_json("shodan_results.json")
    print("Les résultats ont été sauvegardés dans shodan_results.json")