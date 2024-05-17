Voici un exemple de fichier README pour votre dépôt GitHub, présentant et récapitulant les fonctionnalités de votre toolbox :

---

# ToolBox

ToolBox is a comprehensive cybersecurity toolkit designed to perform various network security tasks. This includes host scanning, exploit searching, authentication testing, vulnerability exploitation, and detailed reporting. ToolBox leverages powerful tools like Shodan, Nmap, and custom scripts to provide a wide range of functionalities.

## Features

### 1. Host Search by Keyword
Search for hosts based on specific keywords using Shodan.

### 2. Host Scanning
Perform host scans using either Shodan or Nmap to gather information about the target.

- **Shodan Scan**: Retrieves information such as IP address, organization, operating system, open ports, and associated CVEs.
- **Nmap Scan**: Performs a version scan on the target host, gathering details about open ports, services, versions, and associated CVEs.

### 3. Exploit Search by CVE
Search for exploits based on CVE identifiers.

### 4. Authentication Testing
Test the authentication mechanisms of a target host.

- **Brute Force SSH**: Perform a brute force attack on an SSH service.
- **Anonymous FTP Login**: Test for anonymous login on an FTP server.

### 5. Vulnerability Exploitation
Execute various exploits against target hosts.

- **Shellcode Execution**
- **Reverse TCP**
- **Listener Setup**

### 6. Reporting
Generate detailed HTML reports based on scan results from Shodan and Nmap.

- **Shodan Report**: Create an HTML report from Shodan scan results.
- **Nmap Report**: Create an HTML report from Nmap scan results.

### 7. Local Network Scanning
Scan the local network for active hosts.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/toolbox.git
    cd toolbox
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Set up your Shodan API key:
    - Open the `ToolBox.py` file and set your Shodan API key in the `self.API_KEY` variable.

## Usage

1. Run the toolbox:
    ```bash
    python ToolBox.py
    ```

2. Follow the on-screen prompts to navigate through the various functionalities.

## Menu Options

### Main Menu
- **1. Search Host by Keyword**: Search for hosts based on a keyword using Shodan.
- **2. Scan Host**: Choose between scanning with Shodan or Nmap.
- **3. Search Exploit by CVE**: Find exploits related to specific CVE identifiers.
- **4. Test Authentication**: Perform brute force SSH attacks or test anonymous FTP login.
- **5. Exploit Vulnerabilities**: Execute various exploits against a target host.
- **6. Reporting**: Generate HTML reports based on scan results.
- **7. Scan Local Network**: Scan the local network for active hosts.
- **info**: Get information about using the toolbox.
- **quit**: Exit the toolbox.

### Scan Host Menu
- **1. Scan with Shodan**: Perform a host scan using Shodan.
- **2. Scan with Nmap**: Perform a host scan using Nmap.
- **0. Back to Main Menu**: Return to the main menu.

### Reporting Menu
- **1. Generate Shodan Report**: Create an HTML report from Shodan scan results.
- **2. Generate Nmap Report**: Create an HTML report from Nmap scan results.
- **0. Back to Main Menu**: Return to the main menu.

### Authentication Testing Menu
- **1. Brute Force SSH**: Perform a brute force attack on an SSH service.
- **2. Ftp Anonymous**: Test for anonymous login on an FTP server.
- **3. Auth_Z**: Placeholder for additional authentication tests.
- **0. Back to Main Menu**: Return to the main menu.

## Contributing

Feel free to fork this repository and submit pull requests. Your contributions are always welcome!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational and ethical testing purposes only. The author is not responsible for any misuse or damage caused by this tool. Always obtain permission before running any scans or exploits on a network.

---

Feel free to customize the README further to fit your specific needs and repository structure.
