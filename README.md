# network-vuln-scanner
A web-based Network Vulnerability Scanner that uses Nmap to detect open ports, identify operating systems, and generate downloadable PDF reports for vulnerability analysis.
# Network Vulnerability Scanner

A web-based tool that uses Nmap to scan IP addresses or domains for open ports, detect operating systems, and generate downloadable PDF reports. Built with Python and Flask.

## 🚀 Features

- 🔍 Scan target IP/domain using Nmap
- 🖥️ Detect open ports and services
- 🧠 Perform OS fingerprinting
- 📄 Generate and download PDF scan reports
- 🌐 Web-based interface with simple input and results

## 🛠️ Technologies Used

- Python 3
- Flask
- Nmap
- PDF generation library (like ReportLab/FPDF)
- HTML/CSS (Bootstrap or custom)



## ⚙️ How to Run Locally

1. Clone the repository
   ```bash
   git clone https://github.com/YOUR_USERNAME/network-vulnerability-scanner.git
   cd network-vulnerability-scanner

2. Create a virtual environment
   ```bash
    python -m venv venv
   Kali: source venv/bin/activate
   Windows: venv\Scripts\activate

4. Install dependencies
   ```bash
     pip install -r requirements.txt

6. Run the app
    ```bash
     python app.py

8. Visit in browser
   ```bash
     http://127.0.0.1:5000
