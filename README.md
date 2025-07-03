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

Create a virtual environment
  python -m venv venv
  source venv/bin/activate    # On Windows: venv\Scripts\activate

Install dependencies
  pip install -r requirements.txt

Run the app
  python app.py

Visit in browser
  http://127.0.0.1:5000
