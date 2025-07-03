from flask import Flask, render_template, request, send_file
from scanner import scan_target
import socket
import pdfkit
import os
from datetime import datetime

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    target = ''
    if request.method == 'POST':
        target = request.form.get('target')
        if not target:
            error = "Target is required."
        else:
            try:
                resolved_ip = socket.gethostbyname(target)
                result = scan_target(resolved_ip)
                result['resolved_ip'] = resolved_ip
                result['original_target'] = target
                if result.get('status') == 'error':
                    error = result.get('message')
                    result = None
            except socket.gaierror:
                error = f"Could not resolve domain name: {target}"
    return render_template('index.html', result=result, error=error)

@app.route('/download-pdf', methods=['POST'])
def download_pdf():
    from flask import render_template_string

    result_data = request.form.to_dict(flat=False)
    html_content = render_template_string("""
        <h1>Scan Report for {{ target }}</h1>
        <p><strong>Resolved IP:</strong> {{ ip }}</p>
        <p><strong>Detected OS:</strong> {{ os }}</p>
        <h2>Open Ports</h2>
        <ul>
            {% for port in ports %}
                <li>{{ port }}</li>
            {% endfor %}
        </ul>
    """, target=result_data.get('target')[0], ip=result_data.get('ip')[0], os=result_data.get('os')[0], ports=result_data.get('ports'))

    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = f"reports/scan_report_{timestamp}.pdf"
    pdfkit.from_string(html_content, pdf_path)
    return send_file(pdf_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
