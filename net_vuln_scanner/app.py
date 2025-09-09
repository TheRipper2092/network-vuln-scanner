# app.py
from flask import Flask, render_template, request, redirect, url_for, session, send_file
import subprocess
import re
import socket
from scanner import scan_target, get_all_nmap_scripts
from pdf_utils import generate_scan_pdf

app = Flask(__name__)
app.secret_key = 'replace-this-with-a-strong-key' # Remember to use a strong, unique key for production!

# Scan options as a map of keys to nmap flags
SCAN_OPTIONS = {
    'os_detection': '-O',
    'version_detection': '-sV',
    'agg_scan': '-A',
    'default_scripts': '-sC',
    'fast_scan': '-T4',
    'no_ping': '-Pn',
    'top_ports': '--top-ports 100',
    'udp_scan': '-sU',
    'traceroute': '--traceroute'
}

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Main route to handle the input form for scan parameters.
    It performs basic validation and stores the data in a session.
    """
    error = None
    all_scripts = get_all_nmap_scripts()
    selected_scripts = []

    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        # Removed the arbitrary limit on the number of scan options
        selected_options_keys = request.form.getlist('scan_option')
        selected_scripts = request.form.getlist('scripts')

        if not target:
            error = "Target is required."
        else:
            try:
                # Validate if target resolves to a valid IP address
                socket.gethostbyname(target)
                nmap_options = [SCAN_OPTIONS[k] for k in selected_options_keys if k in SCAN_OPTIONS]
                session['scan_data'] = {
                    'target': target,
                    'options': nmap_options,
                    'scripts': selected_scripts
                }
                # Redirect to the scan report page to avoid form resubmission
                return redirect(url_for('scan_report'))
            except socket.gaierror:
                error = f"Could not resolve: {target}"
            except Exception as e:
                # Catch any other unexpected errors during validation
                error = f"An unexpected error occurred: {str(e)}"

    return render_template('index.html', scan_options=SCAN_OPTIONS, error=error, all_scripts=all_scripts, selected_scripts=selected_scripts)

@app.route('/scan-report')
def scan_report():
    """
    Handles the execution of the Nmap scan and displays the results.
    It retrieves the scan parameters from the session.
    """
    scan_data = session.get('scan_data')
    if not scan_data:
        # Redirect if no scan data is found in the session
        return redirect(url_for('index'))

    target = scan_data['target']
    options = scan_data.get('options', [])
    scripts = scan_data.get('scripts', [])

    # Call the scan_target function from scanner.py
    # This is a blocking call, so the user will see a loading screen
    result = scan_target(target, options, scripts)

    # Use the result from the scan_target function to display the report
    if result['status'] == 'error':
        # If the scan failed, show an error message
        return render_template('report.html', result=result, cmd='', target=target, error=result['message'])
    
    # Construct the full command string for display purposes
    nmap_cmd = ['nmap'] + options
    if scripts:
        nmap_cmd.append(f"--script={','.join(scripts)}")
    nmap_cmd.append(target)

    # Store the results in the session for the PDF download route
    session['last_result'] = result
    session['nmap_cmd'] = ' '.join(nmap_cmd)
    
    # Render the report with the scan results and command
    return render_template('report.html', result=result, cmd=' '.join(nmap_cmd), target=target)

@app.route('/download-pdf')
def download_pdf():
    """
    Generates and serves a PDF of the last scan report.
    """
    scan_data = session.get('scan_data')
    result = session.get('last_result')
    nmap_cmd = session.get('nmap_cmd')

    if not scan_data or not result or not nmap_cmd:
        # Redirect to the main page if there's no data to generate a PDF
        return redirect(url_for('index'))

    # Generate the PDF and send it as a file
    pdf_buffer = generate_scan_pdf({**scan_data, **result}, nmap_cmd)
    return send_file(pdf_buffer, as_attachment=True, download_name='nmap_scan_report.pdf', mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)
