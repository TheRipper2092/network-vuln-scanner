# pdf_utils.py
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO

def generate_scan_pdf(scan_data, nmap_cmd):
    """
    Generates a PDF report from scan data.
    
    This function has been updated to:
    1. Use a more robust way of creating lists for recommendations.
    2. Add alternating row colors to the tables for better readability.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18, leftMargin=18, topMargin=18, bottomMargin=18)
    styles = getSampleStyleSheet()
    elements = []

    # Title with a simple, professional look
    title = Paragraph("<b>🛡️ Nmap Scan Detailed Report</b>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # General parameters table
    params_data = [
        ['<b>Target</b>', scan_data.get('target', 'N/A')],
        ['<b>Host OS</b>', scan_data.get('os', 'Unknown')],
        ['<b>Command</b>', nmap_cmd],
        ['<b>Options</b>', ', '.join(scan_data.get('options', [])) or "None"],
        ['<b>Scripts</b>', ', '.join(scan_data.get('scripts', [])) or "None"]
    ]
    table = Table(params_data, colWidths=[80, 420])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#207567')),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        # Add alternating row colors for better readability
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F5F5F5')),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 16))

    elements.append(Paragraph('<b>Open Ports & Services</b>', styles['Heading3']))
    if scan_data.get('ports'):
        port_data = [["Port", "Proto", "Service", "State", "Version", "Script Output"]]
        for port_info in scan_data['ports']:
            port_data.append([
                str(port_info['port']),
                port_info['protocol'],
                port_info['service'],
                port_info['state'],
                port_info['version'] or '',
                "\n".join(f"{k}: {v}" for k, v in port_info.get('script_results', {}).items()) or 'N/A'
            ])
        port_table = Table(port_data, colWidths=[40, 48, 90, 60, 80, 180])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#207567')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#22cfd0')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            # Add alternating row colors for the ports table
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#E0E0E0')),
        ]))
        elements.append(port_table)
    else:
        elements.append(Paragraph("No open ports found.", styles['Normal']))

    elements.append(Spacer(1, 16))
    elements.append(Paragraph('<b>Next Steps & Recommendations:</b>', styles['Normal']))
    
    # Using ListFlowable for proper list formatting
    advice_list = ListFlowable([
        ListItem(Paragraph("Investigate open/critical ports for known exploits or vulnerable services.", styles['Normal'])),
        ListItem(Paragraph("Research product/version banners for CVEs and known issues.", styles['Normal'])),
        ListItem(Paragraph("Try additional NSE scripts relevant to the services found.", styles['Normal'])),
        ListItem(Paragraph("Validate findings and scan with alternative flags (-Pn, -sU, etc.) as needed.", styles['Normal'])),
        ListItem(Paragraph("For web services, follow up with tools like gobuster, nikto, dirsearch, ffuf.", styles['Normal'])),
        ListItem(Paragraph("Only continue with permission and within your bug bounty scope.", styles['Normal']))
    ])
    elements.append(advice_list)

    doc.build(elements)
    buffer.seek(0)
    return buffer
