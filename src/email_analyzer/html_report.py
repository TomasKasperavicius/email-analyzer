from datetime import datetime
from typing import Dict, List, Any
import html


def _escape(val: Any) -> str:
    return html.escape(str(val)) if val is not None else ""


def _extract_latlon(hop: Dict[str, Any]):
    if not hop or not isinstance(hop, dict):
        return None
    geo = hop.get("geo", {})
    if isinstance(geo, dict):
        latitude = geo.get("lat", geo.get("latitude"))
        longitude = geo.get("lon", geo.get("longitude"))
        try:
            if latitude is not None and longitude is not None:
                return float(latitude), float(longitude)
        except (ValueError, TypeError):
            pass
    for lat_key, lon_key in (("lat", "lon"), ("latitude", "longitude")):
        latitude = hop.get(lat_key)
        longitude = hop.get(lon_key)
        try:
            if latitude is not None and longitude is not None:
                return float(latitude), float(longitude)
        except (ValueError, TypeError):
            continue
    return None


def assess_security_issues(report_data: Dict) -> Dict:
    hops = report_data.get('hops', [])
    auth = report_data.get('auth', {})
    issues = {
        'tls_issues': [],
        'authentication_issues': [],
        'geo_issues': [],
        'timing_issues': []
    }
    non_tls_hops = [hop for hop in hops if hop.get('tls') is False]
    if non_tls_hops:
        issues['tls_issues'].append(
            f"{len(non_tls_hops)} hops without TLS encryption")
    auth_results = auth.get('parsed', [])
    for auth_entry in auth_results:
        if auth_entry.get('spf') not in ['pass', None]:
            issues['authentication_issues'].append(
                f"SPF: {auth_entry.get('spf')}")
        if auth_entry.get('dkim') not in ['pass', None]:
            issues['authentication_issues'].append(
                f"DKIM: {auth_entry.get('dkim')}")
        if auth_entry.get('dmarc') not in ['pass', None]:
            issues['authentication_issues'].append(
                f"DMARC: {auth_entry.get('dmarc')}")
    geo_locations = []
    for hop in hops:
        if hop.get('geo') and hop['geo'].get('country'):
            geo_locations.append(hop['geo']['country'])
    unique_countries = len(set(geo_locations))
    if unique_countries > 3:
        issues['geo_issues'].append(
            f"Email routed through {unique_countries} different countries")
    return issues


def generate_security_section(security_issues: Dict) -> str:
    total_issues = sum(len(issues) for issues in security_issues.values())
    if total_issues == 0:
        return """
        <div style="text-align: center; padding: 20px; background: #d4edda; border-radius: 10px;">
            <h3 style="color: #155724;">✅ No Security Issues Detected</h3>
            <p>All security checks passed successfully</p>
        </div>
        """
    html_parts = [f"""
    <div style="background: #f8d7da; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
        <h3 style="color: #721c24;">⚠️ {total_issues} Security Issues Detected</h3>
    </div>
    """]
    for category, issues in security_issues.items():
        if issues:
            html_parts.append(
                f"<div style='margin-bottom:15px;'><h4>{category.replace('_', ' ').title()}:</h4><ul>")
            for issue in issues:
                html_parts.append(f"<li>{_escape(issue)}</li>")
            html_parts.append("</ul></div>")
    return "\n".join(html_parts)


def generate_hops_table(hops: List[Dict]) -> str:
    if not hops:
        return "<p>No hop data available</p>"
    rows = []
    rows.append("""
    <table class="hop-table">
        <thead>
            <tr>
                <th>Hop</th>
                <th>From</th>
                <th>By</th>
                <th>IPs</th>
                <th>TLS</th>
                <th>Location</th>
                <th>Timestamp</th>
                <th>Notes</th>
            </tr>
        </thead>
        <tbody>
    """)
    for hop in hops:
        index = _escape(hop.get("index", ""))
        from_host = _escape(hop.get("from_host", hop.get("from", "")))
        by_host = _escape(hop.get("by_host", hop.get("host", "")))
        ips = hop.get("ips") or ([] if hop.get(
            "ip") is None else [hop.get("ip")])
        ips_html = _escape(", ".join(ips)) if ips else ""
        tls_status = "✅" if hop.get('tls') else (
            "❌" if hop.get('tls') is False else "❓")
        loc = "Unknown"
        latlon = _extract_latlon(hop)
        if hop.get('geo'):
            g = hop.get('geo', {})
            city = g.get('city') or g.get('region') or ""
            country = g.get('country') or ""
            if city or country:
                loc = ", ".join(p for p in (city, country) if p)
        elif latlon:
            loc = f"{latlon[0]:.6f}, {latlon[1]:.6f}"
        timestamp = _escape(hop.get("timestamp", ""))
        notes_list = []
        if hop.get("tls") is False:
            notes_list.append("No TLS")
        if hop.get("relay") or hop.get("proto"):
            notes_list.append(_escape(hop.get("relay") or hop.get("proto")))
        notes_html = _escape(", ".join(notes_list)) if notes_list else ""
        rows.append(f"""
            <tr>
                <td>{index}</td>
                <td>{from_host}</td>
                <td>{by_host}</td>
                <td>{ips_html}</td>
                <td>{tls_status}</td>
                <td>{_escape(loc)}</td>
                <td>{timestamp}</td>
                <td>{notes_html}</td>
            </tr>
        """)
    rows.append("</tbody></table>")
    return "\n".join(rows)


def generate_timeline(timeline_data: List[Dict]) -> str:
    html_parts = []
    for i, item in enumerate(timeline_data):
        risk_class = "risk-low"
        if item.get('risk') == "medium":
            risk_class = "risk-medium"
        elif item.get('risk') == "high":
            risk_class = "risk-high"
        html_parts.append(f"""
        <div class="timeline-item">
            <div class="{risk_class} risk-indicator"></div>
            <h4>{_escape(item.get('title', ''))}</h4>
            <p><strong>Time:</strong> {_escape(item.get('time', ''))}</p>
            <p><strong>Location:</strong> {_escape(item.get('location', ''))}</p>
            <p>{_escape(item.get('description', ''))}</p>
        </div>
        """)
    return "\n".join(html_parts)


def generate_auth_section(auth_data: Dict) -> str:
    auth_results = auth_data.get('parsed', [])
    if not auth_results:
        return "<p>No authentication results available</p>"
    parts = []
    for i, auth in enumerate(auth_results):
        parts.append(f"""
        <div style="background: #e9ecef; padding: 15px; border-radius: 10px; margin-bottom: 15px;">
            <h4>Authentication Result {i+1}</h4>
            <div class="summary-grid">
        """)
        for method, result in auth.items():
            badge_class = "security-pass" if result == "pass" else "security-fail"
            parts.append(f"""
            <div class="summary-card">
                <h3>{_escape(method.upper())}</h3>
                <span class="security-badge {badge_class}">{_escape(result or 'None')}</span>
            </div>
            """)
        parts.append("</div></div>")
    return "\n".join(parts)


def extract_timeline_data(report_data: Dict) -> List[Dict]:
    timeline = []
    hops = report_data.get('hops', [])
    for hop in hops:
        location = "Unknown"
        if hop.get('geo'):
            geo = hop['geo']
            location_parts = []
            if geo.get('city'):
                location_parts.append(geo['city'])
            if geo.get('country'):
                location_parts.append(geo['country'])
            location = ', '.join(
                location_parts) if location_parts else "Unknown"
        risk = "low"
        if hop.get('tls') is False:
            risk = "medium"
        if not hop.get('ips'):
            risk = "high"
        timeline.append({
            'title': f"Hop {hop.get('index')}",
            'time': hop.get('timestamp', 'Unknown'),
            'location': location,
            'description': f"Processed by: {hop.get('by_host', 'Unknown')}",
            'risk': risk
        })
    return timeline


def _lon_label_cardinal(longitude: int) -> str:
    if longitude == 0:
        return "0"
    direction = "W" if longitude < 0 else "E"
    return f"{abs(longitude)}{direction}"


def _lat_label_cardinal(latitude: int) -> str:
    if latitude == 0:
        return "0"
    direction = "S" if latitude < 0 else "N"
    return f"{abs(latitude)}{direction}"


def _lonlat_to_svg_xy(longitude: float, latitude: float, width: int, height: int, padding: int = 20):
    if longitude < -180:
        longitude = -180
    if longitude > 180:
        longitude = 180
    if latitude < -90:
        latitude = -90
    if latitude > 90:
        latitude = 90
    usable_width = width - 2*padding
    usable_height = height - 2*padding
    x = padding + ((longitude + 180.0) / 360.0) * usable_width
    y = padding + ((90.0 - latitude) / 180.0) * usable_height
    return x, y


def _build_svg_map(hops: List[Dict[str, Any]], width: int = 1000, height: int = 420) -> str:
    padding = 28
    markers = []
    for idx, hop in enumerate(hops):
        latlon = _extract_latlon(hop)
        if latlon:
            markers.append((idx, latlon[0], latlon[1]))
    parts = []
    parts.append(
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Hops map">')
    parts.append(
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff" stroke="#e6e6e6"/>')
    for longitude in range(-180, 181, 60):
        x, _ = _lonlat_to_svg_xy(longitude, 0, width, height, padding)
        parts.append(
            f'<line x1="{x:.1f}" y1="{padding}" x2="{x:.1f}" y2="{height-padding}" stroke="#eee" stroke-width="1"/>')
        label = _lon_label_cardinal(longitude)
        parts.append(
            f'<text x="{x + 4:.1f}" y="{height - padding + 14:.1f}" font-size="10" fill="#333">{label}</text>')
    for latitude in range(-60, 61, 30):
        _, y = _lonlat_to_svg_xy(0, latitude, width, height, padding)
        parts.append(
            f'<line x1="{padding}" y1="{y:.1f}" x2="{width-padding}" y2="{y:.1f}" stroke="#f6f6f6" stroke-width="1"/>')
        label = _lat_label_cardinal(latitude)
        parts.append(
            f'<text x="{4:.1f}" y="{y - 4:.1f}" font-size="10" fill="#333">{label}</text>')
    if len(markers) >= 2:
        poly_points = []
        for (idx, latitude, longitude) in markers:
            x, y = _lonlat_to_svg_xy(longitude, latitude, width, height, padding)
            poly_points.append(f"{x:.1f},{y:.1f}")
        parts.append(
            f'<polyline points="{" ".join(poly_points)}" fill="none" stroke="#3498db" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" opacity="0.85"/>')
    for (idx, latitude, longitude) in markers:
        x, y = _lonlat_to_svg_xy(longitude, latitude, width, height, padding)
        hop = hops[idx]
        label = hop.get("label") or hop.get("host") or hop.get(
            "ip") or f"Hop {hop.get('index', idx+1)}"
        tls = hop.get('tls')
        stroke = "#27ae60" if tls is True else (
            "#e74c3c" if tls is False else "#9b59b6")
        parts.append(
            f'<g class="marker" aria-label="{html.escape(str(label))}">')
        parts.append(
            f'  <circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="#ffffff" stroke="{stroke}" stroke-width="2"/>')
        parts.append(
            f'  <circle cx="{x:.1f}" cy="{y:.1f}" r="2.6" fill="{stroke}" />')
        label_x = x + 10
        label_y = y - 10
        location = ""
        if hop.get("geo"):
            geo_data = hop.get("geo", {})
            city = geo_data.get("city") or geo_data.get("region") or ""
            country = geo_data.get("country") or ""
            location = ", ".join(p for p in (city, country) if p)
        elif _extract_latlon(hop):
            lat2, lon2 = _extract_latlon(hop)
            location = f"{lat2:.4f}, {lon2:.4f}"
        ip_address = hop.get("ip") or (", ".join(hop.get("ips", []))
                               if hop.get("ips") else "")
        label_text = f"{label}"
        if ip_address:
            label_text += f" ({ip_address})"
        if location:
            label_text += f" — {location}"
        parts.append(
            f'  <text x="{label_x:.1f}" y="{label_y:.1f}" font-size="11" fill="#222">{html.escape(label_text)}</text>')
        parts.append('</g>')
    parts.append(
        f'<rect x="{padding}" y="{height-padding+4}" width="{width-2*padding}" height="18" fill="#fafafa" stroke="none"/>')
    parts.append(
        f'<text x="{padding+6}" y="{height-padding+16}" font-size="11" fill="#666">Markers placed for hops with coordinates.</text>')
    parts.append('</svg>')
    return "\n".join(parts)


def generate_html_report(report_data: Dict, output_path: str = "email_report.html") -> str:
    security_issues = assess_security_issues(report_data)
    timeline_data = extract_timeline_data(report_data)
    hops = report_data.get('hops', [])
    svg_map = _build_svg_map(hops, width=1000, height=420)
    hops_table_html = generate_hops_table(hops)
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Analysis Report</title>
        <style>
            :root {{ --primary: #2c3e50; --secondary: #3498db; --success: #27ae60; --warning: #f39c12; --danger: #e74c3c; --light: #ecf0f1; --dark: #34495e; }}
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .report-card {{ background: white; border-radius: 15px; box-shadow: 0 15px 35px rgba(0,0,0,0.1); overflow: hidden; margin-bottom: 30px; }}
            .report-header {{ background: var(--primary); color: white; padding: 30px; text-align: center; }}
            .report-header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
            .report-meta {{ display: flex; justify-content: space-between; background: var(--dark); color: white; padding: 15px 30px; font-size: 0.9em; }}
            .section {{ padding: 30px; border-bottom: 1px solid #eee; }}
            .section:last-child {{ border-bottom: none; }}
            .section-title {{ color: var(--primary); margin-bottom: 20px; font-size: 1.5em; border-left: 4px solid var(--secondary); padding-left: 15px; }}
            .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }}
            .summary-card {{ background: var(--light); padding: 20px; border-radius: 10px; text-align: center; }}
            .summary-card h3 {{ color: var(--dark); margin-bottom: 10px; word-break: break-word; hyphens: auto;}}
            .summary-card .value {{ font-size: 1.8em; font-weight: bold; color: var(--primary);  white-space: normal; overflow-wrap: anywhere; word-break: break-word; hyphens: auto; text-align: middle; max-width: 100%; }}
            .hop-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            .hop-table th, .hop-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            .hop-table th {{ background: var(--primary); color: white; }}
            .hop-table tr:hover {{ background: #f5f5f5; }}
            .security-badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; margin: 5px; }}
            .security-pass {{ background: var(--success); }}
            .security-fail {{ background: var(--danger); }}
            .security-warning {{ background: var(--warning); }}
            .timeline {{ position: relative; padding: 20px 0; }}
            .timeline::before {{ content: ''; position: absolute; left: 50%; top: 0; bottom: 0; width: 2px; background: var(--secondary); transform: translateX(-50%); }}
            .timeline-item {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); margin: 20px 0; position: relative; width: 45%; }}
            .timeline-item:nth-child(odd) {{ left: 0; }}
            .timeline-item:nth-child(even) {{ left: 55%; }}
            .risk-indicator {{ width: 20px; height: 20px; border-radius: 50%; position: absolute; top: 20px; right: -10px; }}
            .risk-low {{ background: var(--success); }} .risk-medium {{ background: var(--warning); }} .risk-high {{ background: var(--danger); }}
            @media (max-width: 768px) {{
                .summary-grid {{ grid-template-columns: 1fr; }}
                .timeline::before {{ left: 20px; }}
                .timeline-item {{ width: calc(100% - 60px); left: 40px !important; }}
            }}
            .map-wrapper {{ margin: 12px 0 20px 0; border-radius: 10px; overflow: hidden; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }}
            .map-caption {{ font-size: 0.9rem; color: #555; margin-top: 8px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="report-card">
                <div class="report-header">
                    <h1>📧 Email Analysis Report</h1>
                    <p>Comprehensive email header analysis and security assessment</p>
                </div>

                <div class="report-meta">
                    <div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                    <div>Analysis Tool: Email Analyzer</div>
                </div>

                <div class="section">
                    <h2 class="section-title">Email Summary</h2>
                    <div class="summary-grid">
                        <div class="summary-card"><h3>Subject</h3><div class="value">{_escape(report_data.get('subject', 'N/A'))}</div></div>
                        <div class="summary-card"><h3>From</h3><div class="value">{_escape(report_data.get('from', 'N/A'))}</div></div>
                        <div class="summary-card"><h3>To</h3><div class="value">{_escape(report_data.get('to', 'N/A'))}</div></div>
                        <div class="summary-card"><h3>Hops</h3><div class="value">{len(hops)}</div></div>
                    </div>
                </div>

                <div class="section"><h2 class="section-title">Security Assessment</h2>{generate_security_section(security_issues)}</div>

                <div class="section">
                    <h2 class="section-title">Delivery Path Analysis</h2>

                    <div class="map-wrapper" role="img" aria-label="Hops map">
                        {svg_map}
                    </div>
                    <div class="map-caption">Map shows hops that contain geo coordinates (lat/lon). Markers colored by TLS status: green = TLS, red = no TLS, purple = unknown.</div>

                    {hops_table_html}
                </div>

                <div class="section"><h2 class="section-title">Delivery Timeline</h2><div class="timeline">{generate_timeline(timeline_data)}</div></div>

                <div class="section"><h2 class="section-title">Authentication Results</h2>{generate_auth_section(report_data.get('auth', {}))}</div>

            </div>
        </div>
    </body>
    </html>
    """

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return output_path
