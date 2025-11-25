"""
HTML Report Generation using Jinja2 Templates
Simplified version - all HTML logic moved to templates with loops and conditionals
"""
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
from jinja2 import Environment, FileSystemLoader


TEMPLATES_DIRECTORY = Path(__file__).parent / "templates"

# Set up Jinja2 environment
jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIRECTORY),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True
)


# Custom Jinja2 filters for SVG generation
def _to_svg_position_filter(longitude, latitude, width, height, padding):
    return _coordinates_to_svg_position(longitude, latitude, width, height, padding)


def _format_longitude_filter(longitude):
    return _format_longitude_label(longitude)


def _format_latitude_filter(latitude):
    return _format_latitude_label(latitude)


# Register custom filters
jinja_env.filters['to_svg_position'] = _to_svg_position_filter
jinja_env.filters['format_longitude'] = _format_longitude_filter
jinja_env.filters['format_latitude'] = _format_latitude_filter


def _extract_latitude_longitude(hop: Dict[str, Any]):
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
    
    # Check for non-TLS hops
    non_tls_hops = [hop for hop in hops if hop.get('tls') is False]
    if non_tls_hops:
        issues['tls_issues'].append(
            f"{len(non_tls_hops)} hops without TLS encryption")
    
    # Check authentication results
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
    
    # Check geographic routing
    geo_locations = []
    for hop in hops:
        if hop.get('geo') and hop['geo'].get('country'):
            geo_locations.append(hop['geo']['country'])
    unique_countries = len(set(geo_locations))
    if unique_countries > 3:
        issues['geo_issues'].append(
            f"Email routed through {unique_countries} different countries")
    
    return issues


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
            location = ', '.join(location_parts) if location_parts else "Unknown"
        
        # Risk calculation: priority order
        if not hop.get('ips'):
            risk = "high"
        elif hop.get('tls') is False:
            risk = "medium"
        else:
            risk = "low"
        
        timeline.append({
            'title': f"Hop {hop.get('index')}",
            'time': hop.get('timestamp', 'Unknown'),
            'location': location,
            'description': hop.get('by_host', 'Unknown'),
            'risk': risk
        })
    return timeline


def _format_longitude_label(longitude: float) -> str:
    if longitude == 0:
        return "0"
    direction = "W" if longitude < 0 else "E"
    return f"{abs(longitude)}{direction}"


def _format_latitude_label(latitude: float) -> str:
    if latitude == 0:
        return "0"
    direction = "S" if latitude < 0 else "N"
    return f"{abs(latitude)}{direction}"


def _coordinates_to_svg_position(longitude: float, latitude: float, width: int, height: int, padding: int = 20):
    if longitude < -180:
        longitude = -180
    if longitude > 180:
        longitude = 180
    if latitude < -90:
        latitude = -90
    if latitude > 90:
        latitude = 90
    usable_width = width - 2 * padding
    usable_height = height - 2 * padding
    x = padding + ((longitude + 180.0) / 360.0) * usable_width
    y = padding + ((90.0 - latitude) / 180.0) * usable_height
    return x, y


def _build_svg_map(hops: List[Dict[str, Any]], width: int = 1000, height: int = 420) -> str:
    padding = 28
    
    # Prepare marker data with all computed fields
    markers = []
    for index, hop in enumerate(hops):
        coordinates = _extract_latitude_longitude(hop)
        if coordinates:
            latitude, longitude = coordinates
            
            # Compute label
            label = hop.get("label") or hop.get("host") or hop.get("ip") or f"Hop {hop.get('index', index+1)}"
            
            # Compute location text
            location = ""
            if hop.get("geo"):
                geo_data = hop.get("geo", {})
                city = geo_data.get("city") or geo_data.get("region") or ""
                country = geo_data.get("country") or ""
                location = ", ".join(part for part in (city, country) if part)
            else:
                location = f"{latitude:.4f}, {longitude:.4f}"
            
            # Compute IP addresses
            ip_address = hop.get("ip") or (", ".join(hop.get("ips", [])) if hop.get("ips") else "")
            
            # Build complete label text
            label_text = label
            if ip_address:
                label_text += f" ({ip_address})"
            if location:
                label_text += f" — {location}"
            
            markers.append({
                'latitude': latitude,
                'longitude': longitude,
                'label': label,
                'label_text': label_text,
                'tls': hop.get('tls'),
                'index': index
            })
    
    # Render SVG using Jinja2 template
    template = jinja_env.get_template('svg_map_template.svg')
    svg_content = template.render(
        width=width,
        height=height,
        padding=padding,
        markers=markers
    )
    
    return svg_content


def generate_html_report(report_data: Dict, output_path: str = "email_report.html") -> str:
    # Prepare data for template
    security_issues = assess_security_issues(report_data)
    timeline_data = extract_timeline_data(report_data)
    hops = report_data.get('hops', [])
    
    # Enrich hop data with computed fields for easier template usage
    enriched_hops = []
    for hop in hops:
        hop_data = hop.copy()
        
        # Extract IPs
        hop_data['ip_list'] = hop.get("ips") or ([] if hop.get("ip") is None else [hop.get("ip")])
        
        # TLS status
        if hop.get('tls') is True:
            hop_data['tls_symbol'] = '✅'
            hop_data['tls_class'] = 'success'
        elif hop.get('tls') is False:
            hop_data['tls_symbol'] = '❌'
            hop_data['tls_class'] = 'danger'
        else:
            hop_data['tls_symbol'] = '❓'
            hop_data['tls_class'] = 'secondary'
        
        # Location
        coordinates = _extract_latitude_longitude(hop)
        if hop.get('geo'):
            geo_data = hop.get('geo', {})
            city = geo_data.get('city') or geo_data.get('region') or ""
            country = geo_data.get('country') or ""
            if city or country:
                hop_data['location'] = ", ".join(p for p in (city, country) if p)
            else:
                hop_data['location'] = "Unknown"
        elif coordinates:
            latitude, longitude = coordinates
            hop_data['location'] = f"{latitude:.6f}, {longitude:.6f}"
        else:
            hop_data['location'] = "Unknown"
        
        enriched_hops.append(hop_data)
    
    # Build SVG map
    svg_map = _build_svg_map(hops, width=1000, height=420)
    
    # Calculate total security issues
    total_security_issues = sum(len(issues) for issues in security_issues.values())
    
    # Load and render Jinja2 template
    template = jinja_env.get_template('report_template.html')
    html_content = template.render(
        generated_timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        subject=report_data.get('subject', 'N/A'),
        from_address=report_data.get('from', 'N/A'),
        to_address=report_data.get('to', 'N/A'),
        hops_count=len(hops),
        hops=enriched_hops,
        security_issues=security_issues,
        total_security_issues=total_security_issues,
        timeline_data=timeline_data,
        auth_results=report_data.get('auth', {}).get('parsed', []),
        svg_map=svg_map,
        map_html=report_data.get('map_html', '')
    )

    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(html_content)
    return output_path
