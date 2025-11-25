"""
Report assembly: run parser, geolocation, viz and write JSON report file.
"""
import json
import os

from .parser import load_email, parse_received_hops, parse_authentication_results, extract_additional_headers
from .geolocate import geolocate_ip
from .visualization import build_graph, build_map

def generate_json_report(eml_path: str,
                 graph_out: str = 'hops', map_out: str = 'hops_map.html', json_out: str = None) -> dict:
    msg = load_email(eml_path)
    hops = parse_received_hops(msg)
    
    # geolocate first IP per hop
    for hop in hops:
        if hop.ips:
            ip_address = hop.ips[0]
            geo = geolocate_ip(ip_address)
            hop.geo = geo

    auth = parse_authentication_results(msg)
    additional_headers = extract_additional_headers(msg)

    graph_path = build_graph(hops, out_basename=graph_out) if graph_out else None
    map_result = build_map(hops, out_html=map_out) if map_out else None

    report = {
        'filename': os.path.basename(eml_path),
        'filepath': eml_path,
        'subject': msg.get('Subject'),
        'from': msg.get('From'),
        'to': msg.get('To'),
        'date': msg.get('Date'),
        'hops': [hop.to_dict() for hop in hops],
        'auth': auth,
        'additional_headers': additional_headers,
        'graph': graph_path,
        'map': map_result.get('file_path') if map_result else None,
        'map_html': map_result.get('html_content') if map_result else None,
    }

    # Use provided json_out path or default to next to eml file
    if json_out is None:
        json_out = os.path.splitext(eml_path)[0] + '.report.json'
    
    with open(json_out, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    return report