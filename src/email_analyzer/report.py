"""
Report assembly: run parser, geolocation, viz and write JSON report file.
"""
import json
import os
from typing import Optional

from .parser import load_email, parse_received_hops, parse_authentication_results, extract_additional_headers
from .geolocate import geolocate_ip
from .visualization import build_graph, build_map

def build_report(eml_path: str,
                 graph_out: str = 'hops', map_out: str = 'hops_map.html') -> dict:
    msg = load_email(eml_path)
    hops = parse_received_hops(msg)
    
    # geolocate first IP per hop
    for h in hops:
        if h.ips:
            ip = h.ips[0]
            geo = geolocate_ip(ip)
            h.geo = geo

    auth = parse_authentication_results(msg)
    additional_headers = extract_additional_headers(msg)

    graph_path = build_graph(hops, out_basename=graph_out) if graph_out else None
    map_path = build_map(hops, out_html=map_out) if map_out else None

    report = {
        'filename': os.path.basename(eml_path),
        'filepath': eml_path,
        'subject': msg.get('Subject'),
        'from': msg.get('From'),
        'to': msg.get('To'),
        'date': msg.get('Date'),
        'hops': [h.to_dict() for h in hops],
        'auth': auth,
        'additional_headers': additional_headers,
        'graph': graph_path,
        'map': map_path,
    }

    outjson = os.path.splitext(eml_path)[0] + '.report.json'
    with open(outjson, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    return report