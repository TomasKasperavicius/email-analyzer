"""
Visualization helpers: Graphviz (static directed graph) and Folium map (interactive).
"""
from typing import List, Optional
import graphviz
import folium

def build_graph(hops: List[object], out_basename: str = 'hops', fmt: str = 'svg') -> Optional[str]:
    if not graphviz:
        print('graphviz python package not installed — skipping graph generation')
        return None

    g = graphviz.Digraph('email_path', format=fmt)
    for h in hops:
        node_label = f"hop {h.index}\n"
        if h.from_host:
            node_label += f"from: {h.from_host}\n"
        if h.ips:
            node_label += f"ips: {','.join(h.ips)}\n"
        if h.timestamp:
            node_label += str(h.timestamp)
        g.node(str(h.index), label=node_label, shape='box')

    for i in range(len(hops) - 1):
        a = hops[i]
        label = 'unknown'
        if a.tls is True:
            label = 'TLS'
        elif a.tls is False:
            label = 'plain'
        g.edge(str(i), str(i + 1), label=label)

    try:
        out = g.render(filename=out_basename, cleanup=True)
        return out
    except Exception as e:
        print('graphviz render failed:', e)
        return None

def build_map(hops: List[object], out_html: str = 'hops_map.html') -> Optional[str]:
    if not folium:
        print('folium not installed — skipping map generation')
        return None

    coords = []
    for h in hops:
        if h.geo and h.geo.get('lat') and h.geo.get('lon'):
            coords.append((h.geo['lat'], h.geo['lon']))
    if not coords:
        print('no geolocation coordinates — skipping map')
        return None

    m = folium.Map(location=coords[0], zoom_start=3)
    for h in hops:
        if h.geo and h.geo.get('lat'):
            folium.Marker([h.geo['lat'], h.geo['lon']], popup=f"hop {h.index}: {h.from_host or ','.join(h.ips or [])}").add_to(m)
    folium.PolyLine(coords, tooltip='email path').add_to(m)
    m.save(out_html)
    return out_html