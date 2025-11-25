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

    graph = graphviz.Digraph('email_path', format=fmt)
    for hop in hops:
        node_label = f"hop {hop.index}\n"
        if hop.from_host:
            node_label += f"from: {hop.from_host}\n"
        if hop.ips:
            node_label += f"ips: {','.join(hop.ips)}\n"
        if hop.timestamp:
            node_label += str(hop.timestamp)
        graph.node(str(hop.index), label=node_label, shape='box')

    for index in range(len(hops) - 1):
        current_hop = hops[index]
        label = 'unknown'
        if current_hop.tls is True:
            label = 'TLS'
        elif current_hop.tls is False:
            label = 'plain'
        graph.edge(str(index), str(index + 1), label=label)

    try:
        output_path = graph.render(filename=out_basename, cleanup=True)
        return output_path
    except Exception as e:
        print('graphviz render failed:', e)
        return None

def build_map(hops: List[object], out_html: str = 'hops_map.html') -> Optional[dict]:
    """Build interactive Folium map and return both HTML content and file path.
    
    Returns:
        dict with 'html_content' (str) and 'file_path' (str), or None if map cannot be built
    """
    if not folium:
        print('folium not installed — skipping map generation')
        return None

    coordinates = []
    for hop in hops:
        if hop.geo and hop.geo.get('lat') and hop.geo.get('lon'):
            coordinates.append((hop.geo['lat'], hop.geo['lon']))
    if not coordinates:
        print('no geolocation coordinates — skipping map')
        return None

    map_obj = folium.Map(location=coordinates[0], zoom_start=3)
    for hop in hops:
        if hop.geo and hop.geo.get('lat'):
            folium.Marker([hop.geo['lat'], hop.geo['lon']], popup=f"hop {hop.index}: {hop.from_host or ','.join(hop.ips or [])}").add_to(map_obj)
    folium.PolyLine(coordinates, tooltip='email path').add_to(map_obj)
    
    # Save to file
    map_obj.save(out_html)
    
    # Also return HTML content for embedding
    html_content = map_obj._repr_html_()
    
    return {'html_content': html_content, 'file_path': out_html}