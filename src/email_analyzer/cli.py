"""
Command line entrypoint.
"""
import argparse
import logging
import os
import sys

from .report import build_report
from .html_report import generate_html_report
from .fetch_eml import fetch_eml_from_url

LOG = logging.getLogger('email_analyzer')

def main():
    parser = argparse.ArgumentParser(description='Enhanced Email Header Analyzer')
    parser.add_argument('eml', nargs='?', help='.eml file to analyze (or use --fetch for remote)')
    parser.add_argument('--geoip-db', help='path to GeoLite2-City.mmdb', default=os.getenv('GEOLITE_DB'))
    parser.add_argument('--ipinfo-token', help='IPInfo token', default=os.getenv('IPINFO_TOKEN'))
    parser.add_argument('--graph-out', help='graphviz output basename', default='hops')
    parser.add_argument('--map-out', help='folium map output html', default='hops_map.html')
    parser.add_argument('--html-out', help='HTML report output file', default='email_report.html')
    parser.add_argument('--fetch', help='Fetch EML from URL or IMAP server')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    
    # Handle EML fetching
    eml_path = args.eml
    if args.fetch:
        try:
            eml_path = fetch_eml_from_url(args.fetch)
            LOG.info('Fetched EML from: %s', args.fetch)
        except Exception as error:
            LOG.error('Failed to fetch EML: %s', error)
            sys.exit(1)

    if not eml_path:
        LOG.error('No EML file provided. Use --help for usage information.')
        sys.exit(1)

    LOG.info('Analyzing %s', eml_path)

    try:
        report = build_report(eml_path,
                              graph_out=args.graph_out, map_out=args.map_out)
        
        # Generate HTML report
        html_path = generate_html_report(report, args.html_out)
        
        LOG.info('Analysis complete!')
        LOG.info('JSON Report: %s.report.json', os.path.splitext(eml_path)[0])
        LOG.info('HTML Report: %s', html_path)
        LOG.info('Graph: %s', report.get('graph', 'Not generated'))
        LOG.info('Map: %s', report.get('map', 'Not generated'))
        
    except Exception as error:
        LOG.exception('Failed to analyze email: %s', error)
        sys.exit(1)

if __name__ == '__main__':
    main()