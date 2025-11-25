"""
Command line entrypoint.
"""
import argparse
import logging
import os
import sys

from .json_report import generate_json_report
from .html_report import generate_html_report
from .fetch_eml import fetch_eml

LOG = logging.getLogger('email_analyzer')

def cli_entrypoint():
    parser = argparse.ArgumentParser(description='Enhanced Email Header Analyzer')
    parser.add_argument('eml', nargs='?', help='.eml file to analyze (or use --fetch for remote)')
    parser.add_argument('--output-dir', help='output directory for all generated files (defaults to output.{filename})')
    parser.add_argument('--fetch', help='Fetch EML from URL or IMAP server')
    parser.add_argument('--debug', action='store_true')
    arguments = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if arguments.debug else logging.INFO)
    
    # Handle EML fetching
    eml_path = arguments.eml
    if arguments.fetch:
        try:
            eml_path = fetch_eml(arguments.fetch)
            LOG.info('Fetched EML from: %s', arguments.fetch)
        except Exception as error:
            LOG.error('Failed to fetch EML: %s', error)
            sys.exit(1)

    if not eml_path:
        LOG.error('No EML file provided. Use --help for usage information.')
        sys.exit(1)

    LOG.info('Analyzing %s', eml_path)

    try:
        # Determine output directory
        base_name = os.path.splitext(os.path.basename(eml_path))[0]
        output_dir = arguments.output_dir if arguments.output_dir else f"output.{base_name}"
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Build output paths with static filenames
        graph_out = os.path.join(output_dir, 'hops_diagram')
        map_out = os.path.join(output_dir, 'hops_map.html')
        html_out = os.path.join(output_dir, 'report.html')
        json_out = os.path.join(output_dir, 'report.json')
        
        report = generate_json_report(eml_path,
                              graph_out=graph_out, map_out=map_out, json_out=json_out)
        
        # Generate HTML report
        html_path = generate_html_report(report, html_out)
        
        LOG.info('Analysis complete!')
        LOG.info('Output directory: %s', output_dir)
        LOG.info('JSON Report: %s', json_out)
        LOG.info('HTML Report: %s', html_path)
        LOG.info('Graph: %s', report.get('graph', 'Not generated'))
        LOG.info('Map: %s', report.get('map', 'Not generated'))
        
    except Exception as error:
        LOG.exception('Failed to analyze email: %s', error)
        sys.exit(1)