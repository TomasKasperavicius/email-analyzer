#!/usr/bin/env python3
import sys
import os
import argparse

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'email_analyzer'))

from email_analyzer.cli import main as cli_main

def main():
    parser = argparse.ArgumentParser(description='Email Analyzer with Batch Processing')
    parser.add_argument('--samples', action='store_true', help='Process all EML files in samples directory')
    parser.add_argument('--batch-output', help='Output directory for batch processing', default='reports')
    parser.add_argument('--cli', action='store_true', help='Use original CLI interface')
    
    # Parse known args for our script, pass rest to CLI
    args, remaining = parser.parse_known_args()
    
    if args.cli or remaining:
        # Use original CLI
        sys.argv = [sys.argv[0]] + remaining
        cli_main()
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python main.py --cli sample.eml            # Analyze single email")

if __name__ == '__main__':
    main()