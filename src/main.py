#!/usr/bin/env python3
import sys
import os

# Add src to Python path
current_directory = os.path.dirname(__file__)
email_analyzer_directory = os.path.join(current_directory, 'email_analyzer')
sys.path.insert(0, email_analyzer_directory)

from email_analyzer.cli import cli_entrypoint

def main():
    cli_entrypoint()

if __name__ == '__main__':
    main()