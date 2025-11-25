#!/usr/bin/env python3
import sys
import os
import argparse

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'email_analyzer'))

from email_analyzer.cli import cli_entrypoint

def main():
    cli_entrypoint()

if __name__ == '__main__':
    main()