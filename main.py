#!/usr/bin/env python3
"""
Main entry point for the HTTP Request Smuggling Detection Tool.

This wrapper script allows running the tool directly with python main.py
without needing to use the module syntax.
"""

import os
import sys

# Add the parent directory to sys.path to allow importing from src
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import and run the main function from the CLI module
from src.cli.main import main

if __name__ == "__main__":
    main()
