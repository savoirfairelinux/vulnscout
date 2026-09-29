import sys
import os

# Add mcp/ directory to sys.path so tests can import client, tools.assessments, etc.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
