import sys
import os

# Add repository root to sys.path so tests can import vulnscout_mcp.* modules.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
