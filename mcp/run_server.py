#!/usr/bin/env python3
"""
Wrapper script to initialize venv and run the MCP server.
This ensures the virtual environment is created and dependencies are installed
before the server starts, making it safe to call from mcp-config.json.
"""

import os
import sys
import subprocess
import venv
from pathlib import Path


def get_project_root():
    """Get the directory where this script is located."""
    return Path(__file__).parent


def get_venv_path():
    """Get the virtual environment path."""
    return get_project_root() / "venv"


def venv_exists():
    """Check if virtual environment already exists."""
    venv_path = get_venv_path()
    return (venv_path / "bin" / "python").exists()


def create_venv():
    """Create a new virtual environment."""
    venv_path = get_venv_path()
    print(f"Creating virtual environment at {venv_path}...", file=sys.stderr)
    venv.create(venv_path, with_pip=True)
    print("Virtual environment created successfully.", file=sys.stderr)


def install_requirements():
    """Install dependencies from requirements.txt."""
    venv_path = get_venv_path()
    pip_path = venv_path / "bin" / "pip"
    requirements_path = get_project_root() / "requirements.txt"
    
    if not requirements_path.exists():
        print(f"Warning: requirements.txt not found at {requirements_path}", file=sys.stderr)
        return
    
    print(f"Installing dependencies...", file=sys.stderr)
    result = subprocess.run(
        [str(pip_path), "install", "-r", str(requirements_path)],
        stdout=sys.stderr,
        stderr=sys.stderr,
    )
    
    if result.returncode != 0:
        print(f"Error installing dependencies. Exit code: {result.returncode}", file=sys.stderr)
        sys.exit(1)
    
    print("Dependencies installed successfully.", file=sys.stderr)


def run_server():
    """Run the MCP server using the virtual environment Python."""
    venv_path = get_venv_path()
    python_path = venv_path / "bin" / "python"
    server_path = get_project_root() / "server.py"
    
    print(f"Starting MCP server...", file=sys.stderr)
    
    # Replace the current process with the server
    os.execv(str(python_path), [str(python_path), str(server_path)])


def main():
    """Initialize venv if needed and run the server."""
    try:
        if not venv_exists():
            create_venv()
        else:
            print("Virtual environment already exists.", file=sys.stderr)

        # Always sync dependencies so requirement bumps reach an existing venv.
        install_requirements()
        
        run_server()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
