# Pythmap Installation Guide

Pythmap is a network port scanner and security assessment tool that can be installed system-wide using pipx.

## Prerequisites

- Python 3.6 or higher
- pipx (for isolated installation)
- sudo/root access (required for network scanning)

## Install pipx

If you don't have pipx installed:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install pipx
pipx ensurepath

# macOS (with Homebrew)
brew install pipx
pipx ensurepath

# Using pip
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

## Install Pythmap

### From GitHub

```bash
pipx install git+https://github.com/TheBitty/Pythmap.git
```

### From Local Directory

If you've cloned the repository:

```bash
cd /path/to/pythmap
pipx install .
```

## Usage

After installation, you can run pythmap from anywhere:

```bash
sudo pythmap
```

Note: Root privileges are required for network scanning operations.

## Uninstall

To remove pythmap:

```bash
pipx uninstall pythmap
```

## Development Installation

For development, you can install in editable mode:

```bash
pipx install -e /path/to/pythmap
```

This allows you to make changes to the code without reinstalling.