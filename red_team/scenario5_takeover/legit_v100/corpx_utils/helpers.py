"""Utility helpers — real working functions."""
import re
import os


def slugify(text: str) -> str:
    """Convert text to URL-safe slug."""
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    return re.sub(r'[-\s]+', '-', text)


def parse_config(path: str) -> dict:
    """Parse simple KEY=VALUE config file into dict."""
    config = {}
    if not os.path.isfile(path):
        return config
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, value = line.partition('=')
                config[key.strip()] = value.strip()
    return config
