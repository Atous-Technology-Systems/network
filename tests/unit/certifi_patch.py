"""Patch for certifi to provide the 'where' function."""
import os

def where():
    """Return the path to the CA bundle."""
    return os.path.join(os.path.dirname(__file__), 'cacert.pem')