"""
TLS utilities for HTTP clients.

This module provides helper functions for setting up TLS connections
with appropriate settings for HTTP/1.1 and HTTP/2.
"""

import ssl
from typing import Optional


def create_ssl_context(
    alpn_protocols: Optional[list[str]] = None,
    verify: bool = False,
) -> ssl.SSLContext:
    """Create an SSL context for HTTP connections.
    
    Args:
        alpn_protocols: List of ALPN protocols to advertise (e.g., ['h2', 'http/1.1'])
        verify: Whether to verify server certificates
        
    Returns:
        Configured SSL context
    """
    # Create SSL context with appropriate security settings
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # Configure certificate verification
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    # Set ALPN protocols if provided
    if alpn_protocols:
        context.set_alpn_protocols(alpn_protocols)
    
    return context


def get_http1_ssl_context(verify: bool = False) -> ssl.SSLContext:
    """Get an SSL context configured for HTTP/1.1.
    
    Args:
        verify: Whether to verify server certificates
        
    Returns:
        SSL context for HTTP/1.1
    """
    return create_ssl_context(alpn_protocols=['http/1.1'], verify=verify)


def get_http2_ssl_context(verify: bool = False) -> ssl.SSLContext:
    """Get an SSL context configured for HTTP/2.
    
    Args:
        verify: Whether to verify server certificates
        
    Returns:
        SSL context for HTTP/2
    """
    return create_ssl_context(alpn_protocols=['h2'], verify=verify)


def get_negotiated_protocol(ssl_object: ssl.SSLObject) -> Optional[str]:
    """Get the negotiated ALPN protocol from an SSL object.
    
    Args:
        ssl_object: SSL object from an established connection
        
    Returns:
        Negotiated protocol or None if not available
    """
    try:
        return ssl_object.selected_alpn_protocol()
    except AttributeError:
        return None
