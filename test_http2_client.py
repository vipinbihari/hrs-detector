#!/usr/bin/env python3
"""
Test script for the HTTP2 client.

This script demonstrates how to use the HTTP2 client directly with malformed headers
that contain carriage returns (\r) and newlines (\n) characters.
"""

import asyncio
import argparse
import logging
import sys
from typing import List, Tuple

# Add the project root to the Python path
sys.path.insert(0, '.')

from src.clients.http2 import HTTP2Client
from src.utils.logging import setup_logging


async def test_normal_request(client: HTTP2Client, path: str) -> None:
    """Test a normal HTTP/2 request."""
    print("\n=== Testing normal request ===")
    headers = [
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        ("accept", "*/*"),
        ("accept-encoding", "gzip, deflate, br"),
    ]
    
    response, body = await client.send_request(
        method="GET",
        path=path,
        headers=headers,
    )
    
    print(f"Response status: {response.get('status_code')}")
    print(f"Response headers: {response.get('headers')}")
    print(f"Response body length: {len(body)} bytes")


async def test_malformed_headers(client: HTTP2Client, path: str) -> None:
    """Test HTTP/2 request with malformed headers containing \r\n."""
    print("\n=== Testing malformed headers with \\r\\n ===")
    headers = [
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        ("accept", "*/*"),
        ("x-custom-header", "value1\r\nx-injected-header: injected-value"),
        ("accept-encoding", "gzip, deflate, br"),
    ]
    
    response, body = await client.send_malformed_headers(
        method="GET",
        path=path,
        headers=headers,
    )
    
    print(f"Response status: {response.get('status_code')}")
    print(f"Response headers: {response.get('headers')}")
    print(f"Response body length: {len(body)} bytes")


async def test_content_length_mismatch(client: HTTP2Client, path: str) -> None:
    """Test HTTP/2 request with Content-Length larger than actual body."""
    print("\n=== Testing Content-Length mismatch ===")
    headers = [
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        ("accept", "*/*"),
        ("content-type", "application/x-www-form-urlencoded"),
    ]
    
    # Send a body that's shorter than what we claim in Content-Length
    body = b"abc"  # 3 bytes
    content_length = 10  # But we claim 10 bytes
    
    response, body = await client.send_partial_body(
        method="POST",
        path=path,
        headers=headers,
        body=body,
        content_length=content_length,
        end_stream=True,  # We're ending the stream even though we sent less data
    )
    
    print(f"Response status: {response.get('status_code')}")
    print(f"Response headers: {response.get('headers')}")
    print(f"Response body length: {len(body)} bytes")


async def test_transfer_encoding_chunked(client: HTTP2Client, path: str) -> None:
    """Test HTTP/2 request with Transfer-Encoding: chunked header."""
    print("\n=== Testing Transfer-Encoding: chunked ===")
    headers = [
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        ("accept", "*/*"),
        ("transfer-encoding", "chunked"),
        ("content-type", "application/x-www-form-urlencoded"),
    ]
    
    # Send a chunked body with a terminating chunk but missing the final CRLF
    body = b"0\r\n"  # This is a valid terminating chunk, but missing the final CRLF
    
    response, body = await client.send_malformed_headers(
        method="POST",
        path=path,
        headers=headers,
        body=body,
    )
    
    print(f"Response status: {response.get('status_code')}")
    print(f"Response headers: {response.get('headers')}")
    print(f"Response body length: {len(body)} bytes")


async def test_header_smuggling(client: HTTP2Client, path: str) -> None:
    """Test HTTP/2 request with header smuggling attempt."""
    print("\n=== Testing header smuggling ===")
    headers = [
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
        ("accept", "*/*"),
        # Attempt to smuggle a header by including it in another header's value
        ("x-normal-header", "normal-value\r\nx-smuggled-header: smuggled-value"),
        # Attempt to smuggle a header by including it in a header name
        ("x-another-header:\r\nx-smuggled-name", "another-value"),
    ]
    
    response, body = await client.send_malformed_headers(
        method="GET",
        path=path,
        headers=headers,
    )
    
    print(f"Response status: {response.get('status_code')}")
    print(f"Response headers: {response.get('headers')}")
    print(f"Response body length: {len(body)} bytes")


async def main() -> None:
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Test HTTP/2 client with malformed headers")
    parser.add_argument(
        "-u", "--url", 
        default="https://example.com", 
        help="Target URL (default: https://example.com)"
    )
    parser.add_argument(
        "-p", "--path", 
        default="/", 
        help="Request path (default: /)"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Enable verbose logging"
    )
    args = parser.parse_args()
    
    # Set up logging
    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO, verbose=args.verbose)
    
    # Parse URL
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Extract host, port, and scheme
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    host = parsed_url.netloc.split(":")[0]
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    use_tls = parsed_url.scheme == "https"
    
    print(f"Testing HTTP/2 client against {url}")
    print(f"Host: {host}, Port: {port}, TLS: {use_tls}")
    
    # Create HTTP/2 client
    client = HTTP2Client(
        host=host,
        port=port,
        use_tls=use_tls,
        verify_ssl=False,  # Disable SSL verification for testing
        timeout=10.0,
        force_http2=True,
        verbose=args.verbose,
    )
    
    try:
        # Connect to the server
        await client.connect()
        
        # Run tests
        await test_normal_request(client, args.path)
        await test_malformed_headers(client, args.path)
        await test_content_length_mismatch(client, args.path)
        await test_transfer_encoding_chunked(client, args.path)
        await test_header_smuggling(client, args.path)
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the connection
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
