"""
H2.TE (HTTP/2 to HTTP/1 Transfer-Encoding) detector module.

This module implements detection for H2.TE vulnerabilities, which occur when a front-end
server speaks HTTP/2 with clients but downgrades to HTTP/1.1 when forwarding requests
to a back-end server, and the back-end server processes Transfer-Encoding headers
differently than expected.
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from src.clients.http2 import HTTP2Client
from src.utils.logging import get_logger, setup_logging

logger = get_logger()


async def test_h2_te_vulnerability(
    url: str,
    headers: List[Tuple[str, str]] = None,
    timeout: float = 5.0,
    verbose: bool = False,
    exit_first: bool = False,
    headers_file: Optional[str] = None,
    payload_placement: Optional[str] = None,
) -> Dict[str, Any]:
    """Test for H2.TE HTTP request smuggling vulnerability.
    
    This test detects if a server is vulnerable to H2.TE request smuggling by:
    1. Sending an HTTP/2 request with a Transfer-Encoding: chunked header
    2. Sending a chunked body with a terminating chunk but missing the final CRLF
    3. Measuring the response time to detect if the back-end server is waiting for more data
    
    Args:
        url: Target URL
        headers: Additional headers to include in the request
        timeout: Request timeout in seconds
        verbose: Whether to print verbose output
        exit_first: Whether to exit after finding the first vulnerability
        headers_file: Not used, kept for compatibility
        payload_placement: Where to place the payload (normal_header, custom_header_value, custom_header_name)
        
    Returns:
        Dictionary with test results
    """
    # Print test parameters if verbose
    if verbose:
        logger.info("==== H2.TE TEST PARAMETERS ====")
        logger.info(f"URL: {url}")
        logger.info(f"Timeout: {timeout}s")
        logger.info(f"Headers: {headers}")
        logger.info(f"Payload Placement: {payload_placement}")
    
    # Parse URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Split URL into components
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    host = parsed_url.netloc.split(':')[0]
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    path = parsed_url.path or '/'
    if parsed_url.query:
        path += '?' + parsed_url.query
    use_tls = parsed_url.scheme == 'https'
    
    if verbose:
        logger.info(f"Parsed URL: Host={parsed_url.hostname}, Port={parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)}, Path={parsed_url.path or '/'}, TLS={parsed_url.scheme == 'https'}")
    
    # Initialize results
    results = {
        'url': url,
        'host': host,
        'port': port,
        'path': path,
        'vulnerable': False,
        'findings': [],
        'errors': [],
    }
    
    # Initialize HTTP/2 client
    client = HTTP2Client(
        host=host,
        port=port,
        use_tls=use_tls,
        verify_ssl=False,  # We handle verification ourselves
        timeout=timeout,
        force_http2=True,  # Try to force HTTP/2 even if not advertised in ALPN
        verbose=verbose,
    )
    
    try:
        # Connect to the server
        await client.connect()
        
        # Define default request headers
        request_headers = [
            ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"),
            ("accept", "*/*"),
            ("accept-encoding", "gzip, deflate, br"),
            ("accept-language", "en-US;q=0.9,en;q=0.8"),
            ("cache-control", "max-age=0"),
        ]
        
        # Add custom headers if provided
        if headers:
            for header in headers:
                name, value = header
                request_headers.append((name, value))
        
        # Send a normal request to establish baseline response time
        logger.info("Sending baseline request...")
        start_baseline = time.time()
        try:
            baseline_response, _ = await client.send_request(
                method="GET",
                path=path,
                headers=request_headers,
            )
            end_baseline = time.time()
            baseline_response_time = end_baseline - start_baseline
            logger.info(f"Baseline response time: {baseline_response_time:.6f}s")
        except Exception as e:
            logger.error(f"Error during baseline request: {e}")
            results['errors'].append({
                'error': str(e),
            })
        
        # Define Transfer-Encoding header mutations to test
        mutations = [
            # 1. Normal header
            {
                "description": "Standard Transfer-Encoding header",
                "header_name": "transfer-encoding",
                "header_value": "chunked",
                "type": "normal_header"
            },
            # 2. In custom header value
            {
                "description": "H2.TE via Request Header Injection in Custom Header Value",
                "header_name": "x-custom",
                "header_value": "foo\r\ntransfer-encoding: chunked",
                "type": "custom_header_value"
            },
            # 3. In custom header name
            {
                "description": "H2.TE via Request Header Injection in Custom Header Name",
                "header_name": "x-custom:foo\r\ntransfer-encoding",
                "header_value": "chunked",
                "type": "custom_header_name"
            },
            # 4. In Request line 
            {
                "description": "H2.TE via Request Line Injection",
                "header_name": ":method",
                "header_value": "POST / HTTP/1.1\r\nTransfer-encoding: chunked\r\nx: x",
                "type": "request_line"
            }
        ]
        
        # Filter mutations based on payload_placement if specified
        if payload_placement:
            mutations = [m for m in mutations if m["type"] == payload_placement]
            if not mutations:
                logger.warning(f"No mutations found for placement type: {payload_placement}")
                logger.warning("Valid placement types are: normal_header, custom_header_value, custom_header_name")
                results['errors'].append({
                    'error': f"Invalid payload placement: {payload_placement}"
                })
                return results
            logger.info(f"Testing only {payload_placement} placement")
        
        # Test the mutations
        for mutation in mutations:
            logger.info(f"Testing with {mutation['description']}: {mutation['header_name']}: {mutation['header_value']}")
            
            # This will hold the test result
            test_result = {}
            
            try:
                header_name = mutation["header_name"]
                header_value = mutation["header_value"]
                mutation_type = mutation["type"]
                
                # Create a fresh HTTP/2 client for each test
                client = HTTP2Client(
                    host=host,
                    port=port,
                    use_tls=use_tls,
                    verify_ssl=False,
                    timeout=timeout,
                    force_http2=True,
                    verbose=verbose,
                )
                
                try:
                    await client.connect()
                    
                    # Prepare test headers based on mutation type
                    test_headers = request_headers.copy()
                    
                    # Actual detection logic depends on payload placement
                    # Here we're testing Transfer-Encoding vulnerabilities
                    body_content = "0\r\n"  # Terminating chunk without final CRLF
                    
                    if payload_placement == "normal_header":
                        # Add Transfer-Encoding header
                        test_headers.append((header_name, header_value))
                        
                        if verbose:
                            logger.info(f"\n==== TEST REQUEST DETAILS ====")
                            logger.info(f"Headers:")
                            for name, value in test_headers:
                                logger.info(f"  {name}: {value}")
                            logger.info(f"Body: '{body_content}' ({len(body_content)} bytes)")
                            logger.info(f"Transfer-Encoding header value: {header_value}")
                        
                        # The key part of the test: if the backend is using the
                        # Transfer-Encoding header from our request but we're sending an incomplete
                        # chunked body, it should wait for the final CRLF, causing a timeout
                        # or delay that we can detect.
                        
                    elif payload_placement == "custom_header_value":
                        # Transfer-Encoding in a custom header value position
                        test_headers.append((header_name, header_value))
                    elif payload_placement == "custom_header_name":
                        # Transfer-Encoding in a custom header name position
                        test_headers.append((header_name, header_value))
                    elif payload_placement == "request_line":
                        # Transfer-Encoding in request line
                        test_headers.append((header_name, header_value))
                    
                    # Record start time
                    start_time = time.time()
                    
                    # Use send_malformed_headers for all tests to ensure headers are sent exactly as specified
                    test_response, _ = await client.send_malformed_headers(
                        method="POST",
                        path=path,
                        headers=test_headers,
                        body=body_content.encode(),
                    )
                    
                    # Record end time and calculate response time
                    end_time = time.time()
                    response_time = end_time - start_time
                    
                    # Log response details for debugging
                    if verbose:
                        logger.info(f"Response Status: {test_response.get('status_code')}")
                        logger.info(f"Response Time: {response_time:.6f}s")
                        logger.info(f"Baseline Response Time: {baseline_response_time:.6f}s")
                        logger.info(f"Time Difference: {response_time - baseline_response_time:.6f}s")
                        logger.info(f"Ratio: {response_time / baseline_response_time:.2f}x")
                    
                    # A vulnerability is detected if the response time is significantly longer
                    # than the baseline (indicating the server was waiting for more data)
                    # or if we get a specific error response that indicates the server was expecting more data
                    
                    is_vulnerable = False
                    reason = "No delay detected"
                    
                    # First detection method: timing
                    # If the response takes significantly longer than the baseline, likely vulnerable
                    if response_time > baseline_response_time * 3:
                        is_vulnerable = True
                        reason = f"Response time ({response_time:.3f}s) is more than 3x the baseline ({baseline_response_time:.3f}s)"
                        if verbose:
                            logger.info(f"POTENTIAL VULNERABILITY DETECTED: {reason}")
                    
                    # Second detection method: error responses
                    # Some servers will respond with specific error codes when they're waiting for more data
                    if test_response.get('status_code') in [408, 400, 500]:
                        if verbose:
                            logger.info(f"Suspicious status code: {test_response.get('status_code')}")
                        # Check if this is a timeout or bad request that could indicate a smuggling issue
                        if response_time > baseline_response_time * 1.5:
                            is_vulnerable = True
                            reason = f"Status code {test_response.get('status_code')} with increased response time ({response_time:.3f}s vs baseline {baseline_response_time:.3f}s)"
                            if verbose:
                                logger.info(f"POTENTIAL VULNERABILITY DETECTED: {reason}")
                    
                    # Record the test result
                    test_result = {
                        'is_vulnerable': is_vulnerable,
                        'response_time': response_time,
                        'baseline_time': baseline_response_time,
                        'time_difference': response_time - baseline_response_time,
                        'time_ratio': response_time / baseline_response_time if baseline_response_time > 0 else 0,
                        'reason': reason,
                        'description': mutation["description"],
                        'header_name': header_name,
                        'header_value': header_value,
                        'placement_type': mutation["type"],
                    }
                    
                    # Add to overall results if vulnerable
                    if is_vulnerable:
                        logger.info(f"Vulnerability detected: {reason}")
                        results["findings"].append(test_result)
                        results["vulnerable"] = True
                        
                        # Optionally stop after finding the first vulnerability
                        if exit_first:
                            logger.info("Stopping after finding a vulnerability (--exit-first flag)")
                            break
                except Exception as e:
                    logger.error(f"Error during test execution: {e}")
                    results['errors'].append({
                        'description': mutation["description"],
                        'header_name': header_name,
                        'header_value': header_value,
                        'error': str(e),
                    })
                finally:
                    await client.close()
            except Exception as e:
                logger.error(f"Error preparing test: {e}")
                results['errors'].append({
                    'description': mutation.get("description", "Unknown"),
                    'error': str(e),
                })
    except Exception as e:
        logger.error(f"Error: {e}")
        results['errors'].append({
            'error': str(e),
        })
    finally:
        await client.close()
    
    return results


async def test_h2_te(
    url: str,
    verbose: bool = False,
    timeout: float = 5.0,
    exit_first: bool = False,
    headers_file: Optional[str] = None,
    custom_headers: List[Tuple[str, str]] = None,
    payload_placement: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Test for H2.TE HTTP request smuggling vulnerability.
    
    Args:
        url: Target URL
        verbose: Whether to print verbose output
        timeout: Request timeout in seconds
        exit_first: Whether to exit after finding the first vulnerability
        headers_file: Not used, kept for compatibility
        custom_headers: Additional headers to include in the request
        payload_placement: Where to place the payload (normal_header, custom_header_value, custom_header_name)
        
    Returns:
        List of findings
    """
    # Parse custom headers
    headers = []
    if custom_headers:
        headers.extend(custom_headers)
    
    # Run the vulnerability test
    results = await test_h2_te_vulnerability(
        url=url,
        headers=headers,
        timeout=timeout,
        verbose=verbose,
        exit_first=exit_first,
        headers_file=headers_file,
        payload_placement=payload_placement,
    )
    
    # Convert results to the format expected by the CLI
    findings = []
    
    # First, check if there were any findings marked as vulnerable
    for finding in results.get('findings', []):
        if finding.get('is_vulnerable', False):  
            finding_details = {
                'type': 'h2.te',
                'url': url,
                'response_time': finding.get('response_time', 0),
                'baseline_time': finding.get('baseline_time', 0),
                'ratio': finding.get('response_time', 0) / finding.get('baseline_time', 1) if finding.get('baseline_time', 0) > 0 else 0,
                'details': 'HTTP/2 to HTTP/1 Transfer-Encoding desync vulnerability',
                'reason': finding.get('reason', 'Unknown reason'),
                'mutation_description': finding.get('description', 'Unknown mutation type'),
                'header_name': finding.get('header_name', 'Unknown'),
                'header_value': finding.get('header_value', 'Unknown'),
                'placement_type': finding.get('placement_type', 'Unknown'),
            }
            
            # Add specific details based on the type of finding
            if 'header' in finding:
                finding_details['header'] = finding['header']
                finding_details['details'] += f" (header: {finding['header']})"
            
            findings.append(finding_details)
    
    return findings


async def main(args: argparse.Namespace) -> int:
    """Main function for the H2.TE detector.
    
    Args:
        args: Command-line arguments
        
    Returns:
        Exit code (0 for success, 1 for vulnerability found, 2 for error)
    """
    # Set up logging
    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO)
    logger = get_logger()
    
    # Parse custom headers
    custom_headers = []
    if args.header:
        for header in args.header:
            try:
                name, value = header.split(':', 1)
                custom_headers.append((name.strip(), value.strip()))
            except ValueError:
                logger.warning(f"Invalid header format: {header}")
    
    logger.info(f"Testing {args.url} for H2.TE vulnerabilities...")
    
    try:
        # Test basic connectivity first
        try:
            logger.info(f"Testing basic connectivity to {args.url}")
            import http.client
            from urllib.parse import urlparse
            
            parsed_url = urlparse(args.url)
            host = parsed_url.netloc
            path = parsed_url.path or '/'
            
            if parsed_url.scheme == 'https':
                conn = http.client.HTTPSConnection(host, timeout=args.timeout)
            else:
                conn = http.client.HTTPConnection(host, timeout=args.timeout)
            
            conn.request('GET', path)
            response = conn.getresponse()
            logger.info(f"Basic connectivity test: {response.status} {response.reason}")
            conn.close()
        except Exception as e:
            logger.warning(f"Basic connectivity test failed: {e}")
        
        # Run the test
        try:
            findings = await test_h2_te(
                url=args.url,
                verbose=args.verbose,
                timeout=args.timeout,
                exit_first=args.exit_first,
                headers_file=args.headers_file,
                custom_headers=custom_headers,
                payload_placement=args.h2_payload_placement,
            )
            
            # Print results
            if findings:
                logger.info("\n===== FINDINGS =====\n")
                for finding in findings:
                    logger.info(f"Finding: {finding['type']}")
                    logger.info(f"Description: {finding['details']}")
                    logger.info(f"Confidence: {finding['ratio']}")
                    logger.info(f"Severity: High")
                    logger.info(f"Details: Mutation description: {finding['mutation_description']}, Header name: {finding['header_name']}, Header value: {finding['header_value']}, Placement type: {finding['placement_type']}")
                    logger.info("")
                
                logger.warning("VULNERABLE: The target is vulnerable to H2.TE request smuggling!")
                return 1
            else:
                logger.info("No vulnerabilities found.")
                return 0
        except KeyboardInterrupt:
            logger.info("Interrupted by user.")
            return 2
        except Exception as e:
            logger.error(f"Error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return 2
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return 2


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Test for H2.TE HTTP request smuggling vulnerabilities")
    parser.add_argument('url', help="Target URL")
    parser.add_argument('-t', '--timeout', type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('-o', '--output', help="Save results to JSON file")
    parser.add_argument('-H', '--header', action='append', help="Add custom header (can be used multiple times)")
    parser.add_argument('-x', '--exit-first', action='store_true', help="Exit after finding the first vulnerability")
    parser.add_argument('-f', '--headers-file', help="Not used, kept for compatibility")
    parser.add_argument('--h2-payload-placement', choices=['normal_header', 'custom_header_value', 'custom_header_name'],
                      help="Where to place the payload (normal_header, custom_header_value, custom_header_name)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    exit_code = asyncio.run(main(args))
    sys.exit(exit_code)
