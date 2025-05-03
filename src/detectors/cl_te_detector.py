#!/usr/bin/env python3
"""
Detector script for CL.TE HTTP request smuggling vulnerabilities.

This script sends a request with conflicting Content-Length and Transfer-Encoding
headers to test for CL.TE vulnerabilities using the time-delay technique.
"""

import argparse
import asyncio
import json
import os
import sys
import time
import urllib.parse
from typing import List, Tuple, Dict

# Import from project
from src.clients.http1 import HTTP1Client
from src.utils.logging import setup_logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

async def test_cl_te_with_header(url: str, te_header: Dict, verbose: bool = False, timeout: float = 5.0, custom_headers: List[Tuple[str, str]] = None) -> Dict:
    """Test for CL.TE vulnerability using a specific Transfer-Encoding header variation.
    
    Args:
        url: Target URL
        te_header: Transfer-Encoding header to use (can include special characters)
        verbose: Whether to enable verbose output
        timeout: Request timeout in seconds
        custom_headers: Additional headers to include in the request
        
    Returns:
        Dictionary with test results
    """
    # Parse URL
    parsed_url = urllib.parse.urlparse(url)
    scheme = parsed_url.scheme.lower()
    host = parsed_url.netloc
    path = parsed_url.path or '/'
    
    if ':' in host:
        host, port_str = host.rsplit(':', 1)
        port = int(port_str)
    else:
        port = 443 if scheme == 'https' else 80
        
    use_tls = scheme == 'https'
    
    if verbose:
        print(f"\nTesting with header: {te_header['header_name']}:{te_header['header_value'].replace('\n', '\\n')}")
    
    # Create HTTP client for this test
    test_client = HTTP1Client(
        host=host,
        port=port,
        use_tls=use_tls,
        timeout=timeout,
        connect_timeout=5.0,
    )
    
    result = {
        'header': te_header,
        'vulnerable': False,
        'timed_out': False,
        'time_ratio': 0,
        'test_time': 0,
        'raw_request': '',
        'status_code': None,
        'error': None
    }
    
    try:
        await test_client.connect()
        
        # Prepare headers with Content-Length and the specified Transfer-Encoding variation
        headers = [
            ('Host', host),
            ('Content-Type', 'application/x-www-form-urlencoded'),
            ('Content-Length', '4'),  # Smaller than the actual body length
        ]
        
        # Add any custom headers provided
        if custom_headers:
            headers.extend(custom_headers)
            
        # Process the Transfer-Encoding header
        # Add the main header
        headers.append((te_header['header_name'], te_header['header_value']))
        
        # Add any extra headers if present
        if 'extra_headers' in te_header:
            for extra_header in te_header['extra_headers']:
                headers.append((extra_header['header_name'], extra_header['header_value']))
        
        # Prepare body according to the example
        # If the front-end uses Content-Length and back-end uses Transfer-Encoding,
        # the back-end will time out waiting for the next chunk
        body = (
            # First chunk header (size 1)
            b"1\r\n"
            # Chunk data ('Z')
            b"Z\r\n"
            # Invalid chunk size that will never arrive at back-end
            b"Q\r\n"
        )
        
        # Build the raw request for later display if vulnerability is found
        raw_request = f"POST {path} HTTP/1.1\r\n"
        for name, value in headers:
            raw_request += f"{name}: {value}\r\n"
        raw_request += "\r\n"
        raw_request += body.decode('utf-8', errors='replace')
        
        result['raw_request'] = raw_request
        
        start_time = time.time()
        try:
            test_info, _ = await test_client.send_request(
                method="POST",
                path=path,
                headers=headers,
                body=body,
            )
            test_time = time.time() - start_time
            result['timed_out'] = False
            result['status_code'] = test_info.get('status_code', 0)
            if verbose:
                print(f"Response status: {result['status_code']}")
        except asyncio.TimeoutError:
            test_time = time.time() - start_time
            result['timed_out'] = True
            if verbose:
                print("Request timed out")
        except Exception as e:
            result['error'] = str(e)
            if verbose:
                print(f"Error: {e}")
            return result
        
        result['test_time'] = test_time
        if verbose:
            print(f"Response time: {test_time:.3f} seconds")
            
        # If we detected a potential vulnerability (timeout or significant delay),
        # send a third request with proper Content-Length and properly terminated chunked body
        # to confirm the vulnerability
        if result['timed_out']:
            if verbose:
                print(f"{Fore.CYAN}Potential vulnerability detected (request timed out), sending confirmation request...{Style.RESET_ALL}")
            
            # Prepare headers with accurate Content-Length and the same Transfer-Encoding variation
            confirm_headers = [
                ('Host', host),
                ('Content-Type', 'application/x-www-form-urlencoded'),
                ('Content-Length', '11'),  # Accurate length for the properly terminated body
            ]
            
            # Add any custom headers provided
            if custom_headers:
                confirm_headers.extend(custom_headers)
                
            # Process the Transfer-Encoding header the same way as before
            confirm_headers.append((te_header['header_name'], te_header['header_value']))
            
            # Add any extra headers if present
            if 'extra_headers' in te_header:
                for extra_header in te_header['extra_headers']:
                    confirm_headers.append((extra_header['header_name'], extra_header['header_value']))
            
            # Prepare body with proper chunked encoding termination
            confirm_body = (
                # First chunk header (size 1)
                b"1\r\n"
                # Chunk data ('Z')
                b"Z\r\n"
                # Proper chunked encoding termination
                b"0\r\n\r\n"
            )
            
            # Build the raw request for later display
            confirm_raw_request = f"POST {path} HTTP/1.1\r\n"
            for name, value in confirm_headers:
                confirm_raw_request += f"{name}: {value}\r\n"
            confirm_raw_request += "\r\n"
            confirm_raw_request += confirm_body.decode('utf-8', errors='replace')
            
            result['confirm_raw_request'] = confirm_raw_request
            
            confirm_start_time = time.time()
            try:
                confirm_info, _ = await test_client.send_request(
                    method="POST",
                    path=path,
                    headers=confirm_headers,
                    body=confirm_body,
                )
                confirm_time = time.time() - confirm_start_time
                result['confirm_timed_out'] = False
                result['confirm_status_code'] = confirm_info.get('status_code', 0)
                result['confirm_time'] = confirm_time
                
                if verbose:
                    print(f"Confirmation response status: {result['confirm_status_code']}")
                    print(f"Confirmation response time: {confirm_time:.3f} seconds")
                
                # If the confirmation request doesn't time out, the server is vulnerable
                # (A properly formatted request is processed normally)
                result['vulnerable'] = True
                if verbose:
                    print(f"{Fore.RED}Vulnerability confirmed! The properly terminated request completed successfully.{Style.RESET_ALL}")
                
            except asyncio.TimeoutError:
                confirm_time = time.time() - confirm_start_time
                result['confirm_timed_out'] = True
                if verbose:
                    print("Confirmation request timed out - this is unexpected")
            except Exception as e:
                result['confirm_error'] = str(e)
                if verbose:
                    print(f"Error in confirmation request: {e}")
            
        return result
    
    except Exception as e:
        result['error'] = str(e)
        if verbose:
            print(f"Error: {e}")
        return result
    
    finally:
        await test_client.close()


async def test_cl_te(url: str, verbose: bool = False, timeout: float = 5.0, 
                    exit_first: bool = False, headers_file: str = None, custom_headers: List[Tuple[str, str]] = None):
    """Test for CL.TE vulnerability using time-delay technique with multiple header variations.
    
    Args:
        url: Target URL
        verbose: Whether to enable verbose output
        timeout: Request timeout in seconds (default: 5.0)
        exit_first: Whether to stop after finding the first vulnerability
        headers_file: Path to file containing Transfer-Encoding header variations
        custom_headers: Additional headers to include in all requests
        
    Returns:
        List of vulnerable headers found, empty list if none
    """
    # Set up logging
    setup_logging(verbose=verbose)
    
    # Debug output for URL
    if verbose:
        print(f"Debug: URL received by CL.TE detector: '{url}'")
    
    print(f"{Fore.CYAN}Testing {url} for CL.TE vulnerability...{Style.RESET_ALL}")
    
    # Load Transfer-Encoding header variations
    if headers_file and os.path.exists(headers_file):
        try:
            with open(headers_file, 'r') as f:
                # Load headers from JSON file
                headers_data = json.load(f)
                te_headers = []
                
                # Process the new JSON format with header_name and header_value fields
                for entry in headers_data:
                    if 'header_name' in entry and 'header_value' in entry:
                        # Store the entire entry for later use
                        te_headers.append(entry)
                    
            print(f"{Fore.CYAN}Loaded {len(te_headers)} header variations from {headers_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error loading headers file: {e}{Style.RESET_ALL}")
            # Default fallback header
            te_headers = [{
                "description": "Standard chunked encoding",
                "header_name": "Transfer-Encoding",
                "header_value": "chunked"
            }]
    else:
        # Default list of Transfer-Encoding header variations in the new format
        te_headers = [
            {
                "description": "Standard chunked encoding",
                "header_name": "Transfer-Encoding",
                "header_value": "chunked"
            },
            {
                "description": "Space after header name",
                "header_name": "Transfer-Encoding ",
                "header_value": "chunked"
            }
        ]
        print(f"{Fore.CYAN}Using {len(te_headers)} default header variations{Style.RESET_ALL}")
    
    # First, send a normal request to establish baseline response time
    print(f"\n{Fore.CYAN}Sending baseline request...{Style.RESET_ALL}")
    baseline_client = HTTP1Client(
        host=urllib.parse.urlparse(url).netloc.split(':')[0],
        port=443 if url.startswith('https') else 80,
        use_tls=url.startswith('https'),
        timeout=timeout,
        connect_timeout=5.0,
    )
    
    try:
        await baseline_client.connect()
        
        start_time = time.time()
        baseline_info, _ = await baseline_client.send_request(
            method="GET",
            path=urllib.parse.urlparse(url).path or '/',
            headers=[("Host", urllib.parse.urlparse(url).netloc)],
        )
        baseline_time = time.time() - start_time
        
        print(f"{Fore.CYAN}Baseline response time: {baseline_time:.3f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Baseline status code: {baseline_info['status_code']}{Style.RESET_ALL}")
    finally:
        await baseline_client.close()
    
    # Test each header variation
    vulnerable_headers = []
    
    for i, te_header in enumerate(te_headers):
        print(f"\r{Fore.CYAN}[{i+1}/{len(te_headers)}]{Style.RESET_ALL} Testing header variation", end="")
        sys.stdout.flush()
        
        result = await test_cl_te_with_header(url, te_header, verbose, timeout, custom_headers)
        
        # Calculate time ratio compared to baseline
        if baseline_time > 0 and result['test_time'] > 0:
            time_ratio = result['test_time'] / baseline_time
        else:
            time_ratio = 0
        
        # Determine if this variation indicates a vulnerability
        if result['timed_out'] or result.get('vulnerable', False):
            # Print newline if we're using the progress indicator
            if not verbose:
                print()
                
            # Get the description of the header variation
            description = te_header['description']
            
            print(f"\n{Fore.RED}[!] Potential CL.TE vulnerability detected{Style.RESET_ALL} with header variation: {Fore.YELLOW}{description}{Style.RESET_ALL}")
            print(f"The test request took {Fore.YELLOW}{time_ratio:.1f}x{Style.RESET_ALL} longer than the baseline request.")
            
            # Display the header with escaped control characters for clarity
            escaped_header = f"{te_header['header_name']}:{te_header['header_value'].replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')}"
            print(f"{Fore.CYAN}Header used: {escaped_header}{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Raw request that triggered the vulnerability:{Style.RESET_ALL}")
            print(result['raw_request'])
            
            vulnerable_headers.append((te_header, description))
            
            if exit_first:
                print(f"\n{Fore.YELLOW}Stopping tests as requested (--exit-first){Style.RESET_ALL}")
                break
    
    # Print newline if we're using the progress indicator and didn't find a vulnerability
    if not verbose and not vulnerable_headers:
        print()
    
    # Summarize results
    print(f"\n{Fore.CYAN}" + "=" * 60 + f"{Style.RESET_ALL}")
    # Show the actual number of tested headers, not the total available
    tested_count = min(len(te_headers), i+1) if 'i' in locals() else len(te_headers)
    print(f"{Fore.CYAN}Results Summary:{Style.RESET_ALL} Tested {tested_count} of {len(te_headers)} header variations")
    print(f"{Fore.CYAN}" + "=" * 60 + f"{Style.RESET_ALL}")
    
    findings = []
    if vulnerable_headers:
        print(f"\n{Fore.RED}[!] Found {len(vulnerable_headers)} potential CL.TE vulnerabilities!{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Vulnerable headers:{Style.RESET_ALL}")
        for header, description in vulnerable_headers:
            # Display the header with escaped control characters for clarity
            escaped_header = f"{header['header_name']}:{header['header_value'].replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')}"
            print(f"Header_Description: {Fore.YELLOW}{description}{Style.RESET_ALL}")
            print(f"Actual_Header_Name: {Fore.CYAN}{header['header_name'].replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')}{Style.RESET_ALL}")
            print(f"Actual_Header_Value: {Fore.CYAN}{header['header_value'].replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')}{Style.RESET_ALL}")
            print(f"Vulnerability_Type: {Fore.CYAN}CL.TE{Style.RESET_ALL}")
            print(f"Vulnerable_URL: {Fore.CYAN}{url}{Style.RESET_ALL}")
            print()
            
            # Add to findings list for return value
            findings.append({
                "description": description,
                "header": escaped_header,
                "type": "CL.TE"
            })
    else:
        print(f"\n{Fore.GREEN}No CL.TE vulnerabilities detected with any of the tested header variations.{Style.RESET_ALL}")
    
    return findings

def main():
    """Parse command-line arguments and run tests."""
    parser = argparse.ArgumentParser(description="Test for CL.TE vulnerabilities with multiple header variations")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument("-e", "--exit-first", action="store_true", help="Stop after finding the first vulnerability")
    parser.add_argument("-f", "--file", help="Path to file containing Transfer-Encoding header variations")
    parser.add_argument("-H", "--header", action="append", help="Custom header to include in requests (format: 'Name: Value')")
    
    args = parser.parse_args()
    
    # Process custom headers
    custom_headers = []
    if args.header:
        for header_str in args.header:
            try:
                name, value = header_str.split(':', 1)
                custom_headers.append((name, value))
            except ValueError:
                print(f"{Fore.RED}Invalid header format: {header_str}. Use 'Name: Value' format.{Style.RESET_ALL}")
                sys.exit(1)
    
    findings = asyncio.run(test_cl_te(args.url, args.verbose, args.timeout, args.exit_first, args.file, custom_headers))
    if findings:
        print(f"\n{Fore.RED}[!] Found {len(findings)} potential CL.TE vulnerabilities!{Style.RESET_ALL}")
        for finding in findings:
            print(f"- {Fore.YELLOW}{finding['description']}{Style.RESET_ALL}")
            print(f"  Header: {Fore.CYAN}{finding['header']}{Style.RESET_ALL}")
            print()

if __name__ == "__main__":
    main()
