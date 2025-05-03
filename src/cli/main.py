"""
Main CLI entry point for the HTTP Request Smuggling Detection Tool.

This module provides the command-line interface for the tool,
allowing users to run scans and tests against target servers.
"""

import asyncio
import json
import os
import sys
import urllib.parse
from typing import List, Optional, Tuple, Dict, Any

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.clients.http1 import HTTP1Client
from src.utils.logging import setup_logging, get_logger
from src.detectors import cl_te_detector, te_cl_detector, h2_te_detector, h2_cl_detector
import logging

console = Console()


@click.group()
@click.version_option()
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--log-file', help='Log file path')
def cli(debug: bool, log_file: Optional[str]):
    """HTTP Request Smuggling Detection Tool.
    
    A Python toolkit for detecting HTTP request smuggling vulnerabilities.
    """
    # Set up logging
    log_level = 10 if debug else 20  # DEBUG=10, INFO=20
    setup_logging(level=log_level, log_file=log_file, verbose=debug)


@cli.command()
@click.argument('url')
@click.option('--method', '-m', default='GET', help='HTTP method to use')
@click.option('--header', '-H', multiple=True, help='HTTP header (can be used multiple times)')
@click.option('--data', '-d', help='HTTP request body')
@click.option('--raw', '-r', help='Path to file containing raw HTTP request')
@click.option('--keep-alive', is_flag=True, help='Keep connection alive after request')
@click.option('--timeout', '-t', default=15.0, help='Read timeout in seconds')
@click.option('--connect-timeout', '-c', default=5.0, help='Connection timeout in seconds')
@click.option('--output', '-o', help='Output file for response')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--verify-ssl', is_flag=True, help='Verify SSL certificates')
def request(
    url: str,
    method: str,
    header: List[str],
    data: Optional[str],
    raw: Optional[str],
    keep_alive: bool,
    timeout: float,
    connect_timeout: float,
    output: Optional[str],
    verbose: bool,
    verify_ssl: bool,
):
    """Send a custom HTTP/1.1 request to a target server.
    
    URL should be in the format http(s)://hostname[:port]/path
    """
    logger = get_logger()
    
    # Parse URL
    try:
        parsed_url = urllib.parse.urlparse(url)
        scheme = parsed_url.scheme.lower()
        if scheme not in ('http', 'https'):
            console.print(f"[bold red]Error:[/] Invalid URL scheme: {scheme}. Must be http or https.")
            sys.exit(1)
            
        host = parsed_url.netloc
        path = parsed_url.path or '/'
        
        if ':' in host:
            host, port_str = host.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                console.print(f"[bold red]Error:[/] Invalid port: {port_str}")
                sys.exit(1)
        else:
            port = 443 if scheme == 'https' else 80
            
        use_tls = scheme == 'https'
    except Exception as e:
        console.print(f"[bold red]Error parsing URL:[/] {e}")
        sys.exit(1)
        
    # Add query string to path if present
    if parsed_url.query:
        path = f"{path}?{parsed_url.query}"
    
    # Parse headers
    headers = []
    for h in header:
        if ':' in h:
            name, value = h.split(':', 1)
            headers.append((name.strip(), value.strip()))
        else:
            console.print(f"[bold yellow]Warning:[/] Ignoring invalid header format: {h}")
    
    # Add Host header if not present
    if not any(name.lower() == 'Host' for name, _ in headers):
        headers.append(('Host', host))
    
    # Convert data to bytes
    body_bytes = None
    if data:
        body_bytes = data.encode('utf-8')
    
    # Read raw request if specified
    raw_request = None
    if raw:
        try:
            with open(raw, 'rb') as f:
                raw_request = f.read()
        except Exception as e:
            console.print(f"[bold red]Error reading raw request file:[/] {e}")
            sys.exit(1)
    
    # Run the request
    try:
        asyncio.run(
            _run_request(
                host, port, use_tls, method, path, headers, body_bytes,
                raw_request, keep_alive, timeout, connect_timeout,
                output, verbose, verify_ssl
            )
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Request cancelled by user[/]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        logger.exception("Unhandled exception")
        sys.exit(1)


async def _run_request(
    host: str,
    port: int,
    use_tls: bool,
    method: str,
    path: str,
    headers: List[Tuple[str, str]],
    body: Optional[bytes],
    raw_request: Optional[bytes],
    keep_alive: bool,
    timeout: float,
    connect_timeout: float,
    output: Optional[str],
    verbose: bool,
    verify_ssl: bool,
):
    """Run an HTTP request using the HTTP1Client."""
    logger = get_logger()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Connecting...", total=None)
        
        client = HTTP1Client(
            host=host,
            port=port,
            use_tls=use_tls,
            timeout=timeout,
            connect_timeout=connect_timeout,
            keep_alive=keep_alive,
            verify_ssl=verify_ssl,
        )
        
        try:
            await client.connect()
            
            progress.update(task, description="Sending request...")
            
            start_message = f"Sending {method} request to {path}"
            if raw_request:
                start_message = "Sending raw request"
            logger.info(start_message)
            
            response_info, response_body = await client.send_request(
                method=method,
                path=path,
                headers=headers,
                body=body,
                raw_request=raw_request,
            )
            
            progress.update(task, description="Processing response...", completed=True)
        finally:
            progress.stop()
    
    # Print response info
    console.print(f"[bold green]Status:[/] {response_info['status_code']} {response_info.get('status_message', '')}")
    console.print(f"[bold green]Response time:[/] {response_info.get('response_time', 0):.6f} seconds")
    
    if verbose:
        console.print("\n[bold green]Response headers:[/]")
        for name, value in response_info.get('headers', []):
            console.print(f"  [blue]{name}:[/] {value}")
    
    # Print response body
    try:
        body_text = response_body.decode('utf-8', errors='replace')
        if verbose:
            console.print("\n[bold green]Response body:[/]")
            if len(body_text) > 4096:
                console.print(body_text[:4096])
                console.print("[dim]... (truncated)[/]")
            else:
                console.print(body_text)
        else:
            console.print(f"\n[bold green]Response body:[/] {len(response_body)} bytes")
    except Exception:
        if verbose:
            console.print("\n[bold green]Response body:[/] [dim](binary data)[/]")
            console.print(response_body[:100].hex())
            if len(response_body) > 100:
                console.print("[dim]... (truncated)[/]")
        else:
            console.print(f"\n[bold green]Response body:[/] {len(response_body)} bytes (binary)")
    
    # Save response to file if requested
    if output:
        try:
            with open(output, 'wb') as f:
                f.write(response_body)
            console.print(f"[bold green]Response saved to:[/] {output}")
        except Exception as e:
            console.print(f"[bold red]Error saving response to file:[/] {e}")
            
    # Close the connection
    await client.close()


@cli.command()
@click.argument('url_arg', required=False)
@click.option('-u', '--url', help='Target URL to scan (http(s)://hostname[:port])')
@click.option('-t', '--type', help='Comma-separated vulnerability types to test (e.g., "cl.te,te.cl")')
@click.option('-o', '--output', help='Output file for results (JSON)')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
@click.option('--verify-ssl', is_flag=True, help='Verify SSL certificates')
@click.option('--timeout', default=5.0, help='Request timeout in seconds')
@click.option('-e', '--exit-first', is_flag=True, help='Stop after finding the first vulnerability')
@click.option('-H', '--header', multiple=True, help='Custom header to include in requests (format: "Name: Value")')
@click.option('-f', '--file', help='Path to file containing Transfer-Encoding header variations')
@click.option('--h2-payload-placement', type=click.Choice(['normal_header', 'custom_header_value', 'custom_header_name', 'request_line']), help='Where to place the HTTP/2 payload (normal_header, custom_header_value, custom_header_name, request_line)')
def scan(
    url_arg: Optional[str],
    url: Optional[str],
    type: Optional[str],
    output: Optional[str],
    verbose: bool,
    verify_ssl: bool,
    timeout: float,
    exit_first: bool,
    header: List[str],
    file: Optional[str],
    h2_payload_placement: Optional[str],
):
    """Scan a target for HTTP request smuggling vulnerabilities.
    
    URL should be in the format http(s)://hostname[:port]
    """
    # Determine the target URL (prioritize positional argument over option)
    target_url = url_arg if url_arg else url
    
    # Check if URL is provided
    if not target_url:
        console.print("[bold red]Error:[/bold red] URL is required. Provide it as an argument or with --url/-u option.")
        console.print("Example: hrs_finder scan https://example.com")
        console.print("         hrs_finder scan --url https://example.com")
        sys.exit(1)
    
    # Configure logging based on verbose flag
    logger = get_logger()
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)
    
    # Configure handlers to respect verbose flag
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setLevel(log_level)
    
    # Process custom headers
    custom_headers = []
    for header_str in header:
        try:
            name, value = header_str.split(':', 1)
            custom_headers.append((name.strip(), value.strip()))
        except ValueError:
            console.print(f"[bold red]Error:[/bold red] Invalid header format: {header_str}")
            console.print("Headers should be in the format 'Name: Value'")
            sys.exit(1)
    
    # Process vulnerability types
    vulnerability_types = []
    if type:
        # Debug the raw input
        if verbose:
            console.print(f"[blue]Debug:[/blue] Raw type input: '{type}'")
            
        # Split by comma, strip whitespace, and convert to lowercase
        # This properly handles cases like "te.cl, cl.te" with spaces after commas
        vulnerability_types = [t.strip().lower() for t in type.split(',') if t.strip()]
        
        # Debug output to help diagnose issues
        if verbose:
            console.print(f"[blue]Debug:[/blue] Parsed vulnerability types: {vulnerability_types}")
    
    # Map of vulnerability types to detector functions
    detector_map = {
        'cl.te': cl_te_detector.test_cl_te,
        'te.cl': te_cl_detector.test_te_cl,
        'h2.te': h2_te_detector.test_h2_te,
        'h2.cl': h2_cl_detector.test_h2_cl,
        # Add more detector types here as they are implemented
    }
    
    # If no types specified, run all available detectors
    if not vulnerability_types:
        vulnerability_types = list(detector_map.keys())
    
    # Validate vulnerability types
    invalid_types = [t for t in vulnerability_types if t not in detector_map]
    if invalid_types:
        console.print(f"[bold yellow]Warning:[/bold yellow] Unknown vulnerability type(s): {', '.join(invalid_types)}")
        console.print(f"Available types: {', '.join(detector_map.keys())}")
        
        # Filter out invalid types
        vulnerability_types = [t for t in vulnerability_types if t in detector_map]
        if not vulnerability_types:
            console.print("[bold red]Error:[/bold red] No valid vulnerability types specified")
            sys.exit(1)

    # Run the selected detectors
    results = {}
    for vuln_type in vulnerability_types:
        console.print(f"\n[bold cyan]Running {vuln_type.upper()} detection...[/]")
        detector_func = detector_map[vuln_type]
        
        # Run the detector asynchronously
        try:
            loop = asyncio.get_event_loop()
            
            # Prepare common arguments for all detectors
            detector_args = {
                'url': target_url,
                'verbose': verbose,
                'timeout': timeout,
                'exit_first': exit_first,
                'custom_headers': custom_headers,
            }
            
            # Add h2_payload_placement only for HTTP/2 detectors
            if vuln_type.startswith('h2.') and h2_payload_placement:
                detector_args['payload_placement'] = h2_payload_placement
            
            result = loop.run_until_complete(detector_func(**detector_args))
            
            if result:
                console.print(f"[bold green]Found {len(result)} {vuln_type.upper()} vulnerabilities![/]")
                
                # Print detailed vulnerability information
                for i, finding in enumerate(result):
                    console.print(f"\n[bold cyan]Finding #{i+1}:[/]")
                    
                    # Display basic finding information
                    console.print(f"  [bold]Type:[/] {vuln_type.upper()}")
                    
                    # Display mutation description and placement details if available
                    if 'mutation_description' in finding:
                        console.print(f"  [bold]Mutation:[/] {finding['mutation_description']}")
                    
                    if 'header_name' in finding and 'header_value' in finding:
                        console.print(f"  [bold]Header:[/] {finding['header_name']}: {finding['header_value']}")
                    
                    if 'placement_type' in finding:
                        console.print(f"  [bold]Placement:[/] {finding['placement_type']}")
                    
                    # Display detection details
                    if 'ratio' in finding:
                        console.print(f"  [bold]Time Ratio:[/] {finding['ratio']:.2f}x")
                    
                    if 'response_time' in finding and 'baseline_time' in finding:
                        console.print(f"  [bold]Response Time:[/] {finding['response_time']:.3f}s (baseline: {finding['baseline_time']:.3f}s)")
                    
                    if 'reason' in finding:
                        console.print(f"  [bold]Reason:[/] {finding['reason']}")
                
                results[vuln_type] = result
                
                # Stop after finding the first vulnerability if exit_first is True
                if exit_first:
                    break
            else:
                console.print(f"[green]No {vuln_type.upper()} vulnerabilities detected.[/]")
                results[vuln_type] = []
                
        except Exception as e:
            console.print(f"[bold red]Error running {vuln_type.upper()} detector:[/] {str(e)}")
            results[vuln_type] = f"Error: {str(e)}"
    
    # Output results to file if requested
    if output:
        try:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"\n[bold green]Results saved to {output}[/]")
        except Exception as e:
            console.print(f"[bold red]Error saving results to {output}:[/] {e}")
    
    # Print summary
    console.print("\n[bold cyan]Scan Summary:[/]")
    for vuln_type, result in results.items():
        if isinstance(result, str) and result.startswith("Error:"):
            console.print(f"  {vuln_type.upper()}: [bold red]Error: {result[7:]}[/]")
        elif result:
            console.print(f"  {vuln_type.upper()}: [bold red]Vulnerable[/] ({len(result)} findings)")
        else:
            console.print(f"  {vuln_type.upper()}: [bold green]Not vulnerable[/]")


def main():
    """Main entry point for the CLI."""
    try:
        cli()
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/] {e}")
        get_logger().exception("Unhandled exception in main")
        sys.exit(1)


if __name__ == '__main__':
    main()
