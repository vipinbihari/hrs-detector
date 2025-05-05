# HTTP Request Smuggling Detection Tool - Technical Documentation

## Project Overview

The HTTP Request Smuggling Detection Tool (hrs_finder) is a Python toolkit designed to detect HTTP request smuggling vulnerabilities in web applications and servers. It focuses on various vulnerability types including CL.TE, TE.CL, H2.TE, and H2.CL, with plans to support CL.0 and H2.0 variants in the future.

The tool features custom HTTP/1.1 and HTTP/2 clients that allow sending non-RFC-compliant requests required for detecting these vulnerabilities. It uses a time-based detection technique to identify potential vulnerabilities without affecting other users or causing side effects.

## Project Structure

```
hrs_finder/
├── frontend/           # Web GUI Application (not covered in this documentation)
├── src/                # Main source code
│   ├── __init__.py     # Package initialization
│   ├── cli/            # Command-line interface
│   │   ├── __init__.py
│   │   └── main.py     # CLI entry point
│   ├── clients/        # HTTP clients
│   │   ├── __init__.py
│   │   ├── base.py     # Base client interface
│   │   ├── http1.py    # HTTP/1.1 client using asyncio
│   │   └── http2.py    # HTTP/2 client using h2
│   ├── detectors/      # Vulnerability detector modules
│   │   ├── __init__.py
│   │   ├── cl_te_detector.py  # CL.TE vulnerability detector
│   │   ├── te_cl_detector.py  # TE.CL vulnerability detector
│   │   ├── h2_cl_detector.py  # H2.CL vulnerability detector
│   │   └── h2_te_detector.py  # H2.TE vulnerability detector
│   └── utils/          # Utility functions
│       ├── __init__.py
│       ├── tls.py      # TLS utilities
│       └── logging.py  # Logging utilities
├── payloads/           # Test payloads (header variations)
│   └── te_headers.json # Transfer-Encoding variations
├── main.py             # Direct execution wrapper
├── hrs_finder.sh       # Shell script wrapper for main CLI
├── setup.py            # Package installation script
├── requirements.txt    # Package dependencies
├── README.md           # Project documentation
└── project_content.md  # This technical documentation
```

## Core Components

### 1. Entry Points

#### main.py

The main entry point for direct execution of the tool without using module syntax.

- **Purpose**: Allows running the tool directly with `python main.py` instead of using module syntax
- **Functions**:
  - Adds the project directory to `sys.path`
  - Imports and runs the `main()` function from `src.cli.main`

#### hrs_finder.sh

A shell script wrapper for the main CLI.

- **Purpose**: Provides an easy way to run the tool without installation
- **Usage**: `./hrs_finder.sh scan https://example.com`

### 2. Command-Line Interface (src/cli/)

#### src/cli/main.py

The main CLI entry point for the tool, implemented using the Click library.

- **Purpose**: Provides the command-line interface for the tool
- **Commands**:
  - `scan`: Scan a target for HTTP request smuggling vulnerabilities
  - `request`: Send a custom HTTP/1.1 request to a target server
- **Functions**:
  - `cli()`: Main CLI group with global options
  - `request()`: Command for sending custom HTTP/1.1 requests
  - `_run_request()`: Helper function to run an HTTP request
  - `scan()`: Command for scanning targets for vulnerabilities
  - `main()`: Main entry point for the CLI

##### scan command

```
hrs_finder scan [OPTIONS] [URL_ARG]
```

- **Arguments**:
  - `url_arg`: Target URL (positional argument, optional)
- **Options**:
  - `-u, --url`: Target URL (alternative to positional argument)
  - `-t, --type`: Comma-separated vulnerability types to test (e.g., "cl.te,te.cl")
  - `-o, --output`: Output file for results (JSON)
  - `-v, --verbose`: Enable verbose output
  - `--verify-ssl`: Verify SSL certificates
  - `--timeout`: Request timeout in seconds (default: 5.0)
  - `-e, --exit-first`: Stop after finding the first vulnerability
  - `-H, --header`: Custom header to include in requests (can be used multiple times)
  - `-f, --file`: Path to file containing Transfer-Encoding header variations
  - `--h2-payload-placement`: Where to place the HTTP/2 payload (normal_header, custom_header_value, custom_header_name, request_line)
- **Returns**: Exits with code 0 if no vulnerabilities found, 1 if vulnerabilities found, 2 if errors occurred

##### request command

```
hrs_finder request [OPTIONS] URL
```

- **Arguments**:
  - `url`: Target URL
- **Options**:
  - `--method, -m`: HTTP method to use (default: GET)
  - `--header, -H`: HTTP header (can be used multiple times)
  - `--data, -d`: HTTP request body
  - `--raw, -r`: Path to file containing raw HTTP request
  - `--keep-alive`: Keep connection alive after request
  - `--timeout, -t`: Read timeout in seconds (default: 15.0)
  - `--connect-timeout, -c`: Connection timeout in seconds (default: 5.0)
  - `--output, -o`: Output file for response
  - `--verbose, -v`: Enable verbose output
  - `--verify-ssl`: Verify SSL certificates
- **Returns**: Displays the response information and body

### 3. HTTP Clients (src/clients/)

#### src/clients/base.py

Defines the abstract base class that all HTTP clients must implement.

- **Classes**:
  - `BaseClient`: Abstract base class for HTTP clients
- **Methods**:
  - `connect()`: Establish a connection to the target server
  - `close()`: Close the connection to the target server
  - `send_request()`: Send an HTTP request to the target server
  - `send_raw()`: Send raw bytes over the connection
  - `receive_raw()`: Receive raw bytes from the connection

#### src/clients/http1.py

Custom HTTP/1.1 client implementation using asyncio for low-level socket control.

- **Classes**:
  - `HTTP1Client`: Custom HTTP/1.1 client for sending non-RFC-compliant requests
- **Methods**:
  - `connect()`: Establish a connection to the target server
  - `close()`: Close the connection to the target server
  - `send_raw()`: Send raw bytes over the connection
  - `receive_raw()`: Receive raw bytes from the connection
  - `_build_request()`: Build a raw HTTP/1.1 request
  - `send_request()`: Send an HTTP request to the target server
  - `_parse_response()`: Parse an HTTP/1.1 response
  - `_read_headers()`: Read HTTP headers from the connection
  - `_read_content_length_body()`: Read a body with a known Content-Length
  - `_read_chunked_body()`: Read a chunked-encoded body
  - `_read_until_close()`: Read body data until the connection closes
  - `pipeline_requests()`: Send multiple requests in a pipeline

#### src/clients/http2.py

Custom HTTP/2 client implementation using the h2 library for framing control.

- **Classes**:
  - `HTTP2Client`: Custom HTTP/2 client for sending non-RFC-compliant requests
- **Methods**:
  - `connect()`: Establish a connection to the target server
  - `close()`: Close the connection to the target server
  - `send_raw()`: Send raw bytes over the connection
  - `receive_raw()`: Receive raw bytes from the connection
  - `_process_incoming_data()`: Process incoming HTTP/2 frames
  - `send_request()`: Send an HTTP/2 request to the target server
  - `send_malformed_headers()`: Send a request with potentially malformed headers
  - `send_padded_data()`: Send a request with padded data frames
  - `_parse_response()`: Parse an HTTP/2 response

### 4. Vulnerability Detectors (src/detectors/)

#### src/detectors/cl_te_detector.py

Detector for CL.TE (Content-Length / Transfer-Encoding) HTTP request smuggling vulnerabilities.

- **Functions**:
  - `test_cl_te_with_header()`: Test for CL.TE vulnerability using a specific Transfer-Encoding header variation
  - `test_cl_te()`: Test for CL.TE vulnerability using time-delay technique with multiple header variations
  - `main()`: Parse command-line arguments and run tests
- **Detection Method**:
  - Sends a request with conflicting Content-Length and Transfer-Encoding headers
  - If the front-end uses Content-Length and back-end uses Transfer-Encoding, the back-end will time out waiting for the next chunk
  - Confirms vulnerability by sending a properly terminated chunked body

#### src/detectors/te_cl_detector.py

Detector for TE.CL (Transfer-Encoding / Content-Length) HTTP request smuggling vulnerabilities.

- **Functions**:
  - `test_te_cl_with_header()`: Test for TE.CL vulnerability using a specific Transfer-Encoding header variation
  - `test_te_cl()`: Test for TE.CL vulnerability using time-delay technique with multiple header variations
  - `main()`: Parse command-line arguments and run tests
- **Detection Method**:
  - Sends a request with conflicting Transfer-Encoding and Content-Length headers
  - If the front-end uses Transfer-Encoding and back-end uses Content-Length, the back-end will process only part of the body
  - Uses timing differences to detect the vulnerability

#### src/detectors/h2_te_detector.py

Detector for H2.TE (HTTP/2 to HTTP/1 Transfer-Encoding) HTTP request smuggling vulnerabilities.

- **Functions**:
  - `test_h2_te()`: Test for H2.TE vulnerability using time-delay technique
  - `main()`: Parse command-line arguments and run tests
- **Detection Method**:
  - Sends an HTTP/2 request with a Transfer-Encoding header that might be smuggled to an HTTP/1.1 back-end
  - Uses timing differences to detect the vulnerability

#### src/detectors/h2_cl_detector.py

Detector for H2.CL (HTTP/2 to HTTP/1 Content-Length) HTTP request smuggling vulnerabilities.

- **Functions**:
  - `test_h2_cl()`: Test for H2.CL vulnerability using time-delay technique
  - `main()`: Parse command-line arguments and run tests
- **Detection Method**:
  - Sends an HTTP/2 request with a Content-Length header that might be smuggled to an HTTP/1.1 back-end
  - Uses timing differences to detect the vulnerability

### 5. Utilities (src/utils/)

#### src/utils/tls.py

TLS utilities for HTTP clients.

- **Functions**:
  - `create_ssl_context()`: Create an SSL context for HTTP connections
  - `get_http1_ssl_context()`: Get an SSL context configured for HTTP/1.1
  - `get_http2_ssl_context()`: Get an SSL context configured for HTTP/2
  - `get_negotiated_protocol()`: Get the negotiated ALPN protocol from an SSL object

#### src/utils/logging.py

Logging utilities for the HTTP Request Smuggling Detection Tool.

- **Functions**:
  - `setup_logging()`: Set up logging for the application
  - `get_logger()`: Get the application logger
  - `log_request()`: Log an HTTP request
  - `log_response()`: Log an HTTP response

### 6. Payloads

#### payloads/te_headers.json

JSON file containing Transfer-Encoding header variations for testing.

- **Format**: Array of objects with the following properties:
  - `description`: Human-readable description of the header variation
  - `header_name`: The header name to use (e.g., "Transfer-Encoding")
  - `header_value`: The header value to use (e.g., "chunked")
  - `extra_headers`: Optional array of additional headers to include

## Configuration Files

### setup.py

Package installation script for the tool.

- **Package Name**: hrs_finder
- **Version**: 0.1.0
- **Dependencies**:
  - click (>=8.0.0)
  - colorama (>=0.4.4)
  - rich (>=10.0.0)
  - h2 (>=4.0.0)
  - hpack (>=4.0.0)
- **Entry Points**:
  - `hrs_finder=src.cli.main:main`

### requirements.txt

Package dependencies for the tool.

- click
- colorama
- rich
- h2
- hpack
- pytest
- mypy
- ruff

## Vulnerability Types

### HTTP/1.1 Vulnerabilities

#### CL.TE

Front-end server uses Content-Length, back-end uses Transfer-Encoding.

- **Detection Method**: Time-based detection using malformed chunked encoding
- **Detector Module**: src/detectors/cl_te_detector.py

#### TE.CL

Front-end server uses Transfer-Encoding, back-end uses Content-Length.

- **Detection Method**: Time-based detection using malformed chunked encoding
- **Detector Module**: src/detectors/te_cl_detector.py

### HTTP/2 Vulnerabilities

#### H2.TE

HTTP/2 front-end smuggles Transfer-Encoding to an HTTP/1.1 back-end.

- **Detection Method**: Time-based detection using HTTP/2 request with smuggled Transfer-Encoding header
- **Detector Module**: src/detectors/h2_te_detector.py

#### H2.CL

HTTP/2 front-end smuggles Content-Length to an HTTP/1.1 back-end.

- **Detection Method**: Time-based detection using HTTP/2 request with smuggled Content-Length header
- **Detector Module**: src/detectors/h2_cl_detector.py

## Usage Examples

### Scan Command

```bash
# Scan for all supported vulnerability types
hrs_finder scan https://example.com

# Scan for specific types (comma-separated, no spaces)
hrs_finder scan https://example.com --type cl.te,te.cl

# Scan for specific types (comma-separated with spaces, requires quotes)
hrs_finder scan https://example.com --type "cl.te, te.cl"

# Scan with custom headers
hrs_finder scan https://example.com -H "Cookie: session=1234" -H "X-Forwarded-For: 127.0.0.1"

# Scan with verbose output
hrs_finder scan https://example.com -v

# Scan with output to a JSON file
hrs_finder scan https://example.com --output results.json

# Stop scanning after the first vulnerability is found
hrs_finder scan https://example.com -e
# or
hrs_finder scan https://example.com --exit-first

# Specify payload placement for H2.CL/H2.TE (e.g., smuggle via header name)
hrs_finder scan https://example.com --type h2.cl,h2.te --h2-payload-placement custom_header_name
```

### Request Command

```bash
# Send a simple GET request
hrs_finder request https://example.com

# Send a POST request with data
hrs_finder request https://example.com -X POST -d "param=value"

# Send a request with custom headers
hrs_finder request https://example.com -H "User-Agent: Custom-Agent" -H "Cookie: session=1234"

# Send a raw request (completely custom)
hrs_finder request https://example.com --raw "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
```

## Running Methods

### Direct Python Execution

```bash
# Run with the main.py wrapper
python3 main.py scan https://example.com

# Run with module syntax
python -m src.cli.main scan https://example.com

# Run a specific detector directly
python -m src.detectors.cl_te_detector https://example.com
```

### Shell Script Wrapper

```bash
# Make the script executable
chmod +x hrs_finder.sh

# Run a scan
./hrs_finder.sh scan https://example.com
```

### Installed Package

```bash
# Install the package
pip install .

# Run the command
hrs_finder scan https://example.com