# HTTP Request Smuggling Detection Tool - Project Content

## Directory Structure
hrs_finder/
├── src/                # Main source code
│   ├── __init__.py
│   ├── cli/            # Command-line interface
│   │   ├── __init__.py
│   │   └── main.py
│   ├── clients/        # HTTP clients
│   │   ├── __init__.py
│   │   ├── base.py     # Base client interface
│   │   ├── http1.py    # Low-level asyncio TCP client
│   │   └── http2.py    # HTTP/2 client using h2 library
│   ├── detectors/      # Vulnerability detectors
│   │   ├── __init__.py
│   │   ├── cl_te_detector.py  # CL.TE vulnerability detector
│   │   ├── te_cl_detector.py  # TE.CL vulnerability detector
│   │   ├── h2_cl_detector.py  # H2.CL vulnerability detector
│   │   └── h2_te_detector.py  # H2.TE vulnerability detector
│   └── utils/          # Utility functions
│       ├── __init__.py
│       ├── tls.py      # TLS utilities
│       └── logging.py  # Logging utilities
├── examples/           # Example scripts
├── payloads/           # Test payloads
│   ├── te_headers.json # Transfer-Encoding header variations
│   └── cl_headers.json # Content-Length header variations
├── main.py             # Direct execution wrapper
├── setup.py            # Package installation script
├── requirements.txt    # Package dependencies
├── hrs_finder.sh       # Shell script wrapper for main CLI
├── h2_request.py       # HTTP/2 request script
├── test_http2_client.py # HTTP/2 client test script

## Implemented Components

### src/clients/base.py
- `BaseClient` abstract base class defining the interface for HTTP clients
- Provides common methods and properties that both HTTP/1.1 and HTTP/2 clients must implement
- Methods:
  - `connect()` - Establish a connection to the target server
  - `close()` - Close the connection to the target server
  - `send_request()` - Send an HTTP request and return the response
  - `send_raw()` - Send raw bytes over the connection
  - `receive_raw()` - Receive raw bytes from the connection

### src/clients/http1.py
- `HTTP1Client` implementation of the `BaseClient` interface for HTTP/1.1
- Uses asyncio for asynchronous I/O
- Features:
  - Full control over request construction
  - Support for non-RFC-compliant requests
  - Detailed logging of requests and responses
  - TLS support with configurable options
  - Connection reuse (keep-alive)
  - Raw bytes mode for complete control

### src/clients/http2.py
- `HTTP2Client` implementation of the `BaseClient` interface for HTTP/2
- Uses the `h2` library for HTTP/2 framing
- Features:
  - Support for sending malformed headers and data frames
  - Ability to send duplicate pseudo-headers
  - Support for conflicting content-length values
  - Control over DATA frames (partial bodies, withheld termination)
  - TLS with ALPN negotiation
  - Enhanced verbose logging with complete raw HTTP/2 request details
  - Detailed frame-level logging when verbose mode is enabled
  - Binary data logging with hex dumps when necessary
  - Timestamps, file names, and line numbers in log messages

### src/cli/main.py
- Main command-line interface for the tool
- Commands:
  - `scan` - Run multiple detector types at once
  - `request` - Send a custom HTTP/1.1 request
- Uses the `click` library for the CLI
- Features:
  - Unified scanning interface for all detector types
  - Custom headers support
  - Output to JSON for further analysis
  - Verbose logging option for detailed output
  - Support for comma-separated vulnerability types

### src/detectors/cl_te_detector.py
- Detector for CL.TE HTTP request smuggling vulnerabilities
- Uses time-delay technique to detect vulnerabilities
- Features:
  - Support for multiple Content-Length and Transfer-Encoding header variations
  - Detailed output with raw request and response

### src/detectors/te_cl_detector.py
- Detector for TE.CL HTTP request smuggling vulnerabilities
- Uses time-delay technique to detect vulnerabilities
- Features:
  - Support for multiple Transfer-Encoding header variations
  - Detailed output with raw request and response

### src/detectors/h2_cl_detector.py
- Detector for H2.CL HTTP request smuggling vulnerabilities
- Tests HTTP/2 to HTTP/1.1 Content-Length desync
- Sends HTTP/2 requests with a Content-Length header value larger than the actual body
- Features:
  - Advanced logging with detailed frame information (when verbose mode is enabled)
  - Multiple header placement options:
    - normal_header: Standard Content-Length header
    - custom_header_value: Content-Length smuggled in a custom header value
    - custom_header_name: Content-Length smuggled in a custom header name
  - Configurable timeout for detection
  - Detailed vulnerability reporting with timing ratios and detection explanation

### src/detectors/h2_te_detector.py
- Detector for H2.TE HTTP request smuggling vulnerabilities
- Tests HTTP/2 to HTTP/1.1 Transfer-Encoding desync
- Sends HTTP/2 requests with a Transfer-Encoding: chunked header and an incomplete chunk
- Features:
  - Advanced logging with detailed frame information (when verbose mode is enabled)
  - Multiple header placement options:
    - normal_header: Standard Transfer-Encoding header
    - custom_header_value: Transfer-Encoding smuggled in a custom header value
    - custom_header_name: Transfer-Encoding smuggled in a custom header name
  - Configurable timeout for detection
  - Detailed vulnerability reporting with timing ratios and detection explanation
  - Uses "0\r\n" as the body instead of "abc" (like in H2.CL)
  - Default end_stream=False to keep the connection open for timing-based detection

### src/utils/tls.py
- TLS utilities for HTTP clients
- Functions:
  - `create_ssl_context()` - Create an SSL context with appropriate settings for HTTP/1.1 and HTTP/2
  - Support for disabling SSL verification
  - ALPN protocol negotiation for HTTP/2

### src/utils/logging.py
- Logging utilities for the tool
- Functions:
  - `setup_logging()` - Configure logging for the tool
  - `get_logger()` - Get a logger instance
- Features:
  - Configurable log level (debug, info, warning, error)
  - Console and file logging
  - Rich formatting for console logs
  - Timestamps in log messages
  - File names and line numbers in log messages
  - Clickable file paths in supported terminals

### test_http2_client.py
- Wrapper script to test the HTTP2 client functionality
- Demonstrates various scenarios:
  - Normal HTTP/2 requests
  - Requests with malformed headers (containing \r\n)
  - Content-Length mismatch (for H2.CL testing)
  - Transfer-Encoding chunked (for H2.TE testing)
  - Header smuggling attempts
- Command-line options for target URL, verbose mode, etc.

## Running Options

### Unified Scan Command
```bash
python3 main.py scan https://example.com --type h2.cl,h2.te -v
```

### Individual Detector Modules
```bash
python -m src.detectors.h2_cl_detector https://example.com -v
```

### Direct HTTP/2 Request
```bash
python h2_request.py https://example.com -v
```

### HTTP/2 Client Test
```bash
python test_http2_client.py https://example.com -v
```

## Detector Types

### HTTP/1.1 Vulnerabilities

- **CL.TE**: Front-end server uses Content-Length, back-end uses Transfer-Encoding
- **TE.CL**: Front-end server uses Transfer-Encoding, back-end uses Content-Length

### HTTP/2 Vulnerabilities

- **H2.CL**: HTTP/2 request with Content-Length header value larger than actual content
- **H2.TE**: HTTP/2 request with Transfer-Encoding: chunked header and incomplete chunk

## Detection Logic

### Time-Based Detection
Both the H2.CL and H2.TE detectors use timing-based detection to identify vulnerabilities:

1. First, they send a normal request to establish a baseline response time
2. Then, they send a manipulated request designed to cause a delay if vulnerable
3. If the response time of the manipulated request is significantly longer (3x or more) than the baseline, the server is likely vulnerable

### H2.CL Detection Method
For H2.CL detection, the tool:
1. Sends an HTTP/2 POST request with `Content-Length: 4`
2. But only sends 3 bytes of body data ("abc")
3. A vulnerable server will wait for the 4th byte that will never arrive

### H2.TE Detection Method
For H2.TE detection, the tool:
1. Sends an HTTP/2 POST request with `Transfer-Encoding: chunked`
2. Sends an incomplete chunked body ("0\r\n" without the final \r\n)
3. A vulnerable server will wait for the final chunk terminator that will never arrive

## Verbose Mode

The tool supports detailed output with the `-v` flag, which enables:

1. HTTP/2 frame-level logging
2. Detailed response parsing
3. Complete header dumps
4. Timing information for baseline and test requests
5. Vulnerability explanation with timing ratios and detection explanation

This mode is particularly useful for debugging and understanding the exact nature of detected vulnerabilities.
