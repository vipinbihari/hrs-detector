# HTTP Request Smuggling Detection Tool (hrs_finder)

A Python toolkit for detecting HTTP request smuggling vulnerabilities, including modern HTTP/2-based variants.

## Overview

This tool is designed to detect various types of HTTP request smuggling vulnerabilities:
- CL.TE - Content-Length / Transfer-Encoding desync
- TE.CL - Transfer-Encoding / Content-Length desync
- H2.TE - HTTP/2 to HTTP/1 Transfer-Encoding desync
- H2.CL - HTTP/2 to HTTP/1 Content-Length desync
- CL.0 - Content-Length: 0 desync variant (planned)
- H2.0 - HTTP/2 content-length: 0 variant (planned)

The tool features custom HTTP/1.1 and HTTP/2 clients that allow sending non-RFC-compliant requests required for detecting these vulnerabilities.

## Project Structure

```
hrs_finder/
├── src/                # Main source code
│   ├── cli/            # Command-line interface
│   ├── clients/        # HTTP clients (HTTP/1.1, HTTP/2)
│   ├── detectors/      # Vulnerability detector modules
│   └── utils/          # Utility functions
├── examples/           # Example scripts
├── payloads/           # Test payloads (header variations)
├── main.py             # Direct execution wrapper
├── hrs_finder.sh       # Shell script wrapper
├── h2_request.py       # HTTP/2 request script
├── test_http2_client.py # HTTP/2 client test script
```

## Installation

You can install the HTTP Request Smuggling Detection Tool in several ways:

### 1. Install from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/hrs_finder.git
cd hrs_finder

# Install in development mode (editable)
pip install -e .
```

With an editable installation (`-e` flag), any changes you make to the source code will be immediately available without reinstalling.

### 2. Install as a Package

```bash
# Clone the repository
git clone https://github.com/yourusername/hrs_finder.git
cd hrs_finder

# Install as a package
pip install .
```

After installation, you can run the tool from anywhere using the `hrs_finder` command:

```bash
# Show help
hrs_finder --help

# Run a scan
hrs_finder scan https://example.com
```

### Updating After Changes

If you've installed in development mode (with `-e`), your changes will be immediately available without reinstalling.

If you've installed as a regular package, you'll need to reinstall after making changes:

```bash
pip install .
```

## Usage

### Running Directly with Python

You can also run the tool directly with Python using the main.py script:

```bash
# Run the main script directly
python3 main.py --help

# Run a scan
python3 main.py scan https://example.com

# Run with options
python3 main.py scan https://example.com --timeout 10 -H "Cookie: session=1234"
```

This is the simplest way to run the tool without installation or module syntax.

### Running Without Installation

You can run the tool without installing it by using Python's module syntax:

```bash
# Run a scan with the unified scan command
python -m src.cli.main scan https://example.com

# Run a specific detector module directly
python -m src.detectors.cl_te_detector https://example.com
python -m src.detectors.h2_te_detector https://example.com
```

### Shell Script Wrapper

Alternatively, you can use the included shell script wrapper:

```bash
# Make the script executable
chmod +x hrs_finder.sh

# Run a scan
./hrs_finder.sh scan https://example.com
```

## Scan Command

The unified `scan` command allows testing for all supported vulnerability types in a single run:

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
```

## HTTP/2-Specific Options

The tool provides additional options for HTTP/2 testing:

```bash
# Specify header payload placement for H2 tests
hrs_finder scan https://example.com --type h2.cl --h2-payload-placement normal_header

# Other placement options:
hrs_finder scan https://example.com --type h2.te --h2-payload-placement custom_header_value
hrs_finder scan https://example.com --type h2.cl --h2-payload-placement custom_header_name
```

## Debug Mode and Verbose Output

To get detailed output for debugging:

```bash
# Enable verbose mode
hrs_finder scan https://example.com -v

# Enable debug logging (more detailed than verbose)
hrs_finder --debug scan https://example.com

# Output logs to a file
hrs_finder --log-file debug.log scan https://example.com
```

## Request Command

The tool also provides a `request` command for sending custom HTTP/1.1 requests:

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

## Vulnerability Details

### HTTP/1.1 Vulnerabilities

- **CL.TE**: Front-end server uses Content-Length, back-end uses Transfer-Encoding
- **TE.CL**: Front-end server uses Transfer-Encoding, back-end uses Content-Length

### HTTP/2 Vulnerabilities

- **H2.CL**: HTTP/2 request with Content-Length header value larger than actual content
- **H2.TE**: HTTP/2 request with Transfer-Encoding: chunked header and incomplete chunk

## Enhanced HTTP2 Client Logging

The HTTP/2 client now provides enhanced logging capabilities, including:

- Detailed information about requests and responses, including headers, body, stream ID, and target
- Frame-level information for HTTP/2 communication
- Timestamps, file names, and line numbers in log messages
- Hex dumps of binary data when necessary

## Rewritten h2_te_detector.py

The `h2_te_detector.py` module has been rewritten to improve performance and accuracy.

## test_http2_client.py Script

A new test script, `test_http2_client.py`, has been added to verify the HTTP/2 client functionality.

## Contributing

Contributions are welcome! Feel free to open issues or pull requests.

## License

This project is available under the MIT License.
