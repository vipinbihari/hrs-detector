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

```text
hrs_finder/
├── src/                # Main source code
│   ├── __init__.py
│   ├── cli/            # Command-line interface
│   │   ├── __init__.py
│   │   └── main.py
│   ├── clients/        # HTTP clients
│   │   ├── __init__.py
│   │   ├── base.py     # Base client interface
│   │   ├── http1.py    # HTTP/1.1 client using asyncio
│   │   └── http2.py    # HTTP/2 client using h2
│   ├── detectors/      # Vulnerability detector modules
│   │   ├── __init__.py
│   │   ├── cl_te_detector.py
│   │   ├── te_cl_detector.py
│   │   ├── h2_cl_detector.py
│   │   └── h2_te_detector.py
│   └── utils/          # Utility functions
│       ├── __init__.py
│       ├── tls.py
│       └── logging.py
├── examples/           # Example usage scripts (if any)
├── payloads/           # Test payloads (header variations)
│   ├── te_headers.json # Transfer-Encoding variations
│   └── cl_headers.json # Content-Length variations
├── tests/              # Unit and integration tests
├── main.py             # Direct execution wrapper
├── hrs_finder.sh       # Shell script wrapper for main CLI
├── setup.py            # Package installation script
├── requirements.txt    # Package dependencies
├── test_http2_client.py # Standalone HTTP/2 client test script
├── README.md
├── project_content.md
└── .gitignore
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

This tool utilizes predefined header variations stored in JSON format within the `payloads/` directory (`te_headers.json`, `cl_headers.json`) for constructing test requests.

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

# Stop scanning after the first vulnerability is found
hrs_finder scan https://example.com -e
# or
hrs_finder scan https://example.com --exit-first

# Specify payload placement for H2.CL/H2.TE (e.g., smuggle via header name)
hrs_finder scan https://example.com --type h2.cl,h2.te --h2-payload-placement custom_header_name
```

**Output Formats:** The tool currently supports colorized console output (using `rich`) and JSON file output via the `--output` flag.

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

- **H2.TE**: HTTP/2 front-end smuggles Transfer-Encoding to an HTTP/1.1 back-end
- **H2.CL**: HTTP/2 front-end smuggles Content-Length to an HTTP/1.1 back-end

### Planned Vulnerabilities

- **CL.0**: Content-Length: 0 desync variant
- **H2.0**: HTTP/2 content-length: 0 variant

## Contributing

Contributions are welcome! Please refer to the project's contribution guidelines (if available) or open an issue to discuss potential changes.

## License

(Specify your project's license here, e.g., MIT License)
