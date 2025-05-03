# HRS Finder GUI

A modern, responsive web interface for the HTTP Request Smuggling (HRS) Finder tool. This GUI allows users to configure, run, and view results from HRS scans with an intuitive interface that supports both light and dark themes.

## Features

- **Modern UI**: Clean, responsive design with light and dark theme support
- **Real-time Results**: View scan output in real-time as the scan progresses
- **Vulnerability Findings Table**: Automatically extracts and displays vulnerability information in a structured format
- **Flexible Configuration**: Configure all scan parameters through an intuitive interface
- **WebSocket Communication**: Utilizes WebSockets for efficient real-time updates

## Prerequisites

- Python 3.6+
- FastAPI
- Uvicorn
- Websockets
- HRS Finder tool installed or accessible

## Installation

1. Install the required Python packages:

```bash
pip install fastapi uvicorn websockets pydantic
```

2. Ensure HRS Finder is installed or accessible in your Python environment

## Usage

1. Start the server:

```bash
python server.py
```

2. Open your browser and navigate to http://localhost:8000

3. Configure your scan:
   - Enter the target URL
   - Select vulnerability types to scan for
   - Add any custom headers
   - Configure additional options

4. Click "Start Scan" to begin the scan

5. View real-time results in the output area

6. Review automatically extracted vulnerability findings in the dedicated table below

## Configuration Options

- **Target URL**: The URL to scan
- **Vulnerability Types**: CL.TE, TE.CL, H2.CL, H2.TE
- **Custom Headers**: Add any number of custom headers
- **Timeout**: Specify request timeout in seconds
- **H2 Payload Placement**: (Only when H2 types selected) Configure where payload is placed
- **Exit After First Vulnerability**: Stop scan after finding first vulnerability
- **Verbose Output**: Show detailed output from the scanner

## UI Features

### Theme Support
Toggle between light and dark themes using the sun/moon icon in the top right corner of the interface. The application will remember your preference for future visits and default to your system preference on first use.

### Scan Results Area
The output area displays real-time scan results with proper formatting for different message types (standard logs, errors, debug messages). A scrollbar appears when content exceeds the container size.

### Vulnerability Findings Table
The findings table automatically extracts and presents vulnerability information in a structured format with columns for:
- URL
- Vulnerability Type
- Description 
- Header Name
- Header Value

Each table has separate controls:
- **Reset Findings**: Clear just the vulnerability findings table
- **Clear Output**: Clear just the scan output area

## Architecture

- **Frontend**: HTML5, CSS3, and vanilla JavaScript
- **Backend**: FastAPI Python server
- **Communication**: WebSockets for real-time updates

## Troubleshooting

- If scans aren't starting, check browser console for WebSocket connection errors
- Make sure the HRS Finder tool is properly installed and accessible
- Check server logs for any backend errors or issues with scan execution

## License

This project is licensed under the same terms as the HRS Finder tool.
