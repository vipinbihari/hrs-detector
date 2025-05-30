# HRS Finder Frontend Project Documentation

## Overview

This document provides a comprehensive description of the HRS Finder frontend implementation. The frontend is a modern web application that serves as a graphical user interface for the HTTP Request Smuggling (HRS) detection tool. It provides an intuitive interface for configuring and running scans, displaying real-time results, and offers theme customization options and vulnerability findings display.

## Project Structure

```
/frontend/
├── index.html        # Main HTML file that defines the structure of the UI
├── style.css         # CSS file for styling the UI with theme support
├── script.js         # JavaScript for client-side functionality and WebSocket communication
├── server.py         # FastAPI backend server that bridges the UI with the HRS finder tool
├── README.md         # Project setup and usage instructions
└── project_content.md # This file - detailed documentation
```

## Component Description

### 1. Frontend UI (index.html)

The HTML structure defines a modern and responsive user interface with the following main components:

- **App Header**:
  - Logo and title
  - Theme toggle button (sun/moon icon) for switching between light and dark modes

- **App Content**:
  - **Scan Configuration Panel**:
    - Target URL input field
    - Vulnerability type checkboxes (CL.TE, TE.CL, H2.CL, H2.TE)
    - Custom headers section with dynamic addition of header fields
    - Configuration options (timeout, H2 payload placement, etc.)
    - Scan button to initiate the scanning process
  
  - **Scan Results Panel**:
    - Status indicator showing current scan status
    - Output area displaying real-time scan results with scrollbar
    - Toolbar with clear and copy buttons
  
  - **Vulnerability Findings Panel**:
    - Table displaying structured information about discovered vulnerabilities
    - Columns for URL, type, description, header name, and header value
    - Reset button to clear findings independently

- **App Footer**:
  - Basic footer with link to GitHub repository

### 2. Styling (style.css)

The CSS file implements a modern, clean design with:

- **Theme Support**:
  - CSS variables for light and dark themes
  - Seamless transitions between themes
  - System preference detection for initial theme

- **Responsive Layout**:
  - Grid-based layout with named template areas
  - Mobile-first approach with responsive breakpoints
  - Proper panel arrangement (side-by-side on desktop, stacked on mobile)

- **UI Components**:
  - Panel-based layout with consistent styling
  - Form elements with modern styling
  - Status indicators with color-coding
  - Output styling with different formats for logs, errors, and debug messages
  - Findings table with distinctive header row and consistent row styling

### 3. Client-Side Logic (script.js)

The JavaScript file handles all client-side functionality:

- **DOM Manipulation**:
  - Form element handling
  - Dynamic addition/removal of header input fields
  - Output area updates
  - Vulnerability findings table population

- **WebSocket Communication**:
  - Establishing real-time communication with the backend
  - Handling different message types (status, output, errors)
  - Ensuring proper connection flow (WebSocket first, then scan request)

- **Vulnerability Findings Parsing**:
  - Extracting vulnerability information from scan output using regex
  - Parsing structured data from output markers
  - Populating the findings table with extracted data

- **Theme Management**:
  - Detecting system color scheme preference
  - Storing user theme preference in localStorage
  - Toggling between light and dark themes

- **Form Handling**:
  - Collecting and validating form data
  - Dynamically showing/hiding H2 payload options based on selected vulnerability types
  - Converting form data to JSON for backend communication

- **Scan Process**:
  - Initiating scans via API
  - Updating UI during scanning
  - Processing and displaying real-time scan results

### 4. Backend Server (server.py)

The FastAPI server bridges the frontend UI with the HRS finder tool:

- **API Endpoints**:
  - `/scan` - POST endpoint to start a new scan
  - `/ws/{client_id}` - WebSocket endpoint for real-time communication

- **Process Management**:
  - Converting scan requests to command-line arguments
  - Executing the HRS finder tool as a subprocess
  - Streaming output in real-time to the frontend
  - Managing concurrent scan processes

- **WebSocket Handling**:
  - Maintaining active WebSocket connections
  - Sending structured JSON messages to the client
  - Handling connection lifecycle (connect, disconnect, errors)

## Key Implementation Details

### WebSocket Communication Flow

1. Frontend establishes a WebSocket connection to `/ws/{client_id}`
2. After successful connection, frontend sends a scan request to `/scan` with the same client_id
3. Backend starts the HRS finder process and streams output to the corresponding WebSocket
4. Frontend processes and displays messages in real-time

### Theme System

The theme system uses CSS variables to define colors for light and dark modes:

1. Default theme is based on system preference (using `prefers-color-scheme` media query)
2. User can toggle between themes using the theme button
3. Theme preference is stored in localStorage for persistence
4. Theme changes are applied without page reload

### Dynamic Header Management

Custom headers are managed dynamically:

1. Users can add multiple custom header fields
2. Each header has a name and value input, plus a remove button
3. Headers are collected and sent as part of the scan configuration

### Vulnerability Findings Table

The application automatically extracts and displays vulnerability findings:

1. Parses scan output for specific markers (e.g., Vulnerability_Type:, Vulnerable_URL:)
2. Extracts structured data using regular expressions
3. Populates a dedicated table with formatted columns
4. Provides table-specific controls separate from the scan output
5. Displays vulnerability details in a structured, easy-to-read format

### Scan Output Processing

The application handles different types of output:

1. Regular log messages are displayed as-is
2. Error messages (prefixed with "ERROR:") are styled differently
3. Debug messages (containing "Debug:") have special formatting
4. ANSI color codes are converted to HTML for proper display
5. Output area has a fixed height with scrollbar for overflow

## Troubleshooting

### Common Issues

- **Scan Not Starting**: Ensure the WebSocket connection is established before initiating a scan
- **No Output**: Check browser console for WebSocket errors
- **H2 Payload Options Not Showing**: Verify that H2.CL or H2.TE vulnerability types are selected
- **Findings Not Appearing in Table**: Check that scan output contains correctly formatted finding markers

### Debug Tips

- Enable verbose output for detailed scan information
- Check browser developer tools for WebSocket communication logs
- Server logs provide additional information about process execution
- Console logs include information about vulnerability data extraction

## Future Enhancements

Potential improvements to consider:

- Add scan history feature for previous scan results
- Implement save/load functionality for scan configurations
- Add export options for vulnerability findings (CSV, JSON, PDF)
- Implement user authentication for multi-user environments
- Add more detailed visualizations for vulnerability analysis
- Implement pagination for large result sets in the findings table
