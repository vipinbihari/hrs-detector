# PRD: hrs_finder Web GUI Frontend

**Version:** 1.0
**Date:** 2025-05-03

## 1. Introduction

This document outlines the requirements for a web-based graphical user interface (GUI) frontend for the `hrs_finder` command-line tool. The goal is to provide a user-friendly way to interact with the tool's scanning capabilities without needing direct access to the command line.

## 2. Goals

*   Provide an intuitive web interface for configuring and running `hrs_finder` scans.
*   Display scan progress and results clearly within the browser.
*   Utilize basic HTML, CSS, and JavaScript for the frontend, interacting with a simple Python backend.
*   Enable users to leverage the core features of the `hrs_finder` scan command through the GUI.

## 3. Target Audience

*   Security testers and penetration testers.
*   Web developers testing their applications for HTTP Request Smuggling vulnerabilities.
*   Users who prefer a graphical interface over a command-line tool.

## 4. Key Features

### 4.1. Scan Configuration

The GUI will provide input elements corresponding to the primary options of the `hrs_finder scan` command:

*   **Target URL:** A required text input field for the target URL (e.g., `https://example.com`). Input validation should check for a basic URL format.
*   **Vulnerability Types:** Checkboxes or a multi-select dropdown to choose which vulnerability types to scan for (`cl.te`, `te.cl`, `h2.cl`, `h2.te`). If none are selected, the backend should default to scanning all types.
*   **Custom Headers:** A text area or a dynamic list interface (add/remove fields) to input custom headers in the `Name: Value` format. Each entry corresponds to a `-H` flag.
*   **Timeout:** A number input field for the request timeout in seconds (`--timeout`), defaulting to 5.0.
*   **Exit First:** A checkbox to enable stopping the scan after the first vulnerability is found (`-e` / `--exit-first`).
*   **Verbose Output:** A checkbox to enable verbose logging (`-v` / `--verbose`).
*   **H2 Payload Placement:** A dropdown selector (enabled only if `h2.cl` or `h2.te` is selected) for the `--h2-payload-placement` option, with choices: `normal_header`, `custom_header_value`, `custom_header_name`, `request_line`.
*   **(Optional) Header Variations File:** A file input field to specify a custom file path for header variations (`-f` / `--file`). *Note: The exact purpose and implementation status of this CLI flag needs clarification before GUI implementation.*

### 4.2. Scan Execution

*   **Scan Button:** A button to initiate the scan process based on the configured parameters.
*   **Loading/Progress Indicator:** Visual feedback (e.g., spinner, progress message) indicating that a scan is in progress.

### 4.3. Results Display

*   **Output Area:** A dedicated section (e.g., a `<pre>` tag or a styled `<div>`) to display the real-time output streamed from the `hrs_finder` CLI process.
*   **Output Formatting:** Preserve the formatting (including colors, if possible using libraries like `ansi_up`) from the `rich` console output of the CLI tool.
*   **Clear Status:** Indicate clearly when the scan starts, finishes, or encounters an error.

## 5. Non-Functional Requirements

*   **Technology Stack:**
    *   Frontend: HTML5, CSS3, Vanilla JavaScript (ES6+).
    *   Backend: Python (e.g., using Flask, FastAPI, or the built-in `http.server` module with custom request handling).
*   **User Interface:** Clean, modern, and intuitive design. Responsive layout is desirable but not strictly required for V1.
*   **Performance:** The backend must handle scan execution asynchronously to avoid blocking the web server. Results should be streamed to the frontend without significant delay.
*   **Security:** Basic input validation on the frontend. The backend must securely construct and execute the CLI command, preventing potential command injection vulnerabilities.

## 6. Architecture

### 6.1. Frontend (Browser)

*   **`index.html`:** Defines the structure of the web page (input fields, buttons, output area).
*   **`style.css`:** Provides styling for a modern look and feel.
*   **`script.js`:**
    *   Handles user interactions (button clicks, input changes).
    *   Collects data from form elements.
    *   Validates input (basic checks).
    *   Constructs a JSON payload with scan parameters.
    *   Sends an asynchronous request (e.g., `fetch` API) to the backend API endpoint (e.g., `/scan`).
    *   Establishes a connection (e.g., WebSocket or EventSource) to receive streamed results from the backend.
    *   Updates the output area in real-time as data arrives from the backend.
    *   Handles connection errors and scan completion signals.

### 6.2. Backend (Python Server)

*   **`server.py` (or similar):**
    *   Runs a lightweight Python web server.
    *   Defines an API endpoint (e.g., `/scan`, accepting POST requests with JSON bodies).
    *   Parses the incoming JSON payload containing scan parameters.
    *   Maps the received parameters to the corresponding `hrs_finder` CLI arguments.
    *   **Crucially:** Constructs the `python3 main.py scan ...` command string securely (avoiding direct string formatting with user input if possible, using list arguments for `subprocess`).
    *   Launches the `hrs_finder` script as an asynchronous subprocess (e.g., using `asyncio.create_subprocess_exec`).
    *   Manages a communication channel (e.g., WebSocket connection or SSE stream) back to the specific frontend client that initiated the request.
    *   Reads `stdout` and `stderr` from the subprocess asynchronously.
    *   Streams the output lines back to the connected frontend client.
    *   Handles subprocess termination and potential errors, relaying status back to the frontend.

### 6.3. Communication Protocol

1.  **Frontend -> Backend:** HTTP POST request to `/scan` with a JSON body containing scan parameters (URL, types, headers, timeout, etc.).
2.  **Backend -> Frontend:** Real-time streaming of CLI output. WebSockets are recommended for robust bidirectional communication and easier handling of concurrent clients. Server-Sent Events (SSE) are a simpler alternative if only server-to-client streaming is needed.

## 7. Implementation Details

*   **Backend CLI Execution:** Use `asyncio.create_subprocess_exec` to run `python3 main.py scan ...` asynchronously. This allows capturing `stdout` and `stderr` streams without blocking.
*   **Output Parsing:** The backend script will receive output formatted by `rich`. It should stream this directly to the frontend. The frontend JavaScript can use a library like `ansi_up` to convert ANSI color codes to HTML for display.
*   **Dependency:** The backend server script will depend on the Python environment having the `hrs_finder` dependencies installed.
*   **Running:** The user would typically start the backend server (`python server.py`) and then access the GUI via their web browser (e.g., `http://localhost:8000`).

## 8. Future Considerations (Post V1)

*   Scan history.
*   Saving/Loading scan configurations.
*   More sophisticated results visualization (e.g., highlighting specific findings).
*   Option to save results to a file directly from the GUI.
*   User authentication (if deployed in a shared environment).

