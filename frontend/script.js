// Main JavaScript for HTTP Request Smuggling Detector GUI

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const scanForm = document.getElementById('scan-form');
    const targetUrlInput = document.getElementById('target-url');
    const typeCheckboxes = document.querySelectorAll('input[name="types"]');
    const h2PayloadGroup = document.getElementById('h2-payload-group');
    const h2PayloadPlacement = document.getElementById('h2-payload-placement');
    const addHeaderButton = document.getElementById('add-header');
    const headersContainer = document.getElementById('headers-container');
    const scanButton = document.getElementById('scan-button');
    const clearButton = document.getElementById('clear-button');
    const clearOutputButton = document.getElementById('clear-output');
    const copyOutputButton = document.getElementById('copy-output');
    const outputArea = document.getElementById('output-area');
    const scanStatus = document.getElementById('scan-status');
    const themeToggleButton = document.getElementById('theme-toggle');
    
    // ANSI to HTML converter
    const ansiUp = new AnsiUp();
    
    // Show/hide H2 payload placement based on selected types
    function updateH2PayloadVisibility() {
        const h2Selected = Array.from(typeCheckboxes).some(cb => 
            (cb.checked && (cb.value === 'h2.cl' || cb.value === 'h2.te')));
        
        h2PayloadGroup.style.display = h2Selected ? 'block' : 'none';
    }
    
    // Initialize header counter
    let headerCounter = 0;
    
    // Add a new custom header input group
    function addHeaderInputGroup() {
        headerCounter++;
        const headerGroup = document.createElement('div');
        headerGroup.className = 'header-input-group';
        
        headerGroup.innerHTML = `
            <input type="text" class="header-name" placeholder="Name" name="header-name-${headerCounter}">
            <input type="text" class="header-value" placeholder="Value" name="header-value-${headerCounter}">
            <button type="button" class="remove-header">-</button>
        `;
        
        headersContainer.appendChild(headerGroup);
        
        // Enable all remove buttons when there's more than one header group
        const removeButtons = document.querySelectorAll('.remove-header');
        if (removeButtons.length > 1) {
            removeButtons.forEach(btn => btn.disabled = false);
        }
        
        // Add event listener to the remove button
        headerGroup.querySelector('.remove-header').addEventListener('click', function() {
            headerGroup.remove();
            
            // If only one header group remains, disable its remove button
            const remainingRemoveButtons = document.querySelectorAll('.remove-header');
            if (remainingRemoveButtons.length === 1) {
                remainingRemoveButtons[0].disabled = true;
            }
        });
    }
    
    // Update the output area with new content
    function updateOutput(content, isStatus = false) {
        if (isStatus) {
            scanStatus.textContent = content;
            
            // Update status class
            scanStatus.className = 'status-indicator';
            if (content.toLowerCase().includes('scanning')) {
                scanStatus.classList.add('status-scanning');
            } else if (content.toLowerCase().includes('complete')) {
                scanStatus.classList.add('status-success');
            } else if (content.toLowerCase().includes('error') || 
                       content.toLowerCase().includes('failed')) {
                scanStatus.classList.add('status-error');
            }
            
            return;
        }

        // Process the content
        if (typeof content === 'string') {
            console.log('Processing output:', content);
            
            // Remove any "ERROR:" prefix for normal display 
            // (these come from stderr in the subprocess)
            let textContent = content;
            const isError = content.startsWith('ERROR:');
            const isDebug = content.includes('Debug:');
            
            if (isError) {
                textContent = content.substring(6).trim(); // Remove "ERROR:" prefix
            }
            
            // Convert ANSI escape sequences to HTML
            const htmlContent = ansiUp.ansi_to_html(textContent);
            
            // Create a new div for the message
            const messageDiv = document.createElement('div');
            messageDiv.className = isError ? 'error-message' : 'log-message';
            
            // Add additional classes for specific message types
            if (isDebug && !isError) {
                messageDiv.classList.add('debug');
            }
            
            messageDiv.innerHTML = htmlContent;
            
            // Append to output area
            outputArea.appendChild(messageDiv);
            
            // Scroll to bottom
            outputArea.scrollTop = outputArea.scrollHeight;
        }
    }
    
    // Vulnerability findings storage
    let vulnerabilityFindings = [];

    // Function to parse scan output for vulnerability findings
    function parseOutputForFindings(output) {
        // Regex to find the markers in the output
        // More precise patterns to extract the exact text after the marker
        const urlRegex = /Vulnerable_URL:\s+([^\s\n]+)/g;
        const typeRegex = /Vulnerability_Type:\s+([^\s\n]+)(?=[\n]|Vulnerable_URL)/g;
        const descRegex = /Header_Description:\s+(.+?)(?=[\n]|Actual_Header_Name)/gs;
        const nameRegex = /Actual_Header_Name:\s+(.+?)(?=[\n]|Actual_Header_Value)/gs;
        const valueRegex = /Actual_Header_Value:\s+(.+?)(?=[\n]|Vulnerability_Type)/gs;
        
        // Extract all occurrences of each marker
        const urls = [...output.matchAll(urlRegex)].map(match => match[1]);
        const types = [...output.matchAll(typeRegex)].map(match => match[1]);
        const descriptions = [...output.matchAll(descRegex)].map(match => match[1].trim());
        const headerNames = [...output.matchAll(nameRegex)].map(match => match[1].trim());
        const headerValues = [...output.matchAll(valueRegex)].map(match => match[1].trim());
        
        // For debugging
        console.log('Extracted URLs:', urls);
        console.log('Extracted Types:', types);
        console.log('Extracted Descriptions:', descriptions);
        console.log('Extracted Header Names:', headerNames);
        console.log('Extracted Header Values:', headerValues);
        
        // Create findings array if we have matches
        const findings = [];
        
        // Only process if we have data for at least one finding
        const count = Math.min(
            urls.length, 
            types.length, 
            descriptions.length, 
            headerNames.length, 
            headerValues.length
        );
        
        for (let i = 0; i < count; i++) {
            findings.push({
                url: urls[i] || '',
                type: types[i] || '',
                description: descriptions[i] || '',
                headerName: headerNames[i] || '',
                headerValue: headerValues[i] || ''
            });
        }
        
        return findings;
    }
    
    // Function to update the findings table
    function updateFindingsTable(findings) {
        // Get the table body and no-findings message
        const tableBody = document.getElementById('findings-body');
        const findingsContainer = document.getElementById('findings-container');
        const noFindingsMessage = document.getElementById('no-findings-message');
        
        // Store findings in the global variable
        vulnerabilityFindings = findings;
        
        // Clear existing rows
        tableBody.innerHTML = '';
        
        // Show or hide based on whether we have findings
        findingsContainer.style.display = 'block'; // Always show the panel
        
        if (findings.length === 0) {
            // Show the no findings message
            noFindingsMessage.style.display = 'flex';
            // Hide the actual table
            document.getElementById('findings-table').style.display = 'none';
            return;
        }
        
        // We have findings - show the table and hide the message
        noFindingsMessage.style.display = 'none';
        document.getElementById('findings-table').style.display = 'table';
        
        // Add new rows
        findings.forEach(finding => {
            const row = document.createElement('tr');
            
            // URL cell
            const urlCell = document.createElement('td');
            urlCell.textContent = finding.url;
            urlCell.className = 'url-cell';
            urlCell.title = finding.url; // Show full URL on hover
            row.appendChild(urlCell);
            
            // Type cell
            const typeCell = document.createElement('td');
            typeCell.textContent = finding.type;
            typeCell.className = 'type-cell';
            row.appendChild(typeCell);
            
            // Description cell
            const descCell = document.createElement('td');
            descCell.textContent = finding.description;
            row.appendChild(descCell);
            
            // Header Name cell
            const nameCell = document.createElement('td');
            nameCell.textContent = finding.headerName;
            nameCell.className = 'header-name-cell';
            nameCell.title = finding.headerName; // Show full name on hover
            row.appendChild(nameCell);
            
            // Header Value cell
            const valueCell = document.createElement('td');
            valueCell.textContent = finding.headerValue;
            valueCell.className = 'header-value-cell';
            valueCell.title = finding.headerValue; // Show full value on hover
            row.appendChild(valueCell);
            
            tableBody.appendChild(row);
        });
    }
    
    // Start the scan
    function startScan(formData) {
        // Disable form elements during scan
        scanButton.disabled = true;
        
        // Clear previous results if needed
        if (outputArea.textContent.trim() !== 'Scan results will appear here...') {
            outputArea.innerHTML = '';
        }
        
        // Update status
        updateOutput('Scanning...', true);
        updateOutput('Starting scan...<br>');
        
        // Close any existing WebSocket connection
        if (window.scanSocket && window.scanSocket.readyState !== WebSocket.CLOSED) {
            window.scanSocket.close();
        }
        
        // Generate a temporary client ID
        const tempClientId = Date.now().toString();
        
        // First establish the WebSocket connection
        connectWebSocket(tempClientId, () => {
            // After WebSocket is connected, start the scan
            sendScanRequest(formData, tempClientId);
        });
    }
    
    // Send the scan request to the server
    function sendScanRequest(formData, clientId) {
        // Send the scan request
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ...formData,
                client_id: clientId // Pass the existing client ID to the server
            })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Server responded with status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                updateOutput(`Error: ${data.error}`, false);
                updateOutput('Failed', true);
                scanButton.disabled = false;
                if (window.scanSocket) {
                    window.scanSocket.close();
                }
            } else {
                updateOutput('Scan started successfully!', false);
            }
        })
        .catch(error => {
            updateOutput(`Error starting scan: ${error.message}`, false);
            updateOutput('Error', true);
            scanButton.disabled = false;
            if (window.scanSocket) {
                window.scanSocket.close();
            }
        });
    }
    
    // Connect to the WebSocket for streaming results
    function connectWebSocket(clientId, onConnectCallback) {
        // Determine the correct WebSocket URL (ws:// or wss:// based on current protocol)
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/${clientId}`;
        
        console.log(`Connecting to WebSocket at: ${wsUrl}`);
        
        // Create WebSocket connection
        window.scanSocket = new WebSocket(wsUrl);
        
        // Connection opened
        window.scanSocket.addEventListener('open', (event) => {
            console.log('WebSocket connection established');
            if (onConnectCallback && typeof onConnectCallback === 'function') {
                onConnectCallback();
            }
        });
        
        // Connection closed
        window.scanSocket.addEventListener('close', (event) => {
            console.log('WebSocket connection closed');
            if (!event.wasClean) {
                updateOutput('Connection to server lost', false);
            }
            scanButton.disabled = false;
            updateOutput('Ready', true);
        });
        
        // Connection error
        window.scanSocket.addEventListener('error', (event) => {
            console.error('WebSocket error:', event);
            updateOutput('Error connecting to server', false);
            scanButton.disabled = false;
            updateOutput('Error', true);
        });
        
        // Send a ping every 30 seconds to keep the connection alive
        const pingInterval = setInterval(() => {
            if (window.scanSocket && window.scanSocket.readyState === WebSocket.OPEN) {
                window.scanSocket.send('ping');
            } else {
                clearInterval(pingInterval);
            }
        }, 30000);
        
        // Listen for messages
        window.scanSocket.addEventListener('message', (event) => {
            console.log('Message from server:', event.data);
            
            let messageText = event.data;
            let messageObj = null;
            
            // Try to parse as JSON, but don't fail if it's not valid JSON
            try {
                messageObj = JSON.parse(messageText);
                console.log('Parsed message:', messageObj);
                
                // Handle different message types
                switch (messageObj.type) {
                    case 'output':
                        // Regular output message
                        updateOutput(messageObj.data);
                        // Check for vulnerability findings in the accumulated output
                        if (outputArea.textContent.includes('Vulnerability_Type')) {
                            const findings = parseOutputForFindings(outputArea.textContent);
                            updateFindingsTable(findings);
                        }
                        break;
                    case 'status':
                        // Status update message
                        updateOutput(messageObj.data, true);
                        // Re-enable scan button on completion
                        if (messageObj.data.includes('Complete') || 
                            messageObj.data.includes('Failed') || 
                            messageObj.data.includes('Error')) {
                            scanButton.disabled = false;
                            
                            // If scan is complete, check for findings
                            if (messageObj.data.includes('Complete')) {
                                const findings = parseOutputForFindings(outputArea.textContent);
                                updateFindingsTable(findings);
                            }
                        }
                        break;
                    case 'info':
                        // Informational message
                        updateOutput(messageObj.data);
                        break;
                    case 'error':
                        // Error message
                        updateOutput(messageObj.data);
                        updateOutput('Error', true);
                        scanButton.disabled = false;
                        break;
                    case 'pong':
                        // Just a pong response, ignore
                        break;
                    default:
                        // Unknown message type, just display as is
                        updateOutput(messageObj.data || messageText);
                }
            } catch (e) {
                // If the message is not valid JSON, handle it as a plain text message
                console.log('Handling as plain text:', messageText);
                
                // Check for status updates in plain text
                if (messageText.includes('Scan completed')) {
                    updateOutput('Complete', true);
                    scanButton.disabled = false; // Re-enable scan button
                } else if (messageText.includes('failed')) {
                    updateOutput('Failed', true);
                    scanButton.disabled = false; // Re-enable scan button
                } else if (messageText.includes('error')) {
                    updateOutput('Error', true);
                    scanButton.disabled = false; // Re-enable scan button
                }
                
                // Always display the message in the output area
                updateOutput(messageText);
            }
        });
    }
    
    // Collect form data
    function collectFormData() {
        const formData = {
            url: document.getElementById('target-url').value,
            types: [],
            headers: [],
            timeout: parseFloat(document.getElementById('timeout').value),
            exit_first: document.getElementById('exit-first').checked,
            verbose: document.getElementById('verbose').checked,
            h2_payload_placement: h2PayloadPlacement.value
        };
        
        // Collect selected vulnerability types
        typeCheckboxes.forEach(checkbox => {
            if (checkbox.checked) {
                formData.types.push(checkbox.value);
            }
        });
        
        // Collect custom headers
        const headerGroups = document.querySelectorAll('.header-input-group');
        headerGroups.forEach(group => {
            const nameInput = group.querySelector('.header-name');
            const valueInput = group.querySelector('.header-value');
            
            if (nameInput.value.trim() && valueInput.value.trim()) {
                formData.headers.push({
                    name: nameInput.value.trim(),
                    value: valueInput.value.trim()
                });
            }
        });
        
        return formData;
    }
    
    // Theme Toggle Functionality
    // Check for saved theme preference or use browser preference
    const savedTheme = localStorage.getItem('theme') || 
                       (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    
    // Apply the saved theme
    setTheme(savedTheme);
    
    // Theme toggle event listener
    themeToggleButton.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
    });
    
    // Function to set the theme
    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }
    
    // Event Listeners
    
    // Show/hide H2 payload placement based on selected types
    typeCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', updateH2PayloadVisibility);
    });
    
    // Add header button
    addHeaderButton.addEventListener('click', (e) => {
        e.preventDefault();
        addHeaderInputGroup();
    });
    
    // Form submission
    scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const formData = collectFormData();
        startScan(formData);
    });
    
    // Reset findings table
    const resetFindingsButton = document.getElementById('reset-findings');
    resetFindingsButton.addEventListener('click', () => {
        vulnerabilityFindings = [];
        updateFindingsTable([]);
    });

    // Clear output button
    clearOutputButton.addEventListener('click', () => {
        outputArea.innerHTML = 'Scan results will appear here...';
        updateOutput('Ready', true);
    });
    
    // Copy output button
    copyOutputButton.addEventListener('click', () => {
        // Get all text content from the output area
        const text = outputArea.innerText;
        
        // Copy to clipboard
        navigator.clipboard.writeText(text)
            .then(() => {
                // Visual feedback that copy succeeded
                copyOutputButton.classList.add('copied');
                setTimeout(() => {
                    copyOutputButton.classList.remove('copied');
                }, 1500);
            })
            .catch(err => {
                console.error('Failed to copy text: ', err);
            });
    });
    
    // Initialize the UI
    updateH2PayloadVisibility();
    addHeaderInputGroup();
    updateFindingsTable([]);
});
