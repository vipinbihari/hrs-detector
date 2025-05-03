#!/usr/bin/env python3
# HTTP Request Smuggling Detector - Web Frontend Server
# This script provides a web-based frontend for the hrs_finder CLI tool

import os
import sys
import json
import asyncio
import logging
import argparse
import datetime
from typing import Dict, List, Optional, Any
import uuid
import signal
from pathlib import Path

# Add the parent directory to sys.path to allow importing the hrs_finder package
parent_dir = str(Path(__file__).resolve().parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, WebSocket, WebSocketDisconnect
    from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    import uvicorn
except ImportError:
    print("Required packages not found. Installing dependencies...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn", "websockets", "pydantic"])
    from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, WebSocket, WebSocketDisconnect
    from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("hrs_finder_frontend")

# ------------------- Models for request validation -------------------

class HeaderModel(BaseModel):
    name: str
    value: str

class ScanRequest(BaseModel):
    url: str
    types: List[str] = Field(default=[])
    headers: List[HeaderModel] = Field(default=[])
    timeout: float = Field(default=5.0)
    exit_first: bool = Field(default=False)
    verbose: bool = Field(default=False)
    h2_payload_placement: Optional[str] = Field(default="normal_header")
    client_id: Optional[str] = Field(default=None)

# ------------------- Global state -------------------

# Store WebSocket connections
active_websockets = {}

# Store running processes
processes = {}

# Define app
app = FastAPI(title="HTTP Request Smuggling Detector", version="1.0.0")

# Add CORS middleware to allow cross-origin requests (for development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- Helper functions -------------------

def get_command_args(scan_request: ScanRequest) -> List[str]:
    """Convert the ScanRequest model to command line arguments for hrs_finder"""
    
    # Start with the base command
    cmd = [sys.executable, os.path.join(parent_dir, "main.py"), "scan"]
    
    # Add the target URL
    cmd.append(scan_request.url)
    
    # Add vulnerability types if specified
    if scan_request.types:
        cmd.append("--type")
        cmd.append(",".join(scan_request.types))
    
    # Add custom headers
    for header in scan_request.headers:
        cmd.append("-H")
        cmd.append(f"{header.name}: {header.value}")
    
    # Add timeout
    cmd.append("--timeout")
    cmd.append(str(scan_request.timeout))
    
    # Add exit_first if enabled
    if scan_request.exit_first:
        cmd.append("--exit-first")
    
    # Add verbose if enabled
    if scan_request.verbose:
        cmd.append("--verbose")
    
    # Add h2_payload_placement if any h2 type is selected
    if "h2.cl" in scan_request.types or "h2.te" in scan_request.types:
        cmd.append("--h2-payload-placement")
        cmd.append(scan_request.h2_payload_placement)
    
    return cmd

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await websocket.accept()
    logger.info(f"WebSocket connection accepted for client: {client_id}")
    
    # Store the WebSocket connection
    active_websockets[client_id] = websocket
    
    try:
        # Send initial message
        await websocket.send_json({"type": "info", "data": "Connected. Waiting for scan to start..."})
        logger.info(f"Sent initial connection message to client {client_id}")
        
        # Keep the connection open until client disconnects
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                logger.info(f"Received ping from client {client_id}")
                await websocket.send_json({"type": "pong", "data": "pong"})
    
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for client: {client_id}")
    except Exception as e:
        logger.error(f"Error in WebSocket handler: {str(e)}")
    finally:
        # Clean up
        logger.info(f"Cleaning up WebSocket for client {client_id}")
        if client_id in active_websockets:
            del active_websockets[client_id]

async def run_scan(client_id: str, scan_request: ScanRequest):
    """Run the scan command and stream output to the client"""
    try:
        # Generate command arguments
        cmd = get_command_args(scan_request)
        
        # Check if we have an active WebSocket connection
        if client_id not in active_websockets:
            logger.error(f"No active WebSocket connection for client {client_id}")
            return
        
        websocket = active_websockets[client_id]
        
        # Send initial messages to the client
        try:
            await websocket.send_json({"type": "info", "data": f"Starting scan for {scan_request.url}..."})
            await websocket.send_json({"type": "info", "data": f"Running command: {sys.executable} {' '.join(cmd[1:])}"})  
            logger.info(f"Sent initial messages to client {client_id}")
        except Exception as e:
            logger.error(f"Error sending initial messages: {str(e)}")
            return
        
        # Log the working directory
        logger.info(f"Working directory: {parent_dir}")
        
        # Check if main script exists
        main_script = os.path.join(parent_dir, "main.py")
        if not os.path.exists(main_script):
            logger.error(f"main.py not found at {main_script}")
            await websocket.send_json({"type": "error", "data": f"Error: main.py not found at {main_script}"})
            return
            
        logger.info(f"Found main.py at {main_script}")
        
        # Create a subprocess with pipes for stdout and stderr
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=parent_dir
            )
            logger.info(f"Process started with PID: {process.pid}")
            
            try:
                await websocket.send_json({"type": "info", "data": f"Process started with PID: {process.pid}"})
            except Exception as e:
                logger.error(f"Error sending process start message: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to start process: {str(e)}")
            await websocket.send_json({"type": "error", "data": f"Failed to start process: {str(e)}"})
            return
        
        # Store the process
        processes[client_id] = process
        
        # Read from stdout and stderr concurrently
        async def read_stream(stream, prefix=""):
            logger.info(f"Started reading from stream (prefix: {prefix})")
            try:
                while True:
                    # Read one line at a time
                    line = await stream.readline()
                    if not line:
                        logger.info(f"End of stream (prefix: {prefix})")
                        break
                    
                    try:
                        line_str = line.decode("utf-8", errors="replace").rstrip()
                        logger.info(f"Read line: {line_str}")
                        
                        if client_id in active_websockets:
                            try:
                                logger.info(f"Sending to client {client_id}: {prefix}{line_str}")
                                await active_websockets[client_id].send_json({"type": "output", "data": f"{prefix}{line_str}"})
                                logger.info(f"Sent to client: {prefix}{line_str}")
                            except Exception as send_err:
                                logger.error(f"Error sending to client: {str(send_err)}")
                    except Exception as e:
                        logger.error(f"Error processing line: {str(e)}")
            except Exception as e:
                logger.error(f"Error in read_stream: {str(e)}")
                if client_id in active_websockets:
                    try:
                        await active_websockets[client_id].send_json({"type": "error", "data": f"{prefix}Error reading output: {str(e)}"})
                    except Exception:
                        logger.error("Could not send error message")
        
        # Create tasks to read from stdout and stderr
        stdout_task = asyncio.create_task(read_stream(process.stdout))
        stderr_task = asyncio.create_task(read_stream(process.stderr, "ERROR: "))
        
        # Wait for the process to complete
        try:
            exit_code = await process.wait()
            logger.info(f"Process exited with code {exit_code}")
        except Exception as e:
            logger.error(f"Error waiting for process: {str(e)}")
            if client_id in active_websockets:
                try:
                    await active_websockets[client_id].send_json({"type": "error", "data": f"Error waiting for process: {str(e)}"})
                except Exception:
                    logger.error("Could not send error message")
        
        # Wait for stdout and stderr to be fully read
        await asyncio.gather(stdout_task, stderr_task)
        
        # Send completion message
        if client_id in active_websockets:
            try:
                await active_websockets[client_id].send_json({"type": "status", "data": "Complete"})
                if exit_code == 0:
                    await active_websockets[client_id].send_json({"type": "info", "data": "Scan completed successfully"})
                else:
                    await active_websockets[client_id].send_json({"type": "info", "data": f"Scan failed with exit code: {exit_code}"})
            except Exception as e:
                logger.error(f"Error sending completion message: {str(e)}")
        
        # Clean up
        if client_id in processes:
            del processes[client_id]
        
    except Exception as e:
        logger.error(f"Error running scan: {str(e)}")
        if client_id in active_websockets:
            try:
                await active_websockets[client_id].send_json({"type": "error", "data": f"Error running scan: {str(e)}"})
            except Exception:
                logger.error("Could not send error message")

# ------------------- Routes -------------------

@app.get("/", response_class=HTMLResponse)
async def get_index():
    """Serve the index.html file"""
    return FileResponse(os.path.join(os.path.dirname(__file__), "index.html"))

@app.get("/style.css")
async def get_css():
    """Serve the style.css file"""
    return FileResponse(os.path.join(os.path.dirname(__file__), "style.css"))

@app.get("/script.js")
async def get_js():
    """Serve the script.js file"""
    return FileResponse(os.path.join(os.path.dirname(__file__), "script.js"))

@app.post("/scan")
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a scan with the provided configuration"""
    try:
        # Get or generate a client ID
        client_id = getattr(scan_request, 'client_id', None)
        if not client_id:
            # Generate a unique client ID if none was provided
            client_id = str(uuid.uuid4())
            
        logger.info(f"Using client ID: {client_id}")
        
        # Add the scan task to the background tasks
        background_tasks.add_task(run_scan, client_id, scan_request)
        
        # Return the client ID
        return {"status": "success", "client_id": client_id}
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return {"status": "error", "error": str(e)}

# ------------------- Main -------------------

def signal_handler(sig, frame):
    """Handle SIGINT and SIGTERM to terminate gracefully"""
    print("Shutting down...")
    # Terminate all running processes
    for process in processes.values():
        try:
            process.terminate()
        except:
            pass
    sys.exit(0)

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="HTTP Request Smuggling Detector Web Frontend")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    args = parser.parse_args()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check if main.py exists
    main_script = os.path.join(parent_dir, "main.py")
    if not os.path.exists(main_script):
        print(f"Error: {main_script} not found. Please make sure the frontend directory is in the root of the hrs_finder project.")
        sys.exit(1)
    
    # Run the server
    print(f"Starting HTTP Request Smuggling Detector Web Frontend on {args.host}:{args.port}")
    print(f"Open your browser and navigate to http://{args.host}:{args.port}/")
    print("Press Ctrl+C to quit")
    
    uvicorn.run(app, host=args.host, port=args.port)
