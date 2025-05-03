"""
Custom HTTP/2 Client implementation.

This module provides a low-level HTTP/2 client that allows for complete control
over request construction, including non-RFC-compliant requests needed for
HTTP request smuggling detection.
"""

import asyncio
import logging
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings

from src.clients.base import BaseClient
from src.utils import tls
from src.utils.logging import get_logger


class HTTP2Client(BaseClient):
    """Custom HTTP/2 client for sending non-RFC-compliant requests.
    
    Features:
    - Built on top of h2 for framing control
    - Ability to bypass default sanity checks
    - Support for sending malformed headers and data frames
    - Ability to send duplicate pseudo-headers
    - Support for conflicting content-length values
    - Control over DATA frames (partial bodies, withheld termination, padding)
    """
    
    def __init__(
        self,
        host: str,
        port: int,
        use_tls: bool = True,
        timeout: float = 5.0,
        connect_timeout: float = 3.0,
        verify_ssl: bool = False,
        force_http2: bool = False,
        verbose: bool = False,
    ) -> None:
        """Initialize a new HTTP/2 client.
        
        Args:
            host: Target hostname or IP address
            port: Target port
            use_tls: Whether to use TLS (HTTPS)
            timeout: Request timeout in seconds
            connect_timeout: Connection timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            force_http2: Whether to force HTTP/2 even if not advertised in ALPN
            verbose: Whether to enable verbose logging
        """
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.verify_ssl = verify_ssl
        self.force_http2 = force_http2
        self.verbose = verbose  # Add verbose attribute
        
        # Set up SSL context
        self.ssl_context = None
        if self.use_tls:
            self.ssl_context = tls.create_ssl_context(
                verify=self.verify_ssl,
                alpn_protocols=['h2', 'http/1.1']
            )
        
        # Set up logging
        self.logger = get_logger()
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        # Connection state
        self._connected = False
        self._reader = None
        self._writer = None
        self._h2_conn = None
        self._response_buffer = bytearray()
        self._stream_id = None
        self._response_streams = {}
        self._response_events = {}
        self._response_data = {}

    async def connect(self) -> None:
        """Establish a connection to the target server.
        
        This method will attempt to establish an HTTP/2 connection with the server.
        If the server doesn't advertise HTTP/2 support via ALPN, it will either
        fall back to HTTP/1.1 or force HTTP/2 based on the force_http2 setting.
        """
        if self._connected:
            return
        
        self.logger.debug(f"Connecting to {self.host}:{self.port} (TLS: {self.use_tls})")
        
        try:
            # Set up SSL context if needed
            ssl_context = None
            if self.use_tls:
                ssl_context = self.ssl_context
                self.logger.debug(f"Using TLS with context: {ssl_context}")
            
            # Establish connection
            connect_task = asyncio.open_connection(
                host=self.host,
                port=self.port,
                ssl=ssl_context,
                server_hostname=self.host if self.use_tls else None,
                limit=10*1024*1024
            )
            
            self._reader, self._writer = await asyncio.wait_for(
                connect_task,
                timeout=self.connect_timeout
            )
            
            # Check if we have a TLS connection and if HTTP/2 was negotiated
            if self.use_tls:
                ssl_object = self._writer.get_extra_info('ssl_object')
                if ssl_object:
                    protocol = ssl_object.selected_alpn_protocol()
                    self.logger.debug(f"Negotiated ALPN protocol: {protocol}")
                    
                    if protocol != 'h2':
                        if self.force_http2:
                            self.logger.warning(f"Server doesn't advertise HTTP/2 support, but force_http2 is enabled")
                        else:
                            await self.close()
                            raise ConnectionError(f"Server does not support HTTP/2 (negotiated: {protocol})")
            
            # Initialize H2Connection
            config = h2.config.H2Configuration(
                validate_outbound_headers=False,
                validate_inbound_headers=False
            )
            self._h2_conn = h2.connection.H2Connection(config=config)
            
            # Start the connection
            self.logger.debug("Initializing HTTP/2 connection")
            self._h2_conn.initiate_connection()
            data = self._h2_conn.data_to_send()
            
            if self.logger.level <= logging.DEBUG:
                self.logger.debug(f"Sending HTTP/2 preface and SETTINGS ({len(data)} bytes)")
                self.logger.debug(f"Raw data: {data[:50].hex()}" + ("..." if len(data) > 50 else ""))
            
            # Send the HTTP/2 preface and initial settings
            self._writer.write(data)
            await self._writer.drain()
            
            # Wait for the server's settings
            try:
                data = await asyncio.wait_for(
                    self._reader.read(65535),
                    timeout=self.connect_timeout
                )
                self.logger.debug(f"Received {len(data)} bytes from server")
                self.logger.debug(f"Raw data: {data[:50].hex()}" + ("..." if len(data) > 50 else ""))
                
                events = self._h2_conn.receive_data(data)
                self.logger.debug(f"Received {len(events)} events from server")
                
                for event in events:
                    self.logger.debug(f"Received event: {event}")
                
                # Check for SETTINGS frame
                settings_found = any(isinstance(event, h2.events.SettingsAcknowledged) 
                                    or isinstance(event, h2.events.RemoteSettingsChanged) 
                                    for event in events)
                
                if not settings_found:
                    self.logger.warning("No SETTINGS frame received from server")
                
                # Send any necessary responses (like SETTINGS ACK)
                data = self._h2_conn.data_to_send()
                if data:
                    self.logger.debug(f"Sending response ({len(data)} bytes): {data[:50].hex()}" + ("..." if len(data) > 50 else ""))
                    self._writer.write(data)
                    await self._writer.drain()
                    
            except asyncio.TimeoutError:
                self.logger.warning("Timeout waiting for server settings")
                # We'll continue anyway, as some servers might not respond immediately
            
            self.logger.debug("HTTP/2 connection initialized")
            self._connected = True
            self.logger.debug("Connection established successfully")
            return
            
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")
    
    async def close(self) -> None:
        """Close the connection to the target server."""
        if not self._connected or not self._writer:
            return
            
        try:
            self.logger.debug("Closing connection")
            
            # Send GOAWAY frame if HTTP/2 connection is established
            if self._h2_conn:
                self._h2_conn.close_connection()
                self._writer.write(self._h2_conn.data_to_send())
                await self._writer.drain()
            
            self._writer.close()
            await self._writer.wait_closed()
        except Exception as e:
            self.logger.debug(f"Error closing connection: {e}")
        finally:
            self._connected = False
            self._reader = None
            self._writer = None
            self._h2_conn = None
            self._stream_id = None
            self._response_streams.clear()
            self._response_events.clear()
            self._response_data.clear()
            self._response_buffer.clear()
    
    async def send_raw(self, data: bytes) -> None:
        """Send raw bytes over the connection.
        
        Args:
            data: Raw bytes to send
        """
        if not self._connected or not self._writer:
            await self.connect()
            
        try:
            self.logger.debug(f"Sending {len(data)} bytes")
            self._writer.write(data)
            await self._writer.drain()
        except Exception as e:
            self._connected = False
            self.logger.error(f"Error sending data: {e}")
            raise ConnectionError(f"Error sending data: {e}")
    
    async def receive_raw(self, max_size: int = 65536) -> bytes:
        """Receive raw bytes from the connection.
        
        Args:
            max_size: Maximum number of bytes to receive
            
        Returns:
            Raw bytes received
        """
        if not self._connected or not self._reader:
            raise ConnectionError("Not connected")
            
        try:
            self.logger.debug(f"Receiving up to {max_size} bytes")
            data = await asyncio.wait_for(
                self._reader.read(max_size),
                timeout=self.timeout
            )
            self.logger.debug(f"Received {len(data)} bytes")
            return data
        except asyncio.TimeoutError:
            self.logger.error(f"Read timed out after {self.timeout} seconds")
            raise TimeoutError(f"Read timed out after {self.timeout} seconds")
        except Exception as e:
            self._connected = False
            self.logger.error(f"Error receiving data: {e}")
            raise ConnectionError(f"Error receiving data: {e}")

    async def _process_incoming_data(self, stream_id: Optional[int] = None) -> List[h2.events.Event]:
        """Process incoming HTTP/2 frames.
        
        Args:
            stream_id: Optional stream ID to filter events for
            
        Returns:
            List of HTTP/2 events
        """
        if not self._connected or not self._h2_conn:
            raise ConnectionError("Not connected")
        
        events = []
        
        try:
            # Read data with timeout
            if self.logger.level <= logging.DEBUG:
                self.logger.debug(f"Waiting for response on stream {stream_id}...")
            
            data = await asyncio.wait_for(self._reader.read(65535), timeout=self.timeout)
            
            if not data:
                if self.logger.level <= logging.DEBUG:
                    self.logger.debug(f"No data received from server, connection may be closed")
                return events
            
            if self.logger.level <= logging.DEBUG:
                self.logger.debug(f"Received {len(data)} bytes of response data: {data[:50].hex()}" + 
                      ("..." if len(data) > 50 else ""))
            
            # Process the data through h2 connection
            new_events = self._h2_conn.receive_data(data)
            if self.logger.level <= logging.DEBUG:
                self.logger.debug(f"Processed into {len(new_events)} events")
            for event in new_events:
                if self.logger.level <= logging.DEBUG:
                    self.logger.debug(f"Event: {event}")
                
            events.extend(new_events)
            
            # Save events and data for the specific stream if requested
            if stream_id is not None:
                self._response_events.setdefault(stream_id, []).extend(
                    [e for e in new_events if hasattr(e, 'stream_id') and e.stream_id == stream_id]
                )
                
                # Extract data from DATA frames for this stream
                for event in new_events:
                    if (isinstance(event, h2.events.DataReceived) and 
                        event.stream_id == stream_id):
                        self._response_data.setdefault(stream_id, bytearray()).extend(event.data)
                    
                    # Mark if the stream is ended
                    if ((isinstance(event, h2.events.StreamEnded) or 
                         isinstance(event, h2.events.StreamReset)) and 
                        event.stream_id == stream_id):
                        self._response_streams[stream_id] = True
            
            # Handle any necessary responses
            response_data = self._h2_conn.data_to_send()
            if response_data:
                self._writer.write(response_data)
                await self._writer.drain()
            
            # If we're waiting for a specific stream and it hasn't ended yet,
            # try to read more data
            if (stream_id is not None and 
                not self._response_streams.get(stream_id, False) and 
                not any(isinstance(e, h2.events.StreamEnded) for e in events if hasattr(e, 'stream_id') and e.stream_id == stream_id)):
                
                # Recursively call to get more data until stream ends or timeout
                try:
                    more_events = await asyncio.wait_for(
                        self._process_incoming_data(stream_id),
                        timeout=self.timeout
                    )
                    events.extend(more_events)
                except asyncio.TimeoutError:
                    if self.logger.level <= logging.DEBUG:
                        self.logger.debug(f"Timeout waiting for stream {stream_id} to end, proceeding anyway")
                    pass
                    
        except asyncio.TimeoutError:
            if self.logger.level <= logging.DEBUG:
                self.logger.debug(f"Timeout waiting for server response after {self.timeout}s")
        except ConnectionError as e:
            if self.logger.level <= logging.DEBUG:
                self.logger.debug(f"Connection error: {e}")
        except Exception as e:
            if self.logger.level <= logging.DEBUG:
                self.logger.debug(f"Error processing incoming data: {e}")
        
        return events

    async def send_request(
        self, 
        method: str, 
        path: str, 
        headers: List[Tuple[str, str]], 
        body: Optional[bytes] = None,
        raw_request: Optional[bytes] = None,
    ) -> Tuple[Dict[str, Any], bytes]:
        """Send an HTTP/2 request to the target server.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: List of (name, value) header tuples
            body: Request body as bytes
            raw_request: Not used for HTTP/2, included for compatibility
            
        Returns:
            Tuple of (response_info, response_body)
            where response_info is a dict containing status_code, headers, etc.
        """
        if not self._connected:
            await self.connect()
        
        if not self._h2_conn:
            raise ConnectionError("HTTP/2 connection not established")
        
        # Create a new stream
        stream_id = self._h2_conn.get_next_available_stream_id()
        self._stream_id = stream_id
        
        # Clear previous response data for this stream
        self._response_events[stream_id] = []
        self._response_data[stream_id] = bytearray()
        self._response_streams[stream_id] = False
        
        # Prepare headers
        h2_headers = [
            (':method', method),
            (':path', path),
            (':scheme', 'https' if self.use_tls else 'http'),
            (':authority', f"{self.host}:{self.port}"),
        ]
        
        # Add custom headers
        for name, value in headers:
            h2_headers.append((name.lower(), value))
        
        # Log the request with more detail if verbose
        if self.logger.level <= logging.DEBUG:
            self.logger.debug("\n==== HTTP/2 REQUEST FRAMES ====")
            self.logger.debug(f"STREAM ID: {stream_id}")
            self.logger.debug("HEADERS FRAME:")
            for name, value in h2_headers:
                self.logger.debug(f"  {name}: {value}")
            if body:
                self.logger.debug(f"DATA FRAME: {len(body)} bytes")
                self.logger.debug(f"DATA: {body[:100].hex()}" + ("..." if len(body) > 100 else ""))
        
        # When verbose mode is enabled (-v flag), log the complete raw request
        # This is different from DEBUG level logging and is controlled by the verbose flag
        if hasattr(self, 'verbose') and self.verbose:
            self.logger.info(f"\n==== COMPLETE HTTP/2 REQUEST ====")
            self.logger.info(f"Target: {self.host}:{self.port}")
            self.logger.info(f"Stream ID: {stream_id}")
            self.logger.info("Headers:")
            for name, value in h2_headers:
                self.logger.info(f"  {name}: {value}")
            if body:
                self.logger.info(f"Body ({len(body)} bytes):")
                try:
                    body_str = body.decode('utf-8')
                    self.logger.info(f"  {body_str}")
                except UnicodeDecodeError:
                    self.logger.info(f"  [Binary data: {body.hex()}]")
        
        # Record start time for timing measurements
        start_time = time.time()
        
        # Send headers
        self._h2_conn.send_headers(stream_id, h2_headers, end_stream=not body)
        header_data = self._h2_conn.data_to_send()
        
        if self.logger.level <= logging.DEBUG:
            self.logger.debug(f"RAW HEADERS FRAME: {header_data[:50].hex()}" + ("..." if len(header_data) > 50 else ""))
        
        self._writer.write(header_data)
        await self._writer.drain()
        
        # Send body if provided
        if body:
            self._h2_conn.send_data(stream_id, body, end_stream=True)
            body_data = self._h2_conn.data_to_send()
            
            if self.logger.level <= logging.DEBUG:
                self.logger.debug(f"RAW DATA FRAME: {body_data[:50].hex()}" + ("..." if len(body_data) > 50 else ""))
            
            self._writer.write(body_data)
            await self._writer.drain()
        
        # Wait for response with timeout
        response_received = False
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                # Process incoming data
                events = await asyncio.wait_for(
                    self._process_incoming_data(stream_id),
                    timeout=self.timeout / max_attempts
                )
                
                # Check if we received a response
                for event in events:
                    if isinstance(event, h2.events.ResponseReceived) and event.stream_id == stream_id:
                        response_received = True
                        break
                
                if response_received:
                    break
                    
            except asyncio.TimeoutError:
                self.logger.debug(f"Timeout waiting for response (attempt {attempt+1}/{max_attempts})")
                continue
        
        # Try to parse response even if we didn't receive a complete response
        response_info, response_body = self._parse_response(stream_id)
        
        # Record end time
        end_time = time.time()
        response_info['response_time'] = end_time - start_time
        
        # Log the response
        self.logger.debug(f"Received response: {response_info['status_code']} ({response_info['response_time']:.6f}s)")
        for name, value in response_info.get('headers', []):
            self.logger.debug(f"  {name}: {value}")
        if response_body:
            self.logger.debug(f"  Body: {len(response_body)} bytes")
        
        return response_info, response_body
    
    async def send_malformed_headers(
        self,
        method: str,
        path: str,
        headers: List[Tuple[str, str]],
        pseudo_headers: List[Tuple[str, str]] = None,
        body: Optional[bytes] = None,
        end_stream: bool = False,
    ) -> Tuple[Dict[str, Any], bytes]:
        """Send a request with potentially malformed headers.
        
        This method allows sending HTTP/2 requests with duplicate pseudo-headers,
        conflicting content-length values, or other non-RFC-compliant headers.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: List of (name, value) header tuples
            pseudo_headers: Additional pseudo-headers to include (can be duplicates)
            body: Request body as bytes
            end_stream: Whether to end the stream after sending headers/body
            
        Returns:
            Tuple of (response_info, response_body)
        """
        if not self._connected:
            await self.connect()
        
        if not self._h2_conn:
            raise ConnectionError("HTTP/2 connection not established")
        
        # Create a new stream
        stream_id = self._h2_conn.get_next_available_stream_id()
        self._stream_id = stream_id
        
        # Clear previous response data for this stream
        self._response_events[stream_id] = []
        self._response_data[stream_id] = bytearray()
        self._response_streams[stream_id] = False
        
        # Prepare headers
        h2_headers = []
        
        # Add standard pseudo-headers
        h2_headers.append((':method', method))
        h2_headers.append((':path', path))
        h2_headers.append((':scheme', 'https' if self.use_tls else 'http'))
        h2_headers.append((':authority', f"{self.host}:{self.port}"))
        
        # Add custom pseudo-headers if provided (can be duplicates)
        if pseudo_headers:
            h2_headers.extend(pseudo_headers)
        
        # Add custom headers
        for name, value in headers:
            if name.startswith(':'):
                # This is a pseudo-header, check if it already exists
                replaced = False
                for i, (header_name, _) in enumerate(h2_headers):
                    if header_name == name:
                        # Replace the existing pseudo-header
                        h2_headers[i] = (name, value)
                        replaced = True
                        break
                # If not replaced, add it as a new pseudo-header
                if not replaced:
                    h2_headers.append((name, value))
            else:
                # Regular header, just add it
                h2_headers.append((name.lower(), value))
        
        # Log the complete request headers including pseudo-headers
        if self.logger.level <= logging.DEBUG:
            self.logger.debug(f"\n==== COMPLETE HTTP/2 REQUEST HEADERS ====")
            self.logger.debug(f"STREAM ID: {stream_id}")
            for name, value in h2_headers:
                self.logger.debug(f"  {name}: {value}")
            if body:
                self.logger.debug(f"  Body: {len(body)} bytes")
                self.logger.debug(f"  Body content: {body[:100].decode('utf-8', errors='replace')}" + ("..." if len(body) > 100 else ""))
        else:
            # When verbose mode is enabled (-v flag), log the complete raw request
            # This is different from DEBUG level logging and is controlled by the verbose flag
            if hasattr(self, 'verbose') and self.verbose:
                self.logger.info(f"\n==== COMPLETE HTTP/2 REQUEST ====")
                self.logger.info(f"Target: {self.host}:{self.port}")
                self.logger.info(f"Stream ID: {stream_id}")
                self.logger.info("Headers:")
                for name, value in h2_headers:
                    self.logger.info(f"  {name}: {value}")
                if body:
                    self.logger.info(f"Body ({len(body)} bytes):")
                    try:
                        body_str = body.decode('utf-8')
                        self.logger.info(f"  {body_str}")
                    except UnicodeDecodeError:
                        self.logger.info(f"  [Binary data: {body.hex()}]")
        
        # Record start time for timing measurements
        start_time = time.time()
        
        # Send headers
        self._h2_conn.send_headers(stream_id, h2_headers, end_stream=not body and end_stream)
        self._writer.write(self._h2_conn.data_to_send())
        await self._writer.drain()
        
        # Send body if provided
        if body:
            self._h2_conn.send_data(stream_id, body, end_stream=end_stream)
            self._writer.write(self._h2_conn.data_to_send())
            await self._writer.drain()
        
        # Wait for response
        await self._process_incoming_data(stream_id)
        
        # Parse response
        response_info, response_body = self._parse_response(stream_id)
        
        # Record end time
        end_time = time.time()
        response_info['response_time'] = end_time - start_time
        
        # Log the response
        self.logger.debug(f"Received response: {response_info['status_code']} ({response_info['response_time']:.6f}s)")
        for name, value in response_info.get('headers', []):
            self.logger.debug(f"  {name}: {value}")
        self.logger.debug(f"  Body: {len(response_body)} bytes")
        
        return response_info, response_body
    
    async def send_padded_data(
        self,
        method: str,
        path: str,
        headers: List[Tuple[str, str]],
        body: bytes,
        padding_length: int = 8,
        end_stream: bool = True,
    ) -> Tuple[Dict[str, Any], bytes]:
        """Send a request with padded data frames.
        
        This method allows sending an HTTP/2 request with padded data frames,
        which can be useful for detecting certain HTTP/2 vulnerabilities.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: List of (name, value) header tuples
            body: Request body
            padding_length: Length of padding to add to data frames
            end_stream: Whether to end the stream after sending the body
            
        Returns:
            Tuple of (response_info, response_body)
        """
        if not self._connected:
            await self.connect()
        
        if not self._h2_conn:
            raise ConnectionError("HTTP/2 connection not established")
        
        # Create a new stream
        stream_id = self._h2_conn.get_next_available_stream_id()
        self._stream_id = stream_id
        
        # Clear previous response data for this stream
        self._response_events[stream_id] = []
        self._response_data[stream_id] = bytearray()
        self._response_streams[stream_id] = False
        
        # Prepare headers
        h2_headers = [
            (':method', method),
            (':path', path),
            (':scheme', 'https' if self.use_tls else 'http'),
            (':authority', f"{self.host}:{self.port}"),
        ]
        
        # Add custom headers
        for name, value in headers:
            h2_headers.append((name.lower(), value))
        
        # Log the request
        self.logger.debug(f"Sending padded data request to {path} (stream_id={stream_id})")
        self.logger.debug(f"  Body: {len(body)} bytes, Padding: {padding_length} bytes")
        for name, value in h2_headers:
            self.logger.debug(f"  {name}: {value}")
        
        # When verbose mode is enabled (-v flag), log the complete raw request
        # This is different from DEBUG level logging and is controlled by the verbose flag
        if hasattr(self, 'verbose') and self.verbose:
            self.logger.info(f"\n==== COMPLETE HTTP/2 REQUEST WITH PADDING ====")
            self.logger.info(f"Target: {self.host}:{self.port}")
            self.logger.info(f"Stream ID: {stream_id}")
            self.logger.info(f"Padding length: {padding_length} bytes")
            self.logger.info("Headers:")
            for name, value in h2_headers:
                self.logger.info(f"  {name}: {value}")
            self.logger.info(f"Body ({len(body)} bytes):")
            try:
                body_str = body.decode('utf-8')
                self.logger.info(f"  {body_str}")
            except UnicodeDecodeError:
                self.logger.info(f"  [Binary data: {body.hex()}]")
        
        # Record start time for timing measurements
        start_time = time.time()
        
        # Send headers
        self._h2_conn.send_headers(stream_id, h2_headers, end_stream=not body)
        self._writer.write(self._h2_conn.data_to_send())
        await self._writer.drain()
        
        # Send body with padding if provided
        if body:
            # We need to manually create a DATA frame with padding since h2 doesn't expose this directly
            from h2.frame_buffer import FrameBuffer
            from h2.frames import DataFrame
            
            # Create a DATA frame with padding
            frame = DataFrame(stream_id=stream_id, data=body, pad_length=padding_length, flags=['END_STREAM'] if end_stream else [])
            
            # Serialize the frame
            frame_data = frame.serialize()
            
            # Send the raw frame data
            await self.send_raw(frame_data)
        
        # Wait for response
        await self._process_incoming_data(stream_id)
        
        # Parse response
        response_info, response_body = self._parse_response(stream_id)
        
        # Record end time
        end_time = time.time()
        response_info['response_time'] = end_time - start_time
        
        # Log the response
        self.logger.debug(f"Received response: {response_info['status_code']} ({response_info['response_time']:.6f}s)")
        for name, value in response_info.get('headers', []):
            self.logger.debug(f"  {name}: {value}")
        self.logger.debug(f"  Body: {len(response_body)} bytes")
        
        return response_info, response_body

    def _parse_response(self, stream_id: int) -> Tuple[Dict[str, Any], bytes]:
        """Parse an HTTP/2 response.
        
        Args:
            stream_id: Stream ID to parse response for
            
        Returns:
            Tuple of (response_info, response_body)
        """
        response_info = {
            'status_code': None,
            'headers': [],
        }
        
        events = self._response_events.get(stream_id, [])
        
        # Extract headers from HeadersReceived events
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                for name, value in event.headers:
                    # Convert byte strings to regular strings
                    name_str = name.decode('utf-8') if isinstance(name, bytes) else name
                    value_str = value.decode('utf-8') if isinstance(value, bytes) else value
                    
                    if name_str == ':status':
                        response_info['status_code'] = int(value_str)
                    elif not name_str.startswith(':'):
                        response_info['headers'].append((name_str, value_str))
        
        # Get response body
        response_body = bytes(self._response_data.get(stream_id, b''))
        
        return response_info, response_body
