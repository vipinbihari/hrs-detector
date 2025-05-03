"""
Custom HTTP/1.1 Client implementation.

This module provides a low-level HTTP/1.1 client that allows for complete control
over request construction, including non-RFC-compliant requests needed for
HTTP request smuggling detection.
"""

import asyncio
import logging
import re
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from src.clients.base import BaseClient
from src.utils import tls
from src.utils.logging import get_logger


class HTTP1Client(BaseClient):
    """Custom HTTP/1.1 client for sending non-RFC-compliant requests.
    
    Features:
    - Raw TCP & TLS sockets using asyncio streams
    - Manual construction of request lines, headers, and bodies
    - Support for header duplication, custom casing, and whitespace
    - Keep-alive and pipelining capabilities
    - Timing measurement for differential timing attacks
    """
    
    def __init__(
        self,
        host: str,
        port: int,
        use_tls: bool = True,
        timeout: float = 15.0,
        connect_timeout: float = 5.0,
        keep_alive: bool = False,
        verify_ssl: bool = False,
    ) -> None:
        """Initialize a new HTTP/1.1 client.
        
        Args:
            host: Target hostname or IP address
            port: Target port
            use_tls: Whether to use TLS (HTTPS)
            timeout: Read timeout in seconds
            connect_timeout: Connection timeout in seconds
            keep_alive: Whether to keep the connection alive after a request
            verify_ssl: Whether to verify SSL certificates
        """
        super().__init__(host, port, use_tls, timeout, connect_timeout)
        self.keep_alive = keep_alive
        self.verify_ssl = verify_ssl
        self._response_buffer = bytearray()
        self.logger = get_logger()
        
        # Initialize SSL context if needed
        if self.use_tls:
            self.ssl_context = tls.get_http1_ssl_context(verify=verify_ssl)
    
    async def connect(self) -> None:
        """Establish a connection to the target server."""
        if self._connected:
            return
            
        try:
            self.logger.debug(f"Connecting to {self.host}:{self.port} ({'HTTPS' if self.use_tls else 'HTTP'})")
            connect_task = asyncio.open_connection(
                self.host,
                self.port,
                ssl=self.ssl_context if self.use_tls else None
            )
            self._reader, self._writer = await asyncio.wait_for(
                connect_task, 
                timeout=self.connect_timeout
            )
            self._connected = True
            self.logger.debug("Connection established")
            
            # Log negotiated protocol if using TLS
            if self.use_tls and self._writer.get_extra_info('ssl_object'):
                ssl_object = self._writer.get_extra_info('ssl_object')
                protocol = tls.get_negotiated_protocol(ssl_object)
                if protocol:
                    self.logger.debug(f"Negotiated protocol: {protocol}")
                    
        except asyncio.TimeoutError:
            self.logger.error(f"Connection to {self.host}:{self.port} timed out")
            raise ConnectionError(f"Connection to {self.host}:{self.port} timed out")
        except Exception as e:
            self.logger.error(f"Failed to connect to {self.host}:{self.port}: {e}")
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")
    
    async def close(self) -> None:
        """Close the connection to the target server."""
        if not self._connected or not self._writer:
            return
            
        try:
            self.logger.debug("Closing connection")
            self._writer.close()
            await self._writer.wait_closed()
        except Exception as e:
            self.logger.debug(f"Error closing connection: {e}")
        finally:
            self._connected = False
            self._reader = None
            self._writer = None
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
    
    def _build_request(
        self,
        method: str,
        path: str,
        headers: List[Tuple[str, str]],
        body: Optional[bytes] = None,
    ) -> bytes:
        """Build a raw HTTP/1.1 request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: List of (name, value) header tuples
            body: Request body as bytes
            
        Returns:
            Raw HTTP/1.1 request as bytes
        """
        # Start with request line
        request_parts = [f"{method} {path} HTTP/1.1\r\n"]
        
        # Add headers exactly as provided (preserving case, order, duplicates)
        for name, value in headers:
            request_parts.append(f"{name}: {value}\r\n")
        
        # End headers
        request_parts.append("\r\n")
        
        # Convert to bytes
        request_bytes = "".join(request_parts).encode("utf-8", errors="surrogateescape")
        
        # Add body if provided
        if body:
            request_bytes += body
            
        return request_bytes
    
    async def send_request(
        self,
        method: str,
        path: str,
        headers: List[Tuple[str, str]],
        body: Optional[bytes] = None,
        raw_request: Optional[bytes] = None,
    ) -> Tuple[Dict[str, Any], bytes]:
        """Send an HTTP request to the target server.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: List of (name, value) header tuples
            body: Request body as bytes
            raw_request: Raw request bytes to send (overrides other parameters if provided)
            
        Returns:
            Tuple of (response_info, response_body)
            where response_info is a dict containing status_code, headers, etc.
            
        Raises:
            ConnectionError: If the connection fails
            TimeoutError: If the request times out
        """
        if not self._connected:
            await self.connect()
            
        # Use raw_request if provided, otherwise build the request
        request_data = raw_request if raw_request else self._build_request(method, path, headers, body)
        
        # Log the request
        if raw_request:
            self.logger.debug(f"Sending raw request ({len(raw_request)} bytes)")
            if self.logger.level <= logging.DEBUG:
                try:
                    self.logger.debug(raw_request[:1024].decode('utf-8', errors='replace'))
                    if len(raw_request) > 1024:
                        self.logger.debug("... (truncated)")
                except Exception:
                    self.logger.debug(f"<Binary data: {len(raw_request)} bytes>")
        else:
            self.logger.debug(f"Sending {method} request to {path}")
            for name, value in headers:
                self.logger.debug(f"  {name}: {value}")
            if body:
                self.logger.debug(f"  Body: {len(body)} bytes")
        
        # Record start time for timing measurements
        start_time = time.time()
        
        # Send the request
        await self.send_raw(request_data)
        
        try:
            # Parse the response
            response_info, response_body = await self._parse_response()
            
            # Record end time
            end_time = time.time()
            response_info['response_time'] = end_time - start_time
            
            # Log the response
            self.logger.debug(f"Received response: {response_info['status_code']} ({response_info['response_time']:.6f}s)")
            for name, value in response_info.get('headers', []):
                self.logger.debug(f"  {name}: {value}")
            self.logger.debug(f"  Body: {len(response_body)} bytes")
            
            # Close connection if not keep-alive
            if not self.keep_alive:
                await self.close()
                
            return response_info, response_body
        except asyncio.TimeoutError:
            # Make sure to propagate the timeout error so the caller can detect it
            self.logger.debug(f"Request timed out after {self.timeout} seconds")
            if not self.keep_alive:
                await self.close()
            raise TimeoutError(f"Request timed out after {self.timeout} seconds")
    
    async def _parse_response(self) -> Tuple[Dict[str, Any], bytes]:
        """Parse an HTTP/1.1 response.
        
        Returns:
            Tuple of (response_info, response_body)
        """
        if not self._connected or not self._reader:
            raise ConnectionError("Not connected")
            
        # Read the response headers
        header_data = await self._read_headers()
        
        # Parse status line
        status_match = re.match(rb'HTTP/1\.[01] (\d+) (.*?)\r\n', header_data)
        if not status_match:
            raise ValueError("Invalid HTTP response")
            
        status_code = int(status_match.group(1))
        status_message = status_match.group(2).decode('utf-8', errors='replace')
        
        # Parse headers
        header_lines = header_data[status_match.end():].split(b'\r\n')
        headers = []
        for line in header_lines:
            if not line:
                continue
            try:
                name, value = line.split(b':', 1)
                headers.append((
                    name.decode('utf-8', errors='replace').strip(),
                    value.decode('utf-8', errors='replace').strip()
                ))
            except ValueError:
                # Skip invalid headers
                continue
        
        # Determine body length
        content_length = None
        transfer_encoding = None
        chunked = False
        
        for name, value in headers:
            if name.lower() == 'content-length':
                try:
                    content_length = int(value)
                except ValueError:
                    pass
            elif name.lower() == 'transfer-encoding' and 'chunked' in value.lower():
                transfer_encoding = value
                chunked = True
        
        # Read the body based on headers
        if chunked:
            body = await self._read_chunked_body()
        elif content_length is not None:
            body = await self._read_content_length_body(content_length)
        else:
            # No content-length or transfer-encoding, try to read until connection closes
            body = await self._read_until_close()
        
        response_info = {
            'status_code': status_code,
            'status_message': status_message,
            'headers': headers,
            'chunked': chunked,
            'content_length': content_length,
        }
        
        return response_info, body
    
    async def _read_headers(self) -> bytes:
        """Read HTTP headers from the connection.
        
        Returns:
            Raw header data as bytes
        """
        if not self._connected or not self._reader:
            raise ConnectionError("Not connected")
            
        header_data = bytearray()
        
        # Read until we find the end of headers marker (\r\n\r\n)
        while True:
            try:
                chunk = await asyncio.wait_for(
                    self._reader.readuntil(b'\r\n\r\n'),
                    timeout=self.timeout
                )
                header_data.extend(chunk)
                break
            except asyncio.IncompleteReadError as e:
                if e.partial:
                    header_data.extend(e.partial)
                if b'\r\n\r\n' in header_data:
                    break
                if not e.partial:  # Connection closed
                    break
            except asyncio.LimitOverrunError as e:
                # Read the available data and continue
                chunk = await self._reader.readexactly(e.consumed)
                header_data.extend(chunk)
                if b'\r\n\r\n' in header_data:
                    break
            except asyncio.TimeoutError:
                raise TimeoutError(f"Read timed out after {self.timeout} seconds")
        
        # Return everything up to the end of headers
        end_idx = header_data.find(b'\r\n\r\n')
        if end_idx != -1:
            return bytes(header_data[:end_idx + 4])  # Include the \r\n\r\n
        return bytes(header_data)
    
    async def _read_content_length_body(self, content_length: int) -> bytes:
        """Read a body with a known Content-Length.
        
        Args:
            content_length: Length of the body in bytes
            
        Returns:
            Body data as bytes
        """
        if not self._connected or not self._reader:
            raise ConnectionError("Not connected")
            
        if content_length == 0:
            return b''
            
        try:
            body = await asyncio.wait_for(
                self._reader.readexactly(content_length),
                timeout=self.timeout
            )
            return body
        except asyncio.IncompleteReadError as e:
            # Return partial data if the connection closed prematurely
            return e.partial
        except asyncio.TimeoutError:
            raise TimeoutError(f"Read timed out after {self.timeout} seconds")
    
    async def _read_chunked_body(self) -> bytes:
        """Read a chunked-encoded body.
        
        Returns:
            Decoded body data as bytes
        """
        if not self._connected or not self._reader:
            raise ConnectionError("Not connected")
            
        body = bytearray()
        
        while True:
            # Read the chunk size line
            try:
                chunk_size_line = await asyncio.wait_for(
                    self._reader.readuntil(b'\r\n'),
                    timeout=self.timeout
                )
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                # Incomplete chunk size, return what we have
                break
                
            # Parse the chunk size
            chunk_size_hex = chunk_size_line.split(b';')[0].strip()
            try:
                chunk_size = int(chunk_size_hex, 16)
            except ValueError:
                # Invalid chunk size, stop reading
                break
                
            # Zero-sized chunk means end of body
            if chunk_size == 0:
                # Read the final CRLF
                try:
                    await asyncio.wait_for(
                        self._reader.readexactly(2),
                        timeout=self.timeout
                    )
                except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                    pass
                break
                
            # Read the chunk data
            try:
                chunk_data = await asyncio.wait_for(
                    self._reader.readexactly(chunk_size),
                    timeout=self.timeout
                )
                body.extend(chunk_data)
                
                # Read the CRLF after the chunk
                await asyncio.wait_for(
                    self._reader.readexactly(2),
                    timeout=self.timeout
                )
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                # Incomplete chunk, return what we have
                break
        
        return bytes(body)
    
    async def _read_until_close(self) -> bytes:
        """Read body data until the connection closes.
        
        Returns:
            Body data as bytes
        """
        if not self._connected or not self._reader:
            raise ConnectionError("Not connected")
            
        body = bytearray()
        
        try:
            while True:
                chunk = await asyncio.wait_for(
                    self._reader.read(8192),
                    timeout=self.timeout
                )
                if not chunk:  # Connection closed
                    break
                body.extend(chunk)
        except (asyncio.TimeoutError, ConnectionError):
            # Return what we have so far
            pass
            
        return bytes(body)
    
    async def pipeline_requests(
        self,
        requests: List[Tuple[str, str, List[Tuple[str, str]], Optional[bytes]]],
    ) -> List[Tuple[Dict[str, Any], bytes]]:
        """Send multiple requests in a pipeline.
        
        Args:
            requests: List of (method, path, headers, body) tuples
            
        Returns:
            List of (response_info, response_body) tuples
        """
        if not self._connected:
            await self.connect()
            
        self.logger.debug(f"Sending {len(requests)} pipelined requests")
            
        # Build and send all requests at once
        for method, path, headers, body in requests:
            request_data = self._build_request(method, path, headers, body)
            await self.send_raw(request_data)
            
        # Read all responses
        responses = []
        for i, (method, path, _, _) in enumerate(requests):
            try:
                self.logger.debug(f"Reading response {i+1}/{len(requests)} for {method} {path}")
                response_info, response_body = await self._parse_response()
                responses.append((response_info, response_body))
            except Exception as e:
                # If we can't parse a response, add an error response
                self.logger.error(f"Error parsing response {i+1}: {e}")
                responses.append(({'error': str(e)}, b''))
                # Stop reading responses
                break
                
        # Close connection if not keep-alive
        if not self.keep_alive:
            await self.close()
            
        return responses
