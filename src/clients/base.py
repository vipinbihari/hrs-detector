"""
Base client interface for HTTP clients.

This module defines the abstract base class that all HTTP clients must implement.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Union
import asyncio
import ssl


class BaseClient(ABC):
    """Abstract base class for HTTP clients.
    
    Defines the interface that both HTTP/1.1 and HTTP/2 clients must implement.
    """
    
    def __init__(
        self, 
        host: str, 
        port: int, 
        use_tls: bool = True,
        timeout: float = 15.0,
        connect_timeout: float = 5.0,
    ) -> None:
        """Initialize a new HTTP client.
        
        Args:
            host: Target hostname or IP address
            port: Target port
            use_tls: Whether to use TLS (HTTPS)
            timeout: Read timeout in seconds
            connect_timeout: Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.ssl_context: Optional[ssl.SSLContext] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected = False
        
    @abstractmethod
    async def connect(self) -> None:
        """Establish a connection to the target server."""
        pass
        
    @abstractmethod
    async def close(self) -> None:
        """Close the connection to the target server."""
        pass
        
    @abstractmethod
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
        """
        pass
    
    @property
    def is_connected(self) -> bool:
        """Return whether the client is currently connected."""
        return self._connected
    
    @abstractmethod
    async def send_raw(self, data: bytes) -> None:
        """Send raw bytes over the connection.
        
        Args:
            data: Raw bytes to send
        """
        pass
    
    @abstractmethod
    async def receive_raw(self, max_size: int = 65536) -> bytes:
        """Receive raw bytes from the connection.
        
        Args:
            max_size: Maximum number of bytes to receive
            
        Returns:
            Raw bytes received
        """
        pass
