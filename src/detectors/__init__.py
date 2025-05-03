"""Detectors for HTTP Request Smuggling vulnerabilities.

This package contains detector modules for various HTTP Request Smuggling vulnerability types:
- CL.TE: Content-Length / Transfer-Encoding desync
- TE.CL: Transfer-Encoding / Content-Length desync

Each detector implements a time-based detection technique that identifies potential
vulnerabilities without affecting other users or causing side effects.
"""

__all__ = ['cl_te_detector', 'te_cl_detector']
