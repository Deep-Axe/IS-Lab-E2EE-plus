# Double Ratchet Enhanced Implementation
"""
Enhanced Double Ratchet Protocol Implementation for Educational Purposes

This package provides a comprehensive educational implementation of the Double Ratchet
algorithm with production-like features including:
- Persistent state management
- Enhanced message format with replay protection
- X3DH key agreement integration
- Comprehensive error handling
- Advanced cryptanalysis tools

Educational Use Only - Not for production deployment.
"""

__version__ = "1.0.0"
__author__ = "Double Ratchet Educational Team"

from .core.double_ratchet import DoubleRatchetSession
from .security.x3dh_integration import X3DHSession
from .utils.message_handler import MessageHandler
from .utils.state_manager import StateManager
from .utils.error_handler import ErrorHandler

__all__ = [
    'DoubleRatchetSession',
    'X3DHSession', 
    'MessageHandler',
    'StateManager',
    'ErrorHandler'
]