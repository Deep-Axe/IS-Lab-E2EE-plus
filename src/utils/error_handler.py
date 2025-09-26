# error_handler.py - Comprehensive Error Handling and Recovery
import logging
import traceback
from enum import Enum
from typing import Optional, Dict, Any, Union
import time

class ErrorCode(Enum):
    # Cryptographic errors
    ENCRYPTION_FAILED = "ENC_001"
    DECRYPTION_FAILED = "DEC_001"
    MAC_VERIFICATION_FAILED = "MAC_001"
    KEY_GENERATION_FAILED = "KEY_001"
    DH_EXCHANGE_FAILED = "DHE_001"
    
    # Message errors
    MESSAGE_FORMAT_INVALID = "MSG_001"
    MESSAGE_REPLAY_DETECTED = "MSG_002"
    MESSAGE_TOO_OLD = "MSG_003"
    MESSAGE_SEQUENCE_ERROR = "MSG_004"
    
    # State errors
    STATE_CORRUPTION = "STA_001"
    STATE_SERIALIZATION_FAILED = "STA_002"
    STATE_DESERIALIZATION_FAILED = "STA_003"
    
    # Network errors
    CONNECTION_FAILED = "NET_001"
    TRANSMISSION_FAILED = "NET_002"
    TIMEOUT = "NET_003"
    
    # Key management errors
    KEY_NOT_FOUND = "KMG_001"
    KEY_EXPIRED = "KMG_002"
    BACKUP_FAILED = "KMG_003"
    RESTORE_FAILED = "KMG_004"
    
    # General errors
    INVALID_PARAMETER = "GEN_001"
    OPERATION_NOT_SUPPORTED = "GEN_002"
    INTERNAL_ERROR = "GEN_003"

class DoubleRatchetError(Exception):
    """Base exception for Double Ratchet operations"""
    def __init__(self, error_code: ErrorCode, message: str, details: Optional[Dict[str, Any]] = None):
        self.error_code = error_code
        self.message = message
        self.details = details or {}
        super().__init__(f"{error_code.value}: {message}")

class CryptographicError(DoubleRatchetError):
    """Errors related to cryptographic operations"""
    pass

class MessageError(DoubleRatchetError):
    """Errors related to message handling"""
    pass

class StateError(DoubleRatchetError):
    """Errors related to state management"""
    pass

class NetworkError(DoubleRatchetError):
    """Errors related to network operations"""
    pass

class ErrorHandler:
    """Centralized error handling and recovery system"""
    
    def __init__(self, enable_logging=True):
        self.enable_logging = enable_logging
        self.error_stats = {}
        
        if enable_logging:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            self.logger = logging.getLogger('DoubleRatchet')
    
    def handle_error(self, error: Exception, context: str = "", 
                    recovery_action: Optional[str] = None) -> Dict[str, Any]:
        """
        Handle and log errors, return error information
        """
        error_info = {
            'timestamp': str(logging.Formatter().formatTime(logging.LogRecord(
                name='', level=0, pathname='', lineno=0,
                msg='', args=(), exc_info=None), '%Y-%m-%d %H:%M:%S')),
            'context': context,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'recovery_action': recovery_action,
            'traceback': traceback.format_exc() if self.enable_logging else None
        }
        
        # Add specific error code if it's a DoubleRatchetError
        if isinstance(error, DoubleRatchetError):
            error_info['error_code'] = error.error_code.value
            error_info['details'] = error.details
        
        # Update error statistics
        error_type = type(error).__name__
        if error_type not in self.error_stats:
            self.error_stats[error_type] = 0
        self.error_stats[error_type] += 1
        
        # Log the error
        if self.enable_logging:
            log_message = f"Error in {context}: {error_info['error_message']}"
            if recovery_action:
                log_message += f" | Recovery: {recovery_action}"
            self.logger.error(log_message)
            
            if isinstance(error, DoubleRatchetError):
                self.logger.error(f"Error details: {error.details}")
        
        return error_info
    
    def safe_execute(self, operation, *args, **kwargs):
        """
        Safely execute an operation with error handling
        Returns (success: bool, result: Any, error_info: Dict)
        """
        try:
            result = operation(*args, **kwargs)
            return True, result, None
        except Exception as e:
            error_info = self.handle_error(e, context=operation.__name__)
            return False, None, error_info
    
    def retry_operation(self, operation, max_retries=3, delay=1, *args, **kwargs):
        """
        Retry an operation with exponential backoff
        """
        import time
        
        for attempt in range(max_retries):
            try:
                result = operation(*args, **kwargs)
                if attempt > 0:
                    if self.enable_logging:
                        self.logger.info(f"Operation {operation.__name__} succeeded on attempt {attempt + 1}")
                return True, result, None
            
            except Exception as e:
                if attempt == max_retries - 1:  # Last attempt
                    error_info = self.handle_error(
                        e, 
                        context=f"{operation.__name__} (final attempt {attempt + 1}/{max_retries})",
                        recovery_action="All retry attempts exhausted"
                    )
                    return False, None, error_info
                else:
                    if self.enable_logging:
                        self.logger.warning(f"Attempt {attempt + 1}/{max_retries} failed for {operation.__name__}: {e}")
                    
                    # Exponential backoff
                    time.sleep(delay * (2 ** attempt))
        
        return False, None, {"error": "Unexpected end of retry loop"}
    
    def validate_parameter(self, param_name: str, param_value: Any, 
                          expected_type: Optional[type] = None, 
                          allowed_values: Optional[list] = None,
                          min_length: Optional[int] = None,
                          max_length: Optional[int] = None) -> None:
        """
        Validate parameters and raise DoubleRatchetError if invalid
        """
        if param_value is None:
            raise DoubleRatchetError(
                ErrorCode.INVALID_PARAMETER,
                f"Parameter {param_name} cannot be None"
            )
        
        if expected_type and not isinstance(param_value, expected_type):
            raise DoubleRatchetError(
                ErrorCode.INVALID_PARAMETER,
                f"Parameter {param_name} must be of type {expected_type.__name__}, got {type(param_value).__name__}"
            )
        
        if allowed_values and param_value not in allowed_values:
            raise DoubleRatchetError(
                ErrorCode.INVALID_PARAMETER,
                f"Parameter {param_name} must be one of {allowed_values}, got {param_value}"
            )
        
        if min_length and hasattr(param_value, '__len__') and len(param_value) < min_length:
            raise DoubleRatchetError(
                ErrorCode.INVALID_PARAMETER,
                f"Parameter {param_name} must have minimum length {min_length}, got {len(param_value)}"
            )
        
        if max_length and hasattr(param_value, '__len__') and len(param_value) > max_length:
            raise DoubleRatchetError(
                ErrorCode.INVALID_PARAMETER,
                f"Parameter {param_name} must have maximum length {max_length}, got {len(param_value)}"
            )
    
    def create_recovery_suggestion(self, error: Exception) -> str:
        """
        Provide recovery suggestions based on error type
        """
        if isinstance(error, CryptographicError):
            if error.error_code == ErrorCode.DECRYPTION_FAILED:
                return "Verify message integrity and consider requesting key re-exchange"
            elif error.error_code == ErrorCode.MAC_VERIFICATION_FAILED:
                return "Message may have been tampered with. Discard and request resend"
            elif error.error_code == ErrorCode.DH_EXCHANGE_FAILED:
                return "Restart key exchange process with fresh keys"
        
        elif isinstance(error, MessageError):
            if error.error_code == ErrorCode.MESSAGE_REPLAY_DETECTED:
                return "Ignore duplicate message and continue"
            elif error.error_code == ErrorCode.MESSAGE_TOO_OLD:
                return "Request fresh message or synchronize clocks"
        
        elif isinstance(error, StateError):
            if error.error_code == ErrorCode.STATE_CORRUPTION:
                return "Restore from backup or reinitialize session"
        
        elif isinstance(error, NetworkError):
            if error.error_code == ErrorCode.CONNECTION_FAILED:
                return "Check network connectivity and retry"
            elif error.error_code == ErrorCode.TIMEOUT:
                return "Increase timeout value or check server status"
        
        return "Consider restarting the session or contacting support"
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """
        Get error statistics for monitoring and debugging
        """
        total_errors = sum(self.error_stats.values())
        return {
            'total_errors': total_errors,
            'error_counts': self.error_stats.copy(),
            'error_rates': {
                error_type: count / total_errors * 100 
                for error_type, count in self.error_stats.items()
            } if total_errors > 0 else {}
        }
    
    def reset_statistics(self):
        """Reset error statistics"""
        self.error_stats.clear()

# Convenience functions for common error scenarios
def create_crypto_error(error_code: ErrorCode, message: str, details: Optional[Dict] = None) -> CryptographicError:
    return CryptographicError(error_code, message, details)

def create_message_error(error_code: ErrorCode, message: str, details: Optional[Dict] = None) -> MessageError:
    return MessageError(error_code, message, details)

def create_state_error(error_code: ErrorCode, message: str, details: Optional[Dict] = None) -> StateError:
    return StateError(error_code, message, details)

def create_network_error(error_code: ErrorCode, message: str, details: Optional[Dict] = None) -> NetworkError:
    return NetworkError(error_code, message, details)