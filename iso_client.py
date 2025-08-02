import socket
import logging
import struct
from pyiso8583 import ISO8583, types

logger = logging.getLogger(__name__)

class IsoClient:
    """
    A client to communicate with an ISO 8583 Card Issuer Server.
    Handles socket connection, sending, and receiving ISO 8583 messages.
    """
    def __init__(self, host, port, timeout=120):
        """
        Initializes the ISO 8583 client.

        Args:
            host (str): The IP address or hostname of the ISO 8583 server.
            port (int): The port number of the ISO 8583 server.
            timeout (int): Socket timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        
        # Define a basic ISO 8583 spec for common fields.
        # IMPORTANT: This is a GENERIC ISO 8583 specification.
        # You MUST customize this spec based on your actual ISO 8583 server's requirements.
        # Field types, lengths, and presence are highly dependent on the specific ISO 8583 implementation.
        self.iso_spec = {
            # MTI (Message Type Indicator)
            0: {'type': types.MTI, 'length': 4},
            # Bitmap
            1: {'type': types.Bitmap},
            # Primary Account Number (PAN)
            2: {'type': types.LLVAR_N, 'max_length': 19},
            # Processing Code
            3: {'type': types.FixedNum, 'length': 6},
            # Amount, Transaction
            4: {'type': types.FixedNum, 'length': 12},
            # Transmission Date & Time
            7: {'type': types.FixedNum, 'length': 10},
            # Systems Trace Audit Number (STAN)
            11: {'type': types.FixedNum, 'length': 6},
            # Local Transaction Time
            12: {'type': types.FixedNum, 'length': 6},
            # Local Transaction Date
            13: {'type': types.FixedNum, 'length': 4},
            # Expiration Date
            14: {'type': types.FixedNum, 'length': 4},
            # POS Entry Mode
            22: {'type': types.FixedNum, 'length': 3},
            # Card Sequence Number
            23: {'type': types.FixedNum, 'length': 3},
            # Network International Identifier (NII)
            24: {'type': types.FixedNum, 'length': 3},
            # Point of Service Condition Code
            25: {'type': types.FixedNum, 'length': 2},
            # Track 2 Data (e.g., for magstripe)
            35: {'type': types.LLVAR_ANS, 'max_length': 37},
            # Retrieval Reference Number (RRN)
            37: {'type': types.FixedAns, 'length': 12},
            # Authorization Identification Response (Auth ID)
            38: {'type': types.FixedAns, 'length': 6},
            # Response Code
            39: {'type': types.FixedAns, 'length': 2},
            # Terminal ID
            41: {'type': types.FixedAns, 'length': 8},
            # Card Acceptor Name/Location
            43: {'type': types.FixedAns, 'length': 40},
            # Additional Data - Private
            48: {'type': types.LLLVAR_ANS, 'max_length': 999},
            # Transaction Currency Code
            49: {'type': types.FixedAns, 'length': 3},
            # Message Security Code (MAC)
            53: {'type': types.FixedNum, 'length': 16},
            # Additional Amounts
            54: {'type': types.LLLVAR_N, 'max_length': 120},
            # ICC Data (EMV)
            55: {'type': types.LLLVAR_B, 'max_length': 255},
            # Original Data Elements
            90: {'type': types.FixedNum, 'length': 42},
            # Message Authentication Code (MAC)
            128: {'type': types.FixedB, 'length': 8}
        }
        self.iso_parser = ISO8583(self.iso_spec)


    def connect(self):
        """Establishes a socket connection to the ISO 8583 server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            logger.info(f"Attempting to connect to ISO server at {self.host}:{self.port}...")
            self.socket.connect((self.host, self.port))
            logger.info("Successfully connected to ISO server.")
            return True
        except socket.timeout:
            logger.error(f"Socket connection to {self.host}:{self.port} timed out after {self.timeout} seconds.")
            self.close()
            return False
        except socket.error as e:
            logger.error(f"Socket error connecting to {self.host}:{self.port}: {e}")
            self.close()
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during ISO client connection: {e}")
            self.close()
            return False

    def close(self):
        """Closes the socket connection if it's open."""
        if self.socket:
            logger.info("Closing ISO socket connection.")
            self.socket.close()
            self.socket = None

    def send_iso_message(self, iso_data):
        """
        Sends an ISO 8583 message to the server and waits for a response.

        Args:
            iso_data (dict): A dictionary representing the ISO 8583 fields.

        Returns:
            dict or None: Parsed ISO 8583 response message, or None if an error occurs.
        """
        if not self.socket:
            logger.error("ISO socket not connected. Attempting to reconnect...")
            if not self.connect():
                return None

        try:
            # Pack the ISO 8583 message
            packed_message = self.iso_parser.pack(iso_data)
            
            # ISO 8583 messages often have a 2-byte length header (MLI - Message Length Indicator)
            # This is typically big-endian (network byte order).
            mli = struct.pack('>H', len(packed_message)) # '>H' means unsigned short, big-endian
            
            full_message = mli + packed_message
            
            logger.info(f"Sending ISO message (length: {len(packed_message)} bytes)...")
            self.socket.sendall(full_message)

            # Receive response
            # First, receive the 2-byte MLI
            mli_header = self.socket.recv(2)
            if not mli_header:
                logger.error("No MLI header received from ISO server.")
                return None
            
            response_length = struct.unpack('>H', mli_header)[0]
            logger.info(f"Receiving ISO response (expected length: {response_length} bytes)...")

            # Receive the rest of the message based on the length
            response_data = b''
            bytes_recd = 0
            while bytes_recd < response_length:
                chunk = self.socket.recv(min(response_length - bytes_recd, 4096)) # Receive in chunks
                if not chunk:
                    logger.error("Incomplete ISO response received from server.")
                    break
                response_data += chunk
                bytes_recd += len(chunk)

            if bytes_recd < response_length:
                logger.error(f"Received only {bytes_recd} of {response_length} bytes for ISO response.")
                return None

            # Unpack the ISO 8583 response message
            unpacked_response = self.iso_parser.unpack(response_data)
            logger.info("ISO response successfully received and unpacked.")
            return unpacked_response

        except socket.timeout:
            logger.error("Socket communication timed out during send/receive.")
            self.close() # Close connection on timeout
            return None
        except socket.error as e:
            logger.error(f"Socket error during ISO communication: {e}")
            self.close() # Close connection on error
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred during ISO message processing: {e}")
            self.close() # Close connection on error
            return None
