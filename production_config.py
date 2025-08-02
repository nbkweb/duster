import os
import logging

logger = logging.getLogger(__name__)

def get_production_config():
    """
    Retrieves production configuration settings from environment variables.
    These should be set securely in your deployment environment.
    """
    config = {
        # Default wallet addresses for payouts (these are placeholders, replace with real ones)
        'DEFAULT_ERC20_WALLET': os.environ.get('DEFAULT_ERC20_WALLET', '0xf2716f15fea5133a38b3f2f602db37c683fe2e3e'),
        'DEFAULT_TRC20_WALLET': os.environ.get('DEFAULT_TRC20_WALLET', 'TEti1NerM8dg14cGpxa1eCzYzShPVFTBfs'),

        # Blockchain API Keys
        'INFURA_PROJECT_ID': os.environ.get('INFURA_PROJECT_ID', 'YOUR_INFURA_PROJECT_ID_HERE'),
        'TRONGRID_API_KEY': os.environ.get('TRONGRID_API_KEY', 'YOUR_TRONGRID_API_KEY_HERE'),

        # Sender Wallet Private Keys (HIGHLY SENSITIVE - NEVER HARDCODE IN PRODUCTION!)
        'SENDER_ERC20_PRIVATE_KEY': os.environ.get('SENDER_ERC20_PRIVATE_KEY', '0x1111111111111111111111111111111111111111111111111111111111111111'), # Placeholder
        'SENDER_TRC20_PRIVATE_KEY': os.environ.get('SENDER_TRC20_PRIVATE_KEY', '1111111111111111111111111111111111111111111111111111111111111111'), # Placeholder

        # ISO 8583 Server Details
        'ISO_SERVER_HOST': os.environ.get('ISO_SERVER_HOST', '66.185.176.0'),
        'ISO_SERVER_PORT': int(os.environ.get('ISO_SERVER_PORT', 20)),
        'ISO_TIMEOUT': int(os.environ.get('ISO_TIMEOUT', 120)),

        # Daily transaction limit for the terminal
        'DAILY_LIMIT_PER_TERMINAL': int(os.environ.get('DAILY_LIMIT_PER_TERMINAL', 10000000)), # Default 10M EUR/USD

        # Exchange rates for calculating gas/energy fees in USDT (IMPORTANT: Use real-time oracles in production!)
        'ETH_TO_USDT_RATE': float(os.environ.get('ETH_TO_USDT_RATE', 2000.0)), # Example: 1 ETH = 2000 USDT
        'TRX_TO_USDT_RATE': float(os.environ.get('TRX_TO_USDT_RATE', 0.1)),    # Example: 1 TRX = 0.1 USDT
    }

    # Log warnings if critical production keys are still placeholders
    if config['INFURA_PROJECT_ID'] == '6aaea4c2d2be42bf89c660d07863fea5':
        logger.warning("INFURA_PROJECT_ID is a placeholder. Replace with your actual Infura Project ID.")
    if config['TRONGRID_API_KEY'] == 'YOUR_TRONGRID_API_KEY_HERE':
        logger.warning("TRONGRID_API_KEY is a placeholder. Replace with your actual Trongrid API Key.")
    if config['SENDER_ERC20_PRIVATE_KEY'] == '6b3a7d490a4cf46d8219c155316a947823e9fe7fa43eb42342a83fd7fb3cba9b':
        logger.error("SENDER_ERC20_PRIVATE_KEY is a placeholder. THIS IS HIGHLY SENSITIVE. SET SECURELY IN PRODUCTION!")
    if config['SENDER_TRC20_PRIVATE_KEY'] == '3559ac98cc826107055a7937587a28d9889a6f3c40d8524a89f07e49ecbb7bbd':
        logger.error("SENDER_TRC20_PRIVATE_KEY is a placeholder. THIS IS HIGHLY SENSITIVE. SET SECURELY IN PRODUCTION!")

    return config

def validate_production_config(config):
    """
    Performs basic validation on the loaded production configuration.
    """
    errors = []
    if not config['INFURA_PROJECT_ID'] or config['INFURA_PROJECT_ID'] == '6aaea4c2d2be42bf89c660d07863fea5':
        errors.append("Infura Project ID is missing or is a placeholder.")
    if not config['SENDER_ERC20_PRIVATE_KEY'] or not config['SENDER_ERC20_PRIVATE_KEY'].startswith('0x') or len(config['SENDER_ERC20_PRIVATE_KEY']) != 66:
        errors.append("Invalid or missing SENDER_ERC20_PRIVATE_KEY.")
    if not config['SENDER_TRC20_PRIVATE_KEY'] or len(config['SENDER_TRC20_PRIVATE_KEY']) != 64:
        errors.append("Invalid or missing SENDER_TRC20_PRIVATE_KEY.")
    if not isinstance(config['ETH_TO_USDT_RATE'], (int, float)) or config['ETH_TO_USDT_RATE'] <= 0:
        errors.append("Invalid ETH_TO_USDT_RATE. Must be a positive number.")
    if not isinstance(config['TRX_TO_USDT_RATE'], (int, float)) or config['TRX_TO_USDT_RATE'] <= 0:
        errors.append("Invalid TRX_TO_USDT_RATE. Must be a positive number.")

    if errors:
        for error in errors:
            logger.error(f"Production Config Error: {error}")
        return False
    return True

def get_wallet_config(network_type):
    config = get_production_config()
    if network_type.upper() == 'ERC20':
        return {'address': config['DEFAULT_ERC20_WALLET']}
    elif network_type.upper() == 'TRC20':
        return {'address': config['DEFAULT_TRC20_WALLET']}
    return {'address': ''}
