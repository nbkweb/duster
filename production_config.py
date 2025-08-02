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
        'INFURA_PROJECT_ID': os.environ.get('INFURA_PROJECT_ID', '6aaea4c2d2be42bf89c660d07863fea5'),
        'TRONGRID_API_KEY': os.environ.get('TRONGRID_API_KEY', '90556144-eb12-4d28-be5f-24368bb813ff'),

        # Sender Wallet Private Keys (HIGHLY SENSITIVE - NEVER HARDCODE IN PRODUCTION!)
        # These values MUST be set as environment variables in your deployment.
        # SENDER_ERC20_PRIVATE_KEY is the preferred and canonical key name.
        # It will fall back to ERC20_PRIVATE_KEY if SENDER_ERC20_PRIVATE_KEY is not set in env.
        'SENDER_ERC20_PRIVATE_KEY': os.environ.get('SENDER_ERC20_PRIVATE_KEY', os.environ.get('ERC20_PRIVATE_KEY', '6b3a7d490a4cf46d8219c155316a947823e9fe7fa43eb42342a83fd7fb3cba9b')), # Placeholder
        # SENDER_TRC20_PRIVATE_KEY will fall back to TRC20_PRIVATE_KEY if not set.
        'SENDER_TRC20_PRIVATE_KEY': os.environ.get('SENDER_TRC20_PRIVATE_KEY', os.environ.get('TRC20_PRIVATE_KEY', '3559ac98cc826107055a7937587a28d9889a6f3c40d8524a89f07e49ecbb7bbd')), # Placeholder

        # ISO 8583 Server Details - Aligned with EXTERNAL_ISO_HOST/PORT
        'ISO_SERVER_HOST': os.environ.get('EXTERNAL_ISO_HOST', '66.185.176.0'),
        'ISO_SERVER_PORT': int(os.environ.get('EXTERNAL_ISO_PORT', 20)),
        'ISO_TIMEOUT': int(os.environ.get('ISO_TIMEOUT', 120)),

        # Daily transaction limit for the terminal
        'DAILY_LIMIT_PER_TERMINAL': int(os.environ.get('DAILY_LIMIT_PER_TERMINAL', 10000000)), # Default 10M EUR/USD

        # Exchange rates for calculating gas/energy fees in USDT (IMPORTANT: Use real-time oracles in production!)
        'ETH_TO_USDT_RATE': float(os.environ.get('ETH_TO_USDT_RATE', 2000.0)), # Example: 1 ETH = 2000 USDT
        'TRX_TO_USDT_RATE': float(os.environ.get('TRX_TO_USDT_RATE', 0.1)),    # Example: 1 TRX = 0.1 USDT

        # Session Secret for Flask - Aligned with FLASH_SECRET_KEY
        'SESSION_SECRET': os.environ.get('FLASH_SECRET_KEY', 'blackrock_terminal_secret_2025_DEFAULT_DO_NOT_USE_IN_PROD')
    }

    # Log warnings if critical production keys are still placeholders
    # These checks should compare against the *original* placeholder strings.
    if config['INFURA_PROJECT_ID'] == 'YOUR_INFURA_PROJECT_ID_HERE':
        logger.warning("INFURA_PROJECT_ID is a placeholder. Replace with your actual Infura Project ID.")
    if config['TRONGRID_API_KEY'] == 'YOUR_TRONGRID_API_KEY_HERE':
        logger.warning("TRONGRID_API_KEY is a placeholder. Replace with your actual Trongrid API Key.")

    # Check sender private keys for placeholders
    if config['SENDER_ERC20_PRIVATE_KEY'] == '0x1111111111111111111111111111111111111111111111111111111111111111':
        logger.error("SENDER_ERC20_PRIVATE_KEY is a placeholder. THIS IS HIGHLY SENSITIVE. SET SECURELY IN PRODUCTION!")
    if config['SENDER_TRC20_PRIVATE_KEY'] == '1111111111111111111111111111111111111111111111111111111111111111':
        logger.error("SENDER_TRC20_PRIVATE_KEY is a placeholder. THIS IS HIGHLY SENSITIVE. SET SECURELY IN PRODUCTION!")

    # Warn if ISO server settings are still defaults
    if config['ISO_SERVER_HOST'] == '66.185.176.0' or config['ISO_SERVER_PORT'] == 20:
        logger.warning("ISO_SERVER_HOST or ISO_SERVER_PORT are still default placeholders. Update for production.")

    return config

def validate_production_config(config):
    """
    Performs basic validation on the loaded production configuration.
    """
    errors = []
    # These validations should also check against the *original* placeholder strings
    # or against proper format/length, not specific real values.
    if not config['INFURA_PROJECT_ID'] or config['INFURA_PROJECT_ID'] == 'YOUR_INFURA_PROJECT_ID_HERE':
        errors.append("Infura Project ID is missing or is a placeholder.")

    # Validate SENDER_ERC20_PRIVATE_KEY (which now includes fallback logic)
    # This checks for proper format and length, which is good.
    if not config['SENDER_ERC20_PRIVATE_KEY'] or not config['SENDER_ERC20_PRIVATE_KEY'].startswith('0x') or len(config['SENDER_ERC20_PRIVATE_KEY']) != 66:
        errors.append("Invalid or missing SENDER_ERC20_PRIVATE_KEY.")

    # Validate SENDER_TRC20_PRIVATE_KEY (which now includes fallback logic)
    # This checks for proper format and length, which is good.
    if not config['SENDER_TRC20_PRIVATE_KEY'] or len(config['SENDER_TRC20_PRIVATE_KEY']) != 64:
        errors.append("Invalid or missing SENDER_TRC20_PRIVATE_KEY.")

    if not isinstance(config['ETH_TO_USDT_RATE'], (int, float)) or config['ETH_TO_USDT_RATE'] <= 0:
        errors.append("Invalid ETH_TO_USDT_RATE. Must be a positive number.")
    if not isinstance(config['TRX_TO_USDT_RATE'], (int, float)) or config['TRX_TO_USDT_RATE'] <= 0:
        errors.append("Invalid TRX_TO_USDT_RATE. Must be a positive number.")

    # Validate ISO Server details
    if not config['ISO_SERVER_HOST'] or config['ISO_SERVER_HOST'] == '66.185.176.0':
        errors.append("ISO_SERVER_HOST is missing or is a placeholder.")
    if not isinstance(config['ISO_SERVER_PORT'], int) or config['ISO_SERVER_PORT'] <= 0:
        errors.append("Invalid ISO_SERVER_PORT. Must be a positive integer.")
    if not isinstance(config['ISO_TIMEOUT'], int) or config['ISO_TIMEOUT'] <= 0:
        errors.append("Invalid ISO_TIMEOUT. Must be a positive integer.")

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
