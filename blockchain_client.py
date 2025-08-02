import logging
from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey as TronPrivateKey
from tronpy.providers import HTTPProvider as TronHTTPProvider
# Removed explicit import for TransactionRejectedError to avoid ImportError.
# We will now rely on general Exception handling for transaction failures.

# Import production config for API keys, private keys, and exchange rates
from production_config import get_production_config

logger = logging.getLogger(__name__)

class BlockchainClient:
    """
    A client to interact with various blockchain networks (Ethereum/ERC20 and Tron/TRC20)
    for sending USDT payouts.
    """
    def __init__(self):
        """
        Initializes the BlockchainClient, loading configuration and setting up
        Web3 and Tron connections.
        """
        self.config = get_production_config()

        # Infura Project ID for Ethereum-compatible networks
        self.infura_project_id = self.config['INFURA_PROJECT_ID']
        # Sender's private key for ERC20 transactions
        self.sender_erc20_private_key = self.config['SENDER_ERC20_PRIVATE_KEY']
        self.sender_erc20_address = None # Will be derived from private key

        # Trongrid API Key for Tron network
        self.trongrid_api_key = self.config['TRONGRID_API_KEY']
        # Sender's private key for TRC20 transactions
        self.sender_trc20_private_key = self.config['SENDER_TRC20_PRIVATE_KEY']
        self.sender_trc20_address = None # Will be derived from private key

        # Exchange rates for converting gas/energy fees to USDT
        self.eth_to_usdt_rate = self.config['ETH_TO_USDT_RATE']
        self.trx_to_usdt_rate = self.config['TRX_TO_USDT_RATE']

        # Initialize blockchain clients
        self._init_web3_client()
        self._init_tron_client()

    def _init_web3_client(self):
        """
        Initializes the Web3 client for ERC20 transactions.
        Connects to Infura and derives the sender's ERC20 address.
        """
        try:
            # Connect to Ethereum Mainnet via Infura
            self.web3_client = Web3(Web3.HTTPProvider(f"https://mainnet.infura.io/v3/{self.infura_project_id}"))
            # For Proof-of-Authority (PoA) networks like BSC or Polygon, uncomment the line below:
            # self.web3_client.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            if not self.web3_client.is_connected():
                raise ConnectionError("Failed to connect to Infura (ERC20). Check INFURA_PROJECT_ID and network configuration.")

            # Derive sender address from the ERC20 private key
            self.sender_erc20_address = self.web3_client.eth.account.from_key(self.sender_erc20_private_key).address
            logger.info(f"ERC20 Client initialized. Sender Address: {self.sender_erc20_address}")
        except Exception as e:
            self.web3_client = None
            self.sender_erc20_address = None
            logger.error(f"Error initializing ERC20 client: {e}. Payouts via ERC20 will not work.")

    def _init_tron_client(self):
        """
        Initializes the Tron client for TRC20 transactions.
        Connects to Tron network via Trongrid and derives the sender's TRC20 address.
        """
        try:
            # Connect to Tron Mainnet via Trongrid
            self.tron_client = Tron(
                provider=TronHTTPProvider(api_key=self.trongrid_api_key)
            )
            # Derive sender address from the TRC20 private key
            self.sender_trc20_address = str(TronPrivateKey(bytes.fromhex(self.sender_trc20_private_key)).public_key.to_address())
            logger.info(f"TRC20 Client initialized. Sender Address: {self.sender_trc20_address}")
        except Exception as e:
            self.tron_client = None
            self.sender_trc20_address = None
            logger.error(f"Error initializing TRC20 client: {e}. Payouts via TRC20 will not work.")

    def send_usdt(self, network, to_address, amount_usd):
        """
        Sends USDT (Tether) to a specified address on the given network.
        This function acts as a dispatcher for ERC20 and TRC20 USDT transfers.
        Assumes USDT is a stablecoin pegged to USD.

        Args:
            network (str): The blockchain network ('erc20' or 'trc20').
            to_address (str): The recipient's wallet address.
            amount_usd (float): The amount of USDT to send (in USD equivalent).

        Returns:
            dict: A dictionary containing the transaction status, payout amount,
                  simulated gas fee, transaction hash, and a message.
        """
        if network.lower() == 'erc20':
            return self._send_erc20_usdt(to_address, amount_usd)
        elif network.lower() == 'trc20':
            return self._send_trc20_usdt(to_address, amount_usd)
        else:
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': f"Unsupported network: {network}"
            }

    def _send_erc20_usdt(self, to_address, amount_usd):
        """
        Handles sending USDT on an ERC20 compatible network (e.g., Ethereum Mainnet).

        Args:
            to_address (str): The recipient's ERC20 wallet address.
            amount_usd (float): The amount of USDT to send (in USD equivalent).

        Returns:
            dict: Transaction details including status, payout amount, gas fee, and hash.
        """
        # Pre-check client and private key availability
        if not self.web3_client or not self.web3_client.is_connected() or not self.sender_erc20_address:
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': 'ERC20 client not connected or sender address not derived. Check logs for init errors.'
            }
        # Check if the private key is still the placeholder
        if self.sender_erc20_private_key == get_production_config()['SENDER_ERC20_PRIVATE_KEY']:
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': 'ERC20 sender private key is a placeholder. Cannot send real transaction.'
            }

        try:
            # USDT (ERC20) contract address on Ethereum Mainnet
            # ALWAYS verify contract addresses for the specific chain/token you are using.
            usdt_contract_address = self.web3_client.to_checksum_address("0xdAC17F958D2ee523a2206206994597C13D831ec7")
            # Standard ERC20 ABI for the 'transfer' function
            usdt_abi = [
                {
                    "constant": False,
                    "inputs": [
                        {"name": "_to", "type": "address"},
                        {"name": "_value", "type": "uint256"}
                    ],
                    "name": "transfer",
                    "outputs": [{"name": "", "type": "bool"}],
                    "payable": False,
                    "stateMutability": "nonpayable",
                    "type": "function"
                }
            ]

            usdt_contract = self.web3_client.eth.contract(address=usdt_contract_address, abi=usdt_abi)

            # Convert amount to the token's smallest unit (USDT typically has 6 decimal places)
            amount_in_usdt_decimals = int(amount_usd * (10 ** 6))

            # Estimate gas required for the transaction
            estimated_gas_limit = usdt_contract.functions.transfer(
                self.web3_client.to_checksum_address(to_address),
                amount_in_usdt_decimals
            ).estimate_gas({
                'from': self.sender_erc20_address
            })
            # Add a buffer to the estimated gas limit for network fluctuations
            gas_limit_with_buffer = int(estimated_gas_limit * 1.2) # 20% buffer

            # Get the current gas price from the network
            gas_price_wei = self.web3_client.eth.gas_price

            # Build the transaction dictionary
            transaction = usdt_contract.functions.transfer(
                self.web3_client.to_checksum_address(to_address),
                amount_in_usdt_decimals
            ).build_transaction({
                'from': self.sender_erc20_address,
                'nonce': self.web3_client.eth.get_transaction_count(self.sender_erc20_address),
                'gas': gas_limit_with_buffer,
                'gasPrice': gas_price_wei
            })

            # Sign the transaction with the sender's private key
            signed_txn = self.web3_client.eth.account.sign_transaction(transaction, private_key=self.sender_erc20_private_key)

            # Send the raw, signed transaction to the network
            tx_hash = self.web3_client.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            logger.info(f"ERC20 USDT transaction sent. Hash: {tx_hash_hex}")

            # Calculate the actual gas fee in ETH, then convert to USDT
            actual_gas_fee_wei = gas_limit_with_buffer * gas_price_wei
            actual_gas_fee_eth = self.web3_client.from_wei(actual_gas_fee_wei, 'ether')
            gas_fee_usdt = actual_gas_fee_eth * self.eth_to_usdt_rate

            return {
                'status': 'Success',
                'payout_amount_usdt': amount_usd,
                'simulated_gas_fee_usdt': gas_fee_usdt,
                'transaction_hash': tx_hash_hex,
                'message': 'ERC20 USDT payout successful.'
            }

        except Exception as e:
            logger.error(f"ERC20 USDT payout failed: {e}")
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': f"ERC20 USDT payout failed: {e}"
            }

    def _send_trc20_usdt(self, to_address, amount_usd):
        """
        Handles sending USDT on the TRC20 network (Tron).

        Args:
            to_address (str): The recipient's TRC20 wallet address.
            amount_usd (float): The amount of USDT to send (in USD equivalent).

        Returns:
            dict: Transaction details including status, payout amount, energy/bandwidth fee, and hash.
        """
        # Pre-check client and private key availability
        if not self.tron_client or not self.sender_trc20_address:
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': 'TRC20 client not initialized or sender address not derived. Check logs for init errors.'
            }
        # Check if the private key is still the placeholder
        if self.sender_trc20_private_key == get_production_config()['SENDER_TRC20_PRIVATE_KEY']:
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': 'TRC20 sender private key is a placeholder. Cannot send real transaction.'
            }

        try:
            # USDT (TRC20) contract address on Tron Mainnet
            # ALWAYS verify contract addresses for the specific chain/token you are using.
            trc20_usdt_contract_address = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

            # Convert amount to the token's smallest unit (USDT TRC20 typically has 6 decimal places)
            amount_in_trc20_decimals = int(amount_usd * (10 ** 6))

            # Get the TRC20 token object from the Tron client
            usdt_token = self.tron_client.get_contract(trc20_usdt_contract_address)

            # Create the transfer transaction object
            txn = usdt_token.functions.transfer(
                self.tron_client.to_address(to_address),
                amount_in_trc20_decimals
            ).with_owner(self.sender_trc20_address)

            # Estimate energy and bandwidth for the transaction and build it
            # A fixed, safe fee_limit is used here. In a production system, this should be dynamic
            # based on real-time network conditions and transaction simulation.
            fee_limit_trx = 25 # Example: 25 TRX as a safe upper bound for fee limit
            fee_limit_sun = fee_limit_trx * 1_000_000 # Convert TRX to SUN (1 TRX = 1,000,000 SUN)

            built_txn = txn.build().set_fee_limit(fee_limit_sun)
            # Sign the transaction with the sender's private key
            signed_txn = built_txn.sign(TronPrivateKey(bytes.fromhex(self.sender_trc20_private_key)))

            # Broadcast the transaction to the Tron network and wait for confirmation
            tx_id = self.tron_client.trx.broadcast(signed_txn).wait()
            logger.info(f"TRC20 USDT transaction sent. Tx ID: {tx_id}")

            # Fetch transaction info to get actual resource usage (for accurate fee reporting)
            tx_info = self.tron_client.get_transaction_info(tx_id)
            actual_energy_used = tx_info.get('receipt', {}).get('energy_usage_total', 0)

            # Calculate actual TRX burned for energy
            # 1 Energy Point = 420 SUN (0.00042 TRX) - This rate can change.
            trx_burned_for_energy = (actual_energy_used * 420) / 1_000_000 if actual_energy_used else 0
            # Add a small amount for bandwidth if not covered by free bandwidth
            # (Very rough estimate, actual bandwidth cost depends on transaction size)
            simulated_bandwidth_cost_trx = 0.5

            total_trx_fee = trx_burned_for_energy + simulated_bandwidth_cost_trx
            total_fee_usdt = total_trx_fee * self.trx_to_usdt_rate

            return {
                'status': 'Success',
                'payout_amount_usdt': amount_usd,
                'simulated_gas_fee_usdt': total_fee_usdt,
                'transaction_hash': tx_id,
                'message': 'TRC20 USDT payout successful.'
            }

        except Exception as e:
            logger.error(f"TRC20 USDT payout failed: {e}")
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': f"TRC20 USDT payout failed: {e}"
            }
