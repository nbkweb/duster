import logging
from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey as TronPrivateKey
from tronpy.providers import HTTPProvider as TronHTTPProvider
# Removed specific import for TransactionRejectedError to avoid ImportError.
# We will catch a more general Exception in the send method.


# Import production config for API keys, private keys, and exchange rates
from production_config import get_production_config

logger = logging.getLogger(__name__)

class BlockchainClient:
    def __init__(self):
        self.config = get_production_config()

        self.infura_project_id = self.config['INFURA_PROJECT_ID']
        self.sender_erc20_private_key = self.config['ETH_PRIVATE_KEY']
        self.sender_erc20_address = None

        self.trongrid_api_key = self.config['TRONGRID_API_KEY']
        self.sender_trc20_private_key = self.config['TRON_PRIVATE_KEY']
        self.sender_trc20_address = None

        self.eth_to_usdt_rate = self.config['ETH_TO_USDT_RATE']
        self.trx_to_usdt_rate = self.config['TRX_TO_USDT_RATE']

        self._init_web3_client()
        self._init_tron_client()

    def _init_web3_client(self):
        """Initializes Web3 client for ERC20 transactions."""
        try:
            # Using Infura Ethereum Mainnet. For testnets, change the URL.
            # Example for Sepolia testnet: f"https://sepolia.infura.io/v3/{self.infura_project_id}"
            self.web3_client = Web3(Web3.HTTPProvider(f"https://mainnet.infura.io/v3/{self.infura_project_id}"))
            # self.web3_client.middleware_onion.inject(geth_poa_middleware, layer=0) # Uncomment for PoA networks like BSC, Polygon
            if not self.web3_client.is_connected():
                raise ConnectionError("Failed to connect to Infura (ERC20). Check INFURA_PROJECT_ID and network.")

            # Derive sender address from private key
            self.sender_erc20_address = self.web3_client.eth.account.from_key(self.sender_erc20_private_key).address
            logger.info(f"ERC20 Client initialized. Sender Address: {self.sender_erc20_address}")
        except Exception as e:
            self.web3_client = None
            self.sender_erc20_address = None
            logger.error(f"Error initializing ERC20 client: {e}. Payouts via ERC20 will not work.")

    def _init_tron_client(self):
        """Initializes Tron client for TRC20 transactions."""
        try:
            # Using Tron Mainnet. For testnets, change the URL.
            # Example for Nile testnet: Tron(HTTPProvider("https://api.nileex.io", api_key=self.trongrid_api_key))
            self.tron_client = Tron(
                provider=TronHTTPProvider(api_key=self.trongrid_api_key)
            )
            # Derive sender address from private key
            self.sender_trc20_address = str(TronPrivateKey(bytes.fromhex(self.sender_trc20_private_key)).public_key.to_address())
            logger.info(f"TRC20 Client initialized. Sender Address: {self.sender_trc20_address}")
        except Exception as e:
            self.tron_client = None
            self.sender_trc20_address = None
            logger.error(f"Error initializing TRC20 client: {e}. Payouts via TRC20 will not work.")


    def send_usdt(self, network, to_address, amount_usd):
        """
        Sends USDT (Tether) to a specified address on the given network.
        Assumes USDT is a stablecoin pegged to USD.
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
        """Sends USDT on an ERC20 compatible network (e.g., Ethereum Mainnet)."""
        if not self.web3_client or not self.web3_client.is_connected() or not self.sender_erc20_address:
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': 'ERC20 client not connected or sender address not derived. Check logs for init errors.'
            }
        if not self.sender_erc20_private_key or self.sender_erc20_private_key == self.config['SENDER_ERC20_PRIVATE_KEY']:
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': 'ERC20 sender private key is missing or is a placeholder. Cannot send real transaction.'
            }


        try:
            # USDT (ERC20) contract address on Ethereum Mainnet (always verify for the specific chain/token)
            usdt_contract_address = self.web3_client.to_checksum_address("0xdAC17F958D2ee523a2206206994597C13D831ec7")
            # Standard ERC20 ABI for transfer function
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

            # Amount needs to be in smallest unit (e.g., 6 decimals for USDT)
            amount_in_usdt_decimals = int(amount_usd * (10 ** 6)) # USDT typically has 6 decimal places

            # Estimate gas for the transaction
            # This is a crucial step for production-grade fee handling
            estimated_gas_limit = usdt_contract.functions.transfer(
                self.web3_client.to_checksum_address(to_address),
                amount_in_usdt_decimals
            ).estimate_gas({
                'from': self.sender_erc20_address
            })
            # Add a buffer to the estimated gas limit to account for network fluctuations
            gas_limit_with_buffer = int(estimated_gas_limit * 1.2) # 20% buffer

            # Get current gas price
            gas_price_wei = self.web3_client.eth.gas_price

            # Build the transaction
            transaction = usdt_contract.functions.transfer(
                self.web3_client.to_checksum_address(to_address),
                amount_in_usdt_decimals
            ).build_transaction({
                'from': self.sender_erc20_address,
                'nonce': self.web3_client.eth.get_transaction_count(self.sender_erc20_address),
                'gas': gas_limit_with_buffer,
                'gasPrice': gas_price_wei
            })

            # Sign the transaction
            signed_txn = self.web3_client.eth.account.sign_transaction(transaction, private_key=self.sender_erc20_private_key)

            # Send the transaction
            tx_hash = self.web3_client.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            logger.info(f"ERC20 USDT transaction sent. Hash: {tx_hash_hex}")

            # Calculate actual gas fee in ETH (before conversion to USDT)
            actual_gas_fee_wei = gas_limit_with_buffer * gas_price_wei
            actual_gas_fee_eth = self.web3_client.from_wei(actual_gas_fee_wei, 'ether')
            # Convert ETH gas fee to USDT equivalent using the configured rate
            gas_fee_usdt = actual_gas_fee_eth * self.eth_to_usdt_rate

            return {
                'status': 'Success',
                'payout_amount_usdt': amount_usd,
                'simulated_gas_fee_usdt': gas_fee_usdt, # Now a more realistic calculation
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
        """Sends USDT on the TRC20 network (Tron)."""
        if not self.tron_client or not self.sender_trc20_address:
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': 'TRC20 client not initialized or sender address not derived. Check logs for init errors.'
            }
        if not self.sender_trc20_private_key or self.sender_trc20_private_key == self.config['SENDER_TRC20_PRIVATE_KEY']:
            return {
                'status': 'Failed',
                'payout_amount_usdt': 0.0,
                'simulated_gas_fee_usdt': 0.0,
                'transaction_hash': 'N/A',
                'message': 'TRC20 sender private key is missing or is a placeholder. Cannot send real transaction.'
            }

        try:
            # USDT (TRC20) contract address on Tron Mainnet (always verify)
            trc20_usdt_contract_address = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" # This is a common address

            # Amount needs to be in smallest unit (e.g., 6 decimals for USDT TRC20)
            amount_in_trc20_decimals = int(amount_usd * (10 ** 6))

            # Get the TRC20 token object
            usdt_token = self.tron_client.get_contract(trc20_usdt_contract_address)

            # Create the transfer transaction
            # This is how tronpy allows estimating energy/bandwidth before signing
            txn = usdt_token.functions.transfer(
                self.tron_client.to_address(to_address),
                amount_in_trc20_decimals
            ).with_owner(self.sender_trc20_address)

            # Estimate energy and bandwidth for the transaction
            # This is a key part of realistic fee calculation for Tron
            try:
                # `fee_limit` is the maximum TRX the sender is willing to pay for energy/bandwidth
                # It's crucial to set this appropriately to avoid draining the wallet.
                # A common approach is to simulate the transaction to get actual energy/bandwidth usage.
                # For a USDT transfer, it typically consumes around 31,895 Energy.
                # 1 Energy Point = 420 SUN (0.00042 TRX)
                # So, 31895 Energy * 0.00042 TRX/Energy = ~13.39 TRX.
                # We'll set a reasonable fee_limit, e.g., 50 TRX (50 * 1,000,000 SUN) for safety.
                # In production, you'd call `trigger_constant_contract` or `trigger_smart_contract`
                # with `call_value=0` and `_should_poll=False` to estimate.
                # tronpy's `build()` often does a pre-check that includes estimation.

                # For simplicity, we'll set a high enough fee_limit for now, and note that it should be dynamic.
                # A typical USDT transfer costs around 13.39 TRX if no frozen energy/bandwidth
                # is available. Setting 25 TRX as a safe upper bound for fee_limit.
                fee_limit_trx = 25
                fee_limit_sun = fee_limit_trx * 1_000_000 # 1 TRX = 1,000,000 SUN

                built_txn = txn.build().set_fee_limit(fee_limit_sun)
                # Sign the transaction
                signed_txn = built_txn.sign(TronPrivateKey(bytes.fromhex(self.sender_trc20_private_key)))

            except Exception as tre: # Changed from TransactionRejectedError to a general Exception
                logger.error(f"TRC20 transaction estimation/build failed: {tre}")
                return {
                    'status': 'Failed',
                    'payout_amount_usdt': 0.0,
                    'simulated_gas_fee_usdt': 0.0,
                    'transaction_hash': 'N/A',
                    'message': f"TRC20 transaction pre-check failed: {tre}"
                }


            # Broadcast the transaction
            tx_id = self.tron_client.trx.broadcast(signed_txn).wait() # .wait() blocks until confirmed or timeout
            logger.info(f"TRC20 USDT transaction sent. Tx ID: {tx_id}")

            # Fetch transaction info to get actual resource usage
            # This is crucial for accurate fee reporting
            tx_info = self.tron_client.get_transaction_info(tx_id)
            actual_energy_used = tx_info.get('receipt', {}).get('energy_usage_total', 0)
            # Bandwidth is harder to get directly from receipt, often estimated or implicit.
            # For simplicity, we'll focus on energy for TRC20 smart contract calls.

            # Calculate actual TRX burned for energy (if any)
            # 1 Energy Point = 420 SUN (0.00042 TRX)
            # This conversion rate can change, ideally fetched from chain properties.
            trx_burned_for_energy = (actual_energy_used * 420) / 1_000_000 if actual_energy_used else 0
            # Add a small amount for bandwidth if not covered by free bandwidth
            # (Very rough estimate, actual bandwidth cost depends on transaction size)
            simulated_bandwidth_cost_trx = 0.5 # Assume 0.5 TRX for bandwidth if not free

            total_trx_fee = trx_burned_for_energy + simulated_bandwidth_cost_trx
            total_fee_usdt = total_trx_fee * self.trx_to_usdt_rate


            return {
                'status': 'Success',
                'payout_amount_usdt': amount_usd,
                'simulated_gas_fee_usdt': total_fee_usdt, # Now a more realistic calculation
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
