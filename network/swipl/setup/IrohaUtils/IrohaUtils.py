import os
import binascii
import logging
from pathlib import Path
import re
from google.protobuf.symbol_database import Default
from iroha import IrohaCrypto, Iroha, IrohaGrpc, primitive_pb2
import hashlib

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Iroha peer 1
IROHA_HOST_ADDR_1 = os.getenv('IROHA_HOST_ADDR_1', '172.29.101.121')
IROHA_PORT_1 = os.getenv('IROHA_PORT_1', '50051')
# Iroha peer 2
IROHA_HOST_ADDR_2 = os.getenv('IROHA_HOST_ADDR_2', '172.29.101.122')
IROHA_PORT_2 = os.getenv('IROHA_PORT_2', '50052')
# Iroha peer 3
IROHA_HOST_ADDR_3 = os.getenv('IROHA_HOST_ADDR_3', '172.29.101.123')
IROHA_PORT_3 = os.getenv('IROHA_PORT_3', '50053')
# Iroha peer 4
IROHA_HOST_ADDR_4 = os.getenv('IROHA_HOST_ADDR_3', '172.29.101.124')
IROHA_PORT_4 = os.getenv('IROHA_PORT_4', '50054')

ADMIN_ACCOUNT_ID = os.getenv('ADMIN_ACCOUNT_ID', 'admin@admin')
ADMIN_PRIVATE_KEY = os.getenv(
    'ADMIN_PRIVATE_KEY', 'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70')
iroha_admin = Iroha(ADMIN_ACCOUNT_ID)

admin = {
    "id": "admin@admin",
    "name": "admin",
    "domain": "admin",
    "public_key": IrohaCrypto.derive_public_key(ADMIN_PRIVATE_KEY),
    "private_key": ADMIN_PRIVATE_KEY,
    "iroha": iroha_admin
}


net_1 = IrohaGrpc('{}:{}'.format(IROHA_HOST_ADDR_1, IROHA_PORT_1), timeout=10)
net_2 = IrohaGrpc('{}:{}'.format(IROHA_HOST_ADDR_2, IROHA_PORT_2), timeout=10)
net_3 = IrohaGrpc('{}:{}'.format(IROHA_HOST_ADDR_3, IROHA_PORT_3), timeout=10)
net_4 = IrohaGrpc('{}:{}'.format(IROHA_HOST_ADDR_4, IROHA_PORT_4), timeout=10)


def trace(func):
    """
    A decorator for tracing methods' begin/end execution points
    """

    def tracer(*args, **kwargs):
        name = func.__name__
        logging.debug(f'{bcolors.HEADER}==> Entering "{name}"{bcolors.ENDC}')
        result = func(*args, **kwargs)
        logging.debug(f'{bcolors.HEADER}==> Leaving "{name}"{bcolors.ENDC}')
        return result

    return tracer


@trace
def send_transaction(transaction, connection, verbose=False):
    """Send a transaction across a network to a peer and return the final status
    Verbose mode intended mainly for manual transaction sending and testing
    This method is blocking, waiting for a final status for the transaction

    Args:
        transaction (Iroha.transaction): The signed transaction to send to a peer
        connection (IrohaGrpc): The Grpc connection to send the transaction across
        verbose (bool): A boolean to print the status stream to stdout

    Returns:
        Iroha Transaction Status: The final transaction status received
    """

    hex_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
    logging.debug(transaction)
    logging.debug('Transaction hash = {}, creator = {}'.format(
        hex_hash, transaction.payload.reduced_payload.creator_account_id))
    connection.send_tx(transaction)
    last_status = None
    for status in connection.tx_status_stream(transaction):
        if verbose: print(status)
        logging.debug(status)
        last_status = status
    return last_status

@trace
def send_batch(transactions, connection, verbose=False):
    """Send a batch of transactions across a connection, all at once

    Args:
        transactions (list of Iroha.transaction): The signed transactions to send to a peer
        connection (IrohaGrpc): The Grpc connection to send the transactions across
        verbose (bool): A boolean to print the status stream to stdout

    Returns:
        Iroha Transaction Statuses: List of the final transaction status received, for each transaction in batch
    """

    connection.send_txs(transactions)
    last_status_list = []
    for tx in transactions:
        hex_hash = binascii.hexlify(IrohaCrypto.hash(tx))
        logging.debug('Transaction hash = {}, creator = {}'.format(
            hex_hash, tx.payload.reduced_payload.creator_account_id))
        for status in connection.tx_status_stream(tx):
            if verbose: print(status)
            last_status = status
        last_status_list.append(last_status)
    return last_status_list

@trace
def get_block(block_number, connection):
    """Get the block at height block_number from the node specified by connection 

    Args:
        block_number (int): The block number to get. Must be >0 and less than the maximum height
        connection (IrohaGrpc): The connection to a node to get blocks from

    Returns:
        JSON: the JSON description of the block requested
    
    Throws:
        Exception if block height is invalid, or if connection is invalid
    """

    query = admin["iroha"].query("GetBlock", height=block_number)
    query = IrohaCrypto.sign_query(query, admin["private_key"])
    block = connection.send_query(query)

    return block

@trace
def get_all_blocks(connection):
    """Get all blocks from a connection

    Args:
        connection (IrohaGrpc): The connection to a node to get blocks from

    Returns:
        list of JSON strings: A list of every block in JSON format from a node 
    """

    current_height = 1
    current_block = get_block(current_height, connection)
    block_json = []

    while (current_block := get_block(current_height, connection)).error_response.error_code == 0:
        logging.debug(f"SUCCESSFULLY GOT BLOCK {current_height}")
        block_json.append(current_block)
        current_height += 1
        logging.debug(f"GETTING BLOCK {current_height}")
    logging.debug(f"END OF CHAIN REACHED")
    return block_json

@trace
def log_all_blocks(connection, log_name, logs_directory="logs"):
    """Get all blocks from a node and write them to a log file in JSON format

    Args:
        connection (IrohaGrpc): The connection to a node to get blocks from
        log_name (String): Name of file to write logs to
        logs_directory (String, optional): Name of directory (child of current directory) to place logs into
            Created if not currently created. Defaults to logs
    """

    path = Path(logs_directory + "/" + log_name)
    if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))

    block_json = get_all_blocks(connection)

    with open(path, "w+") as f:
        for block in block_json:
            f.write(str(block)+"\n\n")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

def new_user(user_name, domain_name):
    """
    Create the data for a new user and return it
    Includes public and private keys

    Args:
        user_name (String): The name of the new user
        domain_name (String): The name of the domain the user is to be placed in

    Returns:
        Dictionary : A key-value store of user_id, public and private keys
    """

    priv_key = IrohaCrypto.private_key()
    pub_key = IrohaCrypto.derive_public_key(priv_key)
    id = user_name + "@" + domain_name

    return {
        "id": id,
        "name": user_name,
        "domain": domain_name,
        "public_key": pub_key,
        "private_key": priv_key,
        "iroha": Iroha(id)
    }

class IrohaHashCustodian():
    """
    A class to look after hashes on the block chain
    Offering the ability to get hashes of a file, store hashes on the chain, and find hashes on the chain
    """

    """
    The hash function this custodian will use
    Iroha demands 32 character asset names, so we are restricted greatly in output size
    """
    hash_function = hashlib.md5
    default_role_name = "null_role"

    @trace
    def __init__(self):
        # Ensure default role exists
        q = admin["iroha"].query("GetRoles")
        q = IrohaCrypto.sign_query(q, admin["private_key"])
        response = net_1.send_query(q)
        if self.default_role_name not in response.roles_response.roles:
            commands = [
                admin["iroha"].command("CreateRole", role_name="null_role", permissions=[
            
                ])
            ]
            tx = IrohaCrypto.sign_transaction(
                admin["iroha"].transaction(commands), admin["private_key"])
            logging.debug(tx)
            status = send_transaction(tx, net_1)
            logging.debug(status)

    @trace
    def get_file_hash(self, filename):
        """
        Generate and return the MD5 hex digest of the contents of a file
        While it would be nice to use a different, more secure algorithm we are constrained
        The output of this hash will be the name of an Iroha asset, which can have max length of 32

        Args:
            filename (String): The name of the file to hash

        Returns:
            String: The hex digest of the contents of the file described by filename
        """
        with open(filename, "rb") as f:
            b = f.read()
            h = self.hash_function(b)
        logging.debug(h.hexdigest())
        return h.hexdigest()

    @trace
    def get_hash(self, obj):
        """
        Get the hash digest of an object

        Args:
            obj (Object, hashable): The object to hash

        Returns:
            String: The hex digest of the object
        """
        obj = str(obj).encode()
        return self.hash_function(obj).hexdigest()

    @trace
    def _admin_create_domain(self, domain_name):
        """
        Create a new domain, according to admins specifications
        This function exists so a user cannot make a domain with a specific role, as now admin gets to control this
        This function requires existence of a null_role. Passing in a role would defeat the purpose of this function


        Args:
            domain_name (String): The domain name to create

        Return:
            Boolean: True if domain exists, False otherwise
        """

        commands = [
            admin["iroha"].command("CreateDomain", domain_id=domain_name, default_role="null_role")
        ]
        tx = IrohaCrypto.sign_transaction(
            admin["iroha"].transaction(commands), admin["private_key"])
        logging.debug(tx)
        status = send_transaction(tx, net_1)
        logging.debug(status)
        if status[0]=="COMMITTED":
            logging.debug(f"New domain \"{domain_name}\" created")
        else:
            logging.debug(f"Domain \"{domain_name}\" already exists")

        # Domain will always exist, look into False case later
        return True

    @trace
    def store_hash_on_chain(self, user, h, domain_name=None, connection=net_1):
        """
        Take the hex digest of a message and store this on the blockchain as the name of an asset

        Args:
            user (Dictionary): The user dictionary of the user sending this hash
            h (String): The hash of a message
            domain_name (String or None, optional): The domain name to store the hash in
                If None then use the users domain instead
                Defaults to None
            connection (IrohaGrpc, optional): The connection to send this hash over. Defaults to net_1.

        Return:
            IrohaStatus: The status of the transaction to put this hash to the chain
        """

        if domain_name is None:
            domain_name = user["domain"]

        # Try to create the domain, true if domain now exists, false otherwise
        status = self._admin_create_domain(domain_name)
        if not status:
            logging.info("Domain failed to exist!")
            # Let method continue so rejected status can be passed

        commands = [
            user["iroha"].command('CreateAsset', asset_name=h,
                        domain_id=domain_name, precision=0)
        ]
        tx = IrohaCrypto.sign_transaction(
            user["iroha"].transaction(commands), user["private_key"])
        logging.debug(tx)
        status = send_transaction(tx, connection)
        logging.debug(status)
        return status

    @trace
    def find_hash_on_chain(self, user, h, domain_name=None, connection=net_1):
        """
        Given the hex digest of a message, attempt to find this hash on the blockchain

        Args:
            user (Dictionary): The user dictionary of the user querying this hash
            h (String): The hash of a message
            domain_name (String or None, optional): The domain name to search for the hash in
                If None then use the users domain instead
                Defaults to None
            connection (IrohaGrpc, optional): The connection to send this hash over. Defaults to net_1.

        Return:
            IrohaStatus: The status of this query. True if the hash exists on the blockchain, False otherwise.
        """
        
        if domain_name is None:
            domain_name = user["domain"]

        query = user["iroha"].query("GetAssetInfo", asset_id=f"{h}#{domain_name}")
        query = IrohaCrypto.sign_query(query, user["private_key"])
        logging.debug(query)
        response = connection.send_query(query)
        logging.debug(response)
        #Check if response has an asset id matching the hash we are after
        return response.asset_response.asset.asset_id==h+f"#{user['domain']}"

    @trace
    def get_domain_hashes(self, user, domain_name=None, connection=net_1):
        """
        Find all occurrences of domain being added to over the entire blockchain
        Return this information as a list, from earliest to latest

        Note this operation can be   S L O W   for large chains

        Args:
            user (Dictionary): The user dictionary of the user querying this domain
            domain_name (String or None, optional): The domain name to search for the hash in
                If None then use the users domain instead
                Defaults to None
            connection (IrohaGrpc, optional): The connection to send this hash over. Defaults to net_1.

        Returns:
            List: A list of all occurrences of assets being added to this domain over the entire chain
                The elements of this list are dictionaries of:
                    height: The height that asset was added
                    hash: The name of that asset (remembering names are hashes)
                    domain: The domain of the asset, for completeness
                    creator_id: The creator of that asset
                    time: The time of creation (may be more useful than height in some cases)
        """

        if domain_name is None:
            domain_name = user["domain"]

        current_height=1
        current_block = None
        asset_list = []

        # Loop over every block in the chain, from the first
        while (current_block := get_block(current_height, connection)).error_response.error_code == 0:
            logging.debug(f"Got block at height {current_height}")
            # For each transaction in the block
            for tx in current_block.block_response.block.block_v1.payload.transactions:
                # Get the creator and the time
                current_creator_id = tx.payload.reduced_payload.creator_account_id
                current_created_time = tx.payload.reduced_payload.created_time
                # For each command in the transaction
                for command in tx.payload.reduced_payload.commands:
                    # If the command is to create asset in the target domain, store this
                    if command.create_asset.domain_id == domain_name:
                        current_asset = {
                            "height": current_height,
                            "hash": command.create_asset.asset_name,
                            "domain": command.create_asset.domain_id,
                            "creator_id": current_creator_id,
                            "time": current_created_time
                        }
                        logging.debug("Found matching asset")
                        logging.debug(f"{current_asset=}")
                        asset_list.append(current_asset)
            current_height+=1
        return asset_list