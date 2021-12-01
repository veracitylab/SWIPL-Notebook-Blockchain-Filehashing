import os
import binascii
import logging
import hashlib
from pathlib import Path
from iroha import IrohaCrypto, Iroha, IrohaGrpc

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

    query = iroha_admin.query("GetBlock", height=block_number)
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)
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

    with open(path, "w") as f:
        for block in block_json:
            f.write(str(block)+"\n\n")


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

@trace
def md5_hash(filename):
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
        h = hashlib.md5(b)
    logging.debug(h.hexdigest())
    return h.hexdigest()

@trace
def store_hash_on_chain(user, h, connection=net_1):
    """
    Take the hex digest of a message and store this on the blockchain as the name of an asset

    Args:
        user (Dictionary): The user dictionary of the user sending this hash
        h (String): The hash of a message
        connection (IrohaGrpc, optional): The connection to send this hash over. Defaults to net_1.

    Return:
        IrohaStatus: The status of the transaction to put this hash to the chain
    """

    commands = [
        user["iroha"].command('CreateAsset', asset_name=h,
                      domain_id=user["domain"], precision=0)
    ]
    tx = IrohaCrypto.sign_transaction(
        user["iroha"].transaction(commands), user["private_key"])
    logging.debug(tx)
    status = send_transaction(tx, net_1)
    logging.debug(status)
    return status

@trace
def find_hash_on_chain(user, h, connection=net_1):
    """
    Given the hex digest of a message, attempt to find this hash on the blockchain

    Args:
        user (Dictionary): The user dictionary of the user querying this hash
        h (String): The hash of a message
        connection (IrohaGrpc, optional): The connection to send this hash over. Defaults to net_1.

    Return:
        IrohaStatus: The status of this query. True if the hash exists on the blockchain, False otherwise.
    """
    
    query = user["iroha"].query("GetAssetInfo", asset_id=f"{h}#{user['domain']}")
    query = IrohaCrypto.sign_query(query, user["private_key"])
    logging.debug(query)
    response = connection.send_query(query)
    logging.debug(response)
    #Check if response has an asset id matching the hash we are after
    return response.asset_response.asset.asset_id==h+f"#{user['domain']}"


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)