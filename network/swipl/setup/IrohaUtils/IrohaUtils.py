import os
import binascii
import logging
from pathlib import Path
from google.protobuf.symbol_database import Default
from iroha import IrohaCrypto, Iroha, IrohaGrpc, primitive_pb2

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
def send_transaction(transaction, connection=net_1, verbose=False):
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
def send_batch(transactions, connection=net_1, verbose=False):
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
def get_block(block_number, connection=net_1):
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
def get_all_blocks(connection=net_1):
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
def log_all_blocks(log_name, logs_directory="logs", connection=net_1):
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

import IrohaHashCustodian