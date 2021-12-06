import logging
from time import sleep
from iroha import primitive_pb2
from IrohaUtils import *
import pickle
import os

BLOCKCHAIN_LOGGING = int(os.getenv("BLOCKCHAIN_LOGGING", "1"))
LOGGING_LEVEL = int(os.getenv("LOGGING_LEVEL", "20")) #INFO level is 20
logging.basicConfig(level=LOGGING_LEVEL)
DOMAIN_NAME = "document"
user = new_user("swipluser", DOMAIN_NAME)
with open("/notebooks/iroha_connection/user_data.pkl", "wb+") as user_data:
    pickle.dump(user, user_data)
logging.debug(user)

def setup_iroha():

    commands = [
        # Create a new role that can only create assets (i.e. create hashes) and read assets (to see if they exist)
        iroha_admin.command("CreateRole", role_name="document_creator", permissions=[
                primitive_pb2.can_create_asset,
                primitive_pb2.can_read_assets
            ]),
        # Create a new domain that has document_creator as role
        iroha_admin.command("CreateDomain", domain_id=DOMAIN_NAME, default_role="document_creator"),
        iroha_admin.command('CreateAccount', account_name=user["name"], domain_id=DOMAIN_NAME,
                            public_key=user["public_key"])
    ]
    # Sign and send set up block
    tx = IrohaCrypto.sign_transaction(
            iroha_admin.transaction(commands), ADMIN_PRIVATE_KEY)
    logging.debug(tx)
    status = send_transaction(tx, net_1)
    logging.debug(status)
    return status[0] == "COMMITTED"


# Initial sleep to try and avoid "Network Unreachable!"
logging.info("Starting SWIPL setup")
if BLOCKCHAIN_LOGGING:
    logging.info("Starting Iroha setup")
    sleep(10)
    iroha_setup = False
    while not iroha_setup:
        try:
            logging.info("Iroha connection setup attempt")
            iroha_setup = setup_iroha()
            if not iroha_setup:
                logging.info("Setup failed! Reattempting")
        except Exception:
            logging.info("Network unreachable! Reattempting")
            sleep(5)
            continue
    logging.info("Iroha Setup Complete")

logging.info("SWIPL Setup Complete")