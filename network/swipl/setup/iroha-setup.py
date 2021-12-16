import logging
from time import sleep
from IrohaUtils import *
import pickle
import os

BLOCKCHAIN_LOGGING = int(os.getenv("BLOCKCHAIN_LOGGING", "1"))
LOGGING_LEVEL = int(os.getenv("LOGGING_LEVEL", "20")) #INFO level is 20
logging.basicConfig(level=LOGGING_LEVEL)

# Initial sleep to try and avoid "Network Unreachable!"
logging.info("Starting SWIPL setup")
if BLOCKCHAIN_LOGGING:
    logging.info("Starting Iroha setup")
    sleep(7)
    iroha_setup = False
    while not iroha_setup:
        try:
            custodian = IrohaHashCustodian.Custodian()
            user = custodian.new_hashing_user("swipluser")
            with open("/notebooks/iroha_connection/user_data.pkl", "wb+") as user_data:
                pickle.dump(user, user_data)
            logging.debug(user)
            iroha_setup=True
        except Exception:
            logging.info("Network unreachable! Reattempting")
            sleep(5)
            continue
    logging.info("Iroha Setup Complete")

logging.info("SWIPL Setup Complete")