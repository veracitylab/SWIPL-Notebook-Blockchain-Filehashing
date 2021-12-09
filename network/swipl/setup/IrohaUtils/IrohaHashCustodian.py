from IrohaUtils import *
from iroha import primitive_pb2
import logging
import hashlib
import threading

class BlockStorehouse():
    """
    A class to track the blocks being placed on the chain, to cache the results of querying blocks
    This will allow for a speed up as we will not need to query the same low height blocks over and over
    """

    """
    The current height to which this storehouse has scanned
    """
    current_height = 1

    """
    This storehouse's world state
    The dictionary is indexed by domain>blocks>hashes
    """
    world_state = {}

    @trace
    def __init__(self, conn=net_1):
        """
        Set the variables for the blockstore and create a new connection that will not time out

        Args:
            conn (IrohaGrpc, optional): The connection to copy to the block store. Defaults to net_1.
        """
        self._current_height_lock = threading.Lock()
        self.current_height = 1
        self._world_state_lock = threading.Lock()
        self.world_state = {}
        self.conn = IrohaGrpc(conn._address)
        # Collect all hashes from genesis until now
        self.init_collect_hashes()
        # Start a thread to continue to listen for new blocks
        self.listen_thread = threading.Thread(target=self.listen_for_blocks)
        self.listen_thread.start()

    @trace
    def parse_block(self, block):
        """
        Parse a block from the network, extracting hashes and storing in world_state
        Also increases current height tracker
        """

        # logging.debug(f"Got block {block} at height {self.current_height}")

        # For each transaction in the block
        for tx in block.block_response.block.block_v1.payload.transactions:
            # Get the creator and the time
            current_creator_id = tx.payload.reduced_payload.creator_account_id
            current_created_time = tx.payload.reduced_payload.created_time
            # For each command in the transaction
            for command in tx.payload.reduced_payload.commands:
                # If the command is to create asset in the target domain, store this
                if command.create_asset.domain_id.endswith(Custodian.HASHING_DOMAIN_SUFFIX):
                    # We have a new hash
                    with self._world_state_lock:
                        if command.create_asset.domain_id not in self.world_state.keys():
                            # We need to make a new entry to our world_state domains
                            self.world_state[command.create_asset.domain_id] = []
                        current_hash = {
                            "height": self.current_height,
                            "hash": command.create_asset.asset_name,
                            "domain": command.create_asset.domain_id,
                            "creator_id": current_creator_id,
                            "time": current_created_time
                        }
                        self.world_state[command.create_asset.domain_id].append(current_hash)
        with self._current_height_lock:
            self.current_height+=1

    @trace
    def init_collect_hashes(self):
        """
        Collect all the blocks from genesis to now in one swoop
        This method blocks execution as the storehouse should be up to date before being queried
        Once this method has completed, then the asynchronous polling can occur
        """

        current_block = None
        while (current_block := get_block(self.current_height, self.conn)).error_response.error_code == 0:
            logging.debug(f"Got block at height {self.current_height}")
            self.parse_block(current_block)

    @trace
    def listen_for_blocks(self):
        """
        Subscribe to blocks stream from the network
        Intended to be used as the target of a thread, to avoid blocking (no pun intended)
        """

        query = admin["iroha"].blocks_query()
        IrohaCrypto.sign_query(query, admin["private_key"])
        for block in self.conn.send_blocks_stream_query(query):
            # logging.debug(block)
            self.parse_block(block)

    def get_domain_hashes(self, domain_name):
        """
        Get the domain hashes from a domain, querying the world_state to avoid querying the chain

        Args:
            domain_name (String): The domain name to check for

        Returns:
            List or None: Either the list of hashes for the required domain or None (if no such domain exists in the world state)
        """

        # Check if domain name is in the world state, or if there are no hashes in the domain
        if domain_name not in self.world_state.keys() or len(self.world_state[domain_name])==0:
            return None

        return self.world_state[domain_name]

class Custodian():
    """
    A class to look after hashes on the block chain
    Offering the ability to get hashes of a file, store hashes on the chain, and find hashes on the chain
    """

    """
    The hash function this custodian will use
    Iroha demands 32 character asset names, so we are restricted greatly in output size
    """
    HASH_FUNCTION = hashlib.md5

    """
    The suffix for domains that store file hashes
    """
    HASHING_DOMAIN_SUFFIX = "-hash"

    @trace
    def __init__(self, default_domain_name="hashing", hashing_role_name="hash_creator", null_role_name="null_role", blockstore=False):
        self.default_domain_name = default_domain_name
        self.hashing_role_name = hashing_role_name
        self.null_role_name = null_role_name
        self.block_storehouse = None
        logging.debug(f"{self.default_domain_name=}, {self.hashing_role_name=}, {self.null_role_name=}")
        commands = [
            # Create a new role that can only create assets (i.e. create hashes) and read assets (to see if they exist)
            iroha_admin.command("CreateRole", role_name=self.hashing_role_name, permissions=[
                    primitive_pb2.can_create_asset,
                    primitive_pb2.can_read_assets
                ]),
            # Create a new role that can do NOTHING
            iroha_admin.command("CreateRole", role_name=self.null_role_name, permissions=[
                
            ]),
            # Create a new domain that has document_creator as role
            iroha_admin.command("CreateDomain", domain_id=self.default_domain_name, default_role=self.hashing_role_name)
        ]
        tx = IrohaCrypto.sign_transaction(
            admin["iroha"].transaction(commands), admin["private_key"])
        logging.debug(tx)
        status = send_transaction(tx, net_1)
        logging.debug(status)
        if blockstore:
            # Create BlockStorehouse to check blocks as they come in
            self.block_storehouse = BlockStorehouse()

    @trace
    def new_hashing_user(self, user_name):
        """
        Create a new user capable of hashing to the blockchain, also commits user onto chain

        Args:
            user_name (String): The name of the user to create

        Returns:
            Dictionary : A key-value store of user_id, public and private keys
        """
        user = new_user(user_name, self.default_domain_name)
        commands = [
            iroha_admin.command('CreateAccount', account_name=user["name"], domain_id=user["domain"],
                                public_key=user["public_key"])
        ]
        tx = IrohaCrypto.sign_transaction(
            admin["iroha"].transaction(commands), admin["private_key"])
        logging.debug(tx)
        status = send_transaction(tx, net_1)
        logging.debug(status)
        return user

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
            h = self.HASH_FUNCTION(b)
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
        return self.HASH_FUNCTION(obj).hexdigest()

    def _parse_domain_name(self, domain_name):
        """
        Parse the given domain name to interact with the blockchain
        Currently ensures that None values are converted to the default name
        Also ensures a common suffix is applied

        Args:
            domain_name (String or None): The domain name to parse

        Returns:
            String: the domain name to use for interacting with the blockchain
        """

        if domain_name is None:
            domain_name = self.default_domain_name

        if not domain_name.endswith(Custodian.HASHING_DOMAIN_SUFFIX):
            domain_name+=Custodian.HASHING_DOMAIN_SUFFIX

        return domain_name


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
            admin["iroha"].command("CreateDomain", domain_id=domain_name, default_role=self.null_role_name)
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

        domain_name = self._parse_domain_name(domain_name)
        

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
        
        domain_name = self._parse_domain_name(domain_name)

        query = user["iroha"].query("GetAssetInfo", asset_id=f"{h}#{domain_name}")
        query = IrohaCrypto.sign_query(query, user["private_key"])
        logging.debug(query)
        response = connection.send_query(query)
        logging.debug(response)
        #Check if response has an asset id matching the hash we are after
        return response.asset_response.asset.asset_id==f"{h}#{domain_name}"

    @trace
    def get_domain_hashes(self, domain_name=None, connection = net_1):
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
            List or None: A list of all occurrences of assets being added to this domain over the entire chain
                The elements of this list are dictionaries of:
                    height: The height that asset was added
                    hash: The name of that asset (remembering names are hashes)
                    domain: The domain of the asset, for completeness
                    creator_id: The creator of that asset
                    time: The time of creation (may be more useful than height in some cases)
                None if there is no domain (or no hashes in the domain)
        """

        domain_name = self._parse_domain_name(domain_name)
        if self.block_storehouse is not None:
            return self.block_storehouse.get_domain_hashes(domain_name)
    
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