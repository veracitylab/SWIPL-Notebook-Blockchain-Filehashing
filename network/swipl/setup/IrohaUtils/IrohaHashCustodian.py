from IrohaUtils import *
import logging
import hashlib
import threading

class BlockStorehouse():
    """
    A class to track the blocks being placed on the chain, to cache the results of querying blocks
    This will allow for a speed up as we will not need to query the same low height blocks over and over
    """

    @trace
    def __init__(self, hashing_domain_suffix, thread_mode, conn=net_1):
        """
        Set the variables for the blockstore and create a new connection that will not time out

        Args:
            hashing_domain_suffix (String): The suffix to domain names marking a domain holding hashes
            threading (boolean): Set whether threading should be used or not
                If threading is used (True) then a new thread is spawned that subscribes to block updates. Note this can slow down execution!
                If threading is not used (False) then each request to the chain causes the blockstore to update all at once
                    This removes threads but makes a request after a long delay quite slow
            conn (IrohaGrpc, optional): The connection to copy to the block store. Defaults to net_1.
        """

        self.hashing_domain_suffix = hashing_domain_suffix
        self._current_height_lock = threading.Lock()
        self.current_height = 1
        self._world_state_lock = threading.Lock()
        self.world_state = {}
        self.thread_mode = thread_mode
        self._listen_thread=None
        # Create a new connection with no timeout
        self.conn = IrohaGrpc(conn._address)
        # Collect all hashes from genesis until now
        self.collect_hashes()
        if self.thread_mode:
            # Start a thread to continue to listen for new blocks
            self._listen_thread = threading.Thread(target=self.listen_for_blocks)
            # This thread really shouldn't keep anything running if main thread dies
            self._listen_thread.daemon = True
            self._listen_thread.start()
        # If we are not threading, do not start a thread 

    @trace
    def destroy(self):
        """
        Destroy this storehouse, safely cleaning up the threads (if any) and ensuring memory is released

        Returns:
            None: Returns None so we know this blockstore is destroyed
        """
        if self._listen_thread is not None or self._listen_thread.is_alive():
            self.threading = False

        self.world_state = None
        return None

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
                if command.create_asset.domain_id.endswith(self.hashing_domain_suffix):
                    # We have a new hash
                    with self._world_state_lock:
                        if command.create_asset.domain_id not in self.world_state.keys():
                            # We need to make a new entry to our world_state domains
                            self.world_state[command.create_asset.domain_id] = []
                        current_hash = {
                            "hash": command.create_asset.asset_name,
                            "height": self.current_height,
                            "domain": command.create_asset.domain_id,
                            "creator_id": current_creator_id,
                            "time": current_created_time
                        }
                        self.world_state[command.create_asset.domain_id].append(current_hash)
        with self._current_height_lock:
            self.current_height+=1

    @trace
    def collect_hashes(self):
        """
        Collect all the blocks from current_height to most recent in one swoop
        If threading, note that this method blocks execution as the storehouse, and should only be run at start up
            Once this method has completed, then the asynchronous polling can occur

        If not threading, this method is called at each request to allow the storehouse to catch up
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
            # Check if we are still threading
            if not threading:
                # End the thread by leaving loop
                break
            self.parse_block(block)

    def get_domain_hashes(self, domain_name):
        """
        Get the domain hashes from a domain, querying the world_state to avoid querying the chain

        Args:
            domain_name (String): The domain name to check for

        Returns:
            List or None: Either the list of hashes for the required domain or None (if no such domain exists in the world state)
        """

        # At request, if we are not threading, catch up
        if self._listen_thread is None:
            self.collect_hashes()

        # Check if domain name is in the world state, or if there are no hashes in the domain
        if domain_name not in self.world_state.keys() or len(self.world_state[domain_name])==0:
            return None

        with self._world_state_lock:
            result = self.world_state[domain_name]
        return result

class Custodian():
    """
    A class to look after hashes on the block chain
    Offering the ability to get hashes of a file, store hashes on the chain, and find hashes on the chain
    """

    @trace
    def __init__(self, hashing_domain_suffix="-hash", 
            default_domain_name="hashing", 
            hashing_role_name="hash_creator", 
            null_role_name="null_role", 
            blockstore_threading=False,
            hash_function = hashlib.md5):
        """
        Create a new hash custodian, managing storage of hashes on the blockchain
        Use store_hash_on_chain to store a hash in a domain
        Use find_hash_on_chain to check if a hash exists in a domain
        Use get_domain_hashes to get ALL hashes in a domain

        Args:
            hashing_domain_suffix (str, optional): The suffix for domains that store file hashes. Defaults to "-hash".
            default_domain_name (str, optional): The default domain name if no domain is given to store/find a hash. Defaults to "hashing".
            hashing_role_name (str, optional): The default role name for hashing. Defaults to "hash_creator".
            null_role_name (str, optional): The default role name for new domains. Will have no permissions for security. Defaults to "null_role".
            blockstore_threading (bool, optional): Determines if the blockstore (cache for queries) will thread. Defaults to False.
            hash_function (hashlib.hash, optional): The hash function to use in hashing. Please note Iroha assets are capped at 32 characters, so currently only 32 character hash outputs are supported.
                Defaults to hashlib.md5
        """
        
        self.hashing_domain_suffix = hashing_domain_suffix
        self.default_domain_name = default_domain_name
        self.hashing_role_name = hashing_role_name
        self.null_role_name = null_role_name
        self.block_storehouse = BlockStorehouse(self.hashing_domain_suffix, thread_mode=blockstore_threading)
        self.hash_function = hash_function
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
            

    @trace
    def destroy(self):
        """
        Destroy this custodian. Remove the blockstore (if any) and return None
        This is intended to be used if a new custodian is to be created and you want to clean up
        Especially if threads are involved with the blockstore

        Returns:
            None
        """

        self.block_storehouse = self.block_storehouse.destroy()

        return None

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

        if not domain_name.endswith(self.hashing_domain_suffix):
            domain_name+=self.hashing_domain_suffix

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
    def get_domain_hashes(self, domain_name=None):
        """
        Consult the blockstore about the domain in question

        Args:
            user (Dictionary): The user dictionary of the user querying this domain
            domain_name (String or None, optional): The domain name to search for the hash in
                If None then use the users domain instead
                Defaults to None

        Returns:
            List or None: A list of all occurrences of assets being added to this domain over the entire chain
                The elements of this list are dictionaries of:
                    hash: The name of that asset (remembering names are hashes)
                    height: The height that asset was added
                    domain: The domain of the asset, for completeness
                    creator_id: The creator of that asset
                    time: The time of creation (may be more useful than height in some cases)
                None if there is no domain (or no hashes in the domain)
        """

        domain_name = self._parse_domain_name(domain_name)

        return self.block_storehouse.get_domain_hashes(domain_name)