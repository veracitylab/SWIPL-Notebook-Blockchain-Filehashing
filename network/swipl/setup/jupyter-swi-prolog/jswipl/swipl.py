import logging
import os
from pyswip import Prolog
from pyswip import Functor
from pyswip.prolog import PrologError
import time
import pickle
from IrohaUtils import *
from pathlib import Path
import re
import redis

import sys
from io import StringIO
import contextlib


db = redis.Redis(host="redis", port=6379)

cell_files_dir = Path(Path.cwd(), "consulted_cells")    # The path to the directory for consulted cells
cell_files_dir.mkdir(mode=755, exist_ok=True)   # If the consulted cells directory doesn't exist, make it

BLOCKCHAIN = 0
REDIS = 0
TIMESTAMPING = 1
LOGGING_LEVEL = 20 #INFO level is 20
logging.basicConfig(level=LOGGING_LEVEL)
logging.info(f"\n{BLOCKCHAIN=}\n{REDIS=}\n{TIMESTAMPING=}\n{LOGGING_LEVEL=}")
DEFAULT_LIMIT = 10
user=None
custodian = IrohaHashCustodian.Custodian(blockstore_threading=False)
with open("/notebooks/iroha_connection/user_data.pkl", "rb") as user_data:
    user = pickle.load(user_data)
logging.debug(user)

magic_python_local_vars = {}
magic_python_global_vars = {}

def format_value(value):
    output = ""
    if isinstance(value, list):
        output = "[ " + ", ".join([format_value(val) for val in value]) + " ]"
    elif isinstance(value, Functor) and value.arity == 2:
        output = "{0}{1}{2}".format(value.args[0], value.name, value.args[1])
    else:
        output = "{}".format(value)

    return output

def format_result(result):
    result = list(result)

    if len(result) == 0:
        return "false."

    if len(result) == 1 and len(result[0]) == 0:
        return "true."

    output = ""
    for res in result:
        tmpOutput = []
        for var in res:
            tmpOutput.append(var + " = " + format_value(res[var]))
        output += ", ".join(tmpOutput) + " ;\n"
    output = output[:-3] + " ."

    return output

@contextlib.contextmanager
def stdoutIO(stdout=None):
    old = sys.stdout
    if stdout is None:
        stdout = StringIO()
    sys.stdout = stdout
    yield stdout
    sys.stdout = old

def magic_set_environment_vars(code):
    global BLOCKCHAIN
    global REDIS
    global TIMESTAMPING
    global LOGGING_LEVEL
    output = []
    for line in code.split("\n"):
        line = line.strip().upper()
        # For reference later
        line_end = line[line.find("=")+1:]
        logging.debug(line)
        try:
            if line.startswith("BLOCKCHAIN="):
                BLOCKCHAIN=int(line_end)
                output.append(f"SET ENV {BLOCKCHAIN=}")
            if line.startswith("REDIS="):
                REDIS=int(line_end)
                output.append(f"SET ENV {REDIS=}")
            if line.startswith("TIMESTAMPING="):
                TIMESTAMPING=int(line_end)
                output.append(f"SET ENV {TIMESTAMPING=}")
            if line.startswith("LOGGING_LEVEL="):
                LOGGING_LEVEL=int(line_end)
                output.append(f"SET ENV {LOGGING_LEVEL=}")
                logging.getLogger().setLevel(LOGGING_LEVEL)
            logging.debug(output)
        except ValueError:
            return ["ERROR: Environment variable must be set to an integer", f"{line_end} is not an integer"], False
    return output, True

def magic_consult_file(code):
    output = []
    prolog = Prolog()
    if not REDIS:
        return f"Cannot consult with REDIS being set! Current {REDIS=}", False
    for line in code.split("\n"):
        # Ignore any comments or blank lines
        if line == "" or line[0] == "%": continue
        # Find the hash and domain name in the redis database
        result = db.get(line)
        # If the specified hash does not exist, the returned value is None
        if result is None: output.append(f"{line} not found in Redis!")
        result = result.decode()
        logging.debug(f"{line}: {result}")

        # Find the file name we should save this prolog as
        try:
            sections = line.split("@")
            # Ensure that we have two parts, one before and one after the @
            if len(sections) != 2: 
                logging.debug("Consulted hash has wrong sections on @ split")
                raise TypeError
            domain_data = sections[1].split("-")
            # Ensure we have exactly three sections in the domain data
            # Username, file name, hashing suffix
            if len(domain_data) != 3: 
                logging.debug("Consulted hash has wrong sections on - split")
                raise TypeError
            cell_file_name = domain_data[1]+".pl"
        except TypeError:
            logging.debug(f"ERROR: {line} not of correct format to consult")
            output.append(f"ERROR: {line} not of correct format of <hash>@<username>-<filename>-hash")
            continue
        
        # With file name in hand we can save prolog and consult file
        path = Path(cell_files_dir, cell_file_name)
        try:
            f = open(path, "w+")
            logging.info(f"Write consulted file {cell_file_name}")
            f.write(result)    
            output.append(f"{line}\n{result}\n{'-'*80}")
        finally:
            f.close()
            prolog.consult(f.name)
        output.append(f"Successfully consulted {cell_file_name}\n{'-'*80}\n")
    return output, True

def magic_python_exec(code):
    global magic_python_local_vars
    global magic_python_global_vars
    output = []
     # Execute each line in turn, ignoring the first (%PYTHON)
    code = "\n".join(code.split("\n")[1:])
    with stdoutIO() as s:
    # Handle errors being thrown out the wazoo
        try:
            # Execute this line with the local dictionary context
            exec(code, magic_python_global_vars, magic_python_local_vars)
        except Exception as e:
            output.append(f"ERROR: '{e}'")
    line_out = s.getvalue().strip()
    if len(line_out)>0:
        output.append(line_out)
    return output, True

def exec_prolog_code(code):
    prolog = Prolog()
    cell_file_name = "cell.pl"  # The default consultation cell name, used if no %file is used
    tmp = ""    # Temporary string to house working
    clauses = []    # A list of clauses from this cell, ignoring queries and comments
    isQuery = False # Boolean to check if a line is a query
    output = []
    ok = True
    for line in code.split("\n"):   
        line = line.strip()
        match = re.fullmatch(r"%\s*[Ff]ile:\s*(\w+.*)", line) # Check if line is like %file to magic consultation file
        if match is not None:
            # Get the specified name, the first group, after the %file:
            cell_file_name = match.group(1)
            # If the name does NOT end with .pl, make it end so
            if not cell_file_name.endswith(".pl"):
                cell_file_name += ".pl"
        # If the line is empty or a comment, do nothing
        if line == "" or line[0] == "%":
            continue
        # If line is a query, do that instead but don't save it
        if line[:2] == "?-":
            isQuery = True
            line = line[2:]
            tmp += " " + line
        # Line is a clause, save it
        else:
            clauses.append(line)

        # If line a query, and that query is actually executed
        if isQuery and tmp[-1] == ".":
            tmp = tmp[:-1] # Removes "."
            # Define the maximum number of results from the query
            maxresults = DEFAULT_LIMIT
            # If ending in a }, check if there is no matching {
            # Then check if prolog spat an error to tell us the limit is bad
            if tmp[-1] == "}":
                tmp = tmp[:-1] # Removes "}"
                limitStart = tmp.rfind('{')
                if limitStart == -1:
                    ok = False
                    output.append("ERROR: Found '}' before '.' but opening '{' is missing!")
                else:
                    limit = tmp[limitStart+1:]
                    try:
                        maxresults = int(limit)
                    except:
                        ok = False
                        output.append("ERROR: Invalid limit {" + limit + "}!")
                    tmp = tmp[:limitStart]
            # Actually try the query
            try:
                if isQuery:
                    result = prolog.query(tmp, maxresult=maxresults)
                    output.append(format_result(result))
                    result.close()

            except PrologError as error:
                ok = False
                output.append("ERROR: {}".format(error))
            tmp = ""
            isQuery = False
    # If there are some clauses to look at
    if len(clauses) > 0:
        # Get the path
        path = Path(cell_files_dir, cell_file_name)
        try:
            logging.info(f"Write file {cell_file_name}")
            # Open the path and put te clauses into the file
            f = open(path, 'w+')
            # Time stamp the file to ensure hash can be stored
            timestamp = time.time_ns()
            if TIMESTAMPING:
                clauses.insert(0, f"% {timestamp}")
            logging.debug(clauses)
            f.write('\n'.join(clauses))
        finally:
            # Close the file and consult it
            f.close()
            prolog.consult(f.name)
        # If vital to never put hash on twice, check first
        # Iroha does this for us though
        # Get the file hash
        file_hash = custodian.get_file_hash(path)
        file_name = cell_file_name[:cell_file_name.find(".")]
        domain_name = custodian.parse_domain_name(user["name"]+"-"+ file_name)
        if REDIS:
            # Log the hash and domain name into redis
            key = f"{file_hash}@{domain_name}"
            val = '\n'.join(clauses)
            output.append(f"Redis storing {key}")
            logging.debug(f"Redis storing {key} : {val.encode('unicode_escape')}")
            db.set(key, val)
            
        if BLOCKCHAIN:
            if not custodian.find_hash_on_chain(user, custodian.get_file_hash(path)):
                # Get the domain name in the form of {user_name}-{file_name}
                logging.info(f"File {cell_file_name} hash {file_hash} logging on blockchain")
                # Store the hash on chain
                status = custodian.store_hash_on_chain(user, file_hash, domain_name=domain_name)[0]
                logging.info(f"File {cell_file_name} hash {file_hash} logged to domain {domain_name} with response {status}")
                # Log all blocks for debugging
                log_all_blocks("blocks.log")
                output.append(f"File: {cell_file_name}\nTimestamp: {timestamp}\nHash: {file_hash}\nDomain: {domain_name}\nIroha Response: {status}")
    return output, ok

def run(code):
    logging.debug(f"\n{code=}")

    first_line = code.split("\n")[0].strip().upper()
    logging.debug(first_line)


    # Check if the cell is marked by %ENV
    # If it is, set environment variables
    if re.match(r"%\s*ENV.*", first_line):
        return magic_set_environment_vars(code)

    
    # Consult a hash and execute all stored prolog files
    # Looks through the redis database for all hashes
    # If a hash is not available, report this as an error
    if re.match(r"%\s*CONSULT.*", first_line):
        return magic_consult_file(code)

    # If first line specifies magic python do that instead
    if re.match(r"%\s*PYTHON.*", first_line) is not None:
       return magic_python_exec(code)

    # Do prolog instead
    return exec_prolog_code(code)
