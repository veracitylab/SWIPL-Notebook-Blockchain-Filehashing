# SWIPL Magic File Iroha File Hash Example

## Prerequisites
Ensure that your machine can run the `docker` and `docker-compose` commands.

## Running this project
While in development, running `./manage-network up` will totally rebuild the Docker container image for the `swipl-notebook` container. This is because sometimes using `docker-compose` and `Dockerfile`s can lead to the container not updating between tests. Note that this can be expensive, but should be removed once the image is in a stable state.

After running `./manage-network up`, a log from the `swiplnotebook` container will be printed to the terminal with a link to the Jupyter notebook. This notebook will have a Prolog kernel available.

Notebooks are saved to persistent storage on the host in the `network/swipl/notebooks` directory. 

Using magic file notation (putting `%file: filename.pl` at the top of a Prolog cell), that file will be hashed and stored on the Iroha blockchain running on the Iroha containers. This provides a record of what files were activated and when, which could be used to detect inconsistencies in a Prolog environment.

Using more magic notation (putting `%python` at the top of a cell) you can run Python code in the SWIPL kernel. This is currently VERY poorly implemented and is intended to just be for scripting e.g. creating images from Prolog consultation files.

A log of the blockchain is stored after each new file is stored on the chain. The logs are stored in `network/swipl/notebooks/logs` due to a quirk in how Jupyter notebook kernels run.

## Extra Peculiarities
- To ensure a cell can be updated several times (possibly even reverting to an earlier state) and still be hashed onto the Iroha network, we added a timestamp (Python `time.time_ns()`) in a Prolog comment at the top of each magic file. This ensure each time a file is created the hash will be different (up to miniscule collision probabiliy) and thus stored on chain.
- To allow multiple notebooks to be opened in a single session, all Iroha setup on the SWIPL-notebook container happens *before* the notebook is run. This includes creating a new Iroha user, creating the role, defining permissions, and creating the domain. The user data is stored (using pickle) into a file so every opened notebook can get a copy and send file hashes to Iroha.
    - The Iroha setup means this container has access to the admin Iroha user. This should not be used in a production environment, but then again neither should any of this network as Iroha is not primarily designed for storing file hashes, and is used in 8this proof of concept code repository* only as a convenience.
