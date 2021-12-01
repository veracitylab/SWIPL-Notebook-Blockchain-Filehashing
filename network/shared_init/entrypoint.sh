#!/bin/sh

cp /opt/init/genesis.block /opt/iroha_data
cp /opt/init/startup.sh /opt/iroha_data
cd /opt/iroha_data
bash /opt/iroha_data/startup.sh
