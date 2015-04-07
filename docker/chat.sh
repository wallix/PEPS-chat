#!/bin/sh
/chat/opa_chat.js \
     --db-remote:opa_chat $MONGOD_PORT_27017_TCP_ADDR:$MONGOD_PORT_27017_TCP_PORT \
     --db-remote:opa_share $MONGOD_PORT_27017_TCP_ADDR:$MONGOD_PORT_27017_TCP_PORT \
     --db-remote:opa_metric $MONGOD_PORT_27017_TCP_ADDR:$MONGOD_PORT_27017_TCP_PORT \
     --port 9000 \
     --host http://localhost:9000
