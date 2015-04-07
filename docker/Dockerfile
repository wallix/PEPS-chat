# The main peps_chat container

# Based on our generic opa container which has mlstatelibs and node built in.
FROM opa:latest

MAINTAINER MLstate <contact@mlstate.com>

# Download the peps executable
RUN curl -sf -o /tmp/chat.zip -L https://github.com/MLstate/PEPS/releases/download/0.9.9/chat.zip
RUN mkdir -p /chat && cd /chat && unzip -q /tmp/chat.zip
RUN rm /tmp/chat.zip

# We need to add the node modules to the node path
ENV NODE_PATH $NODE_PATH:/chat

# Set this to allow connection to bad certificates
ENV NODE_TLS_REJECT_UNAUTHORIZED 0

# Get global configuration data from PEPS
VOLUME ["/etc/peps"]

# Run the peps_chat executable
# FIXME predefined port, should be taken from /etc/peps/chat/port
EXPOSE 9000

# Add startup scripts (or to /etc/service/peps?)
ADD peps.sh /etc/my_init.d/10chat.sh

# Start the init daemon
CMD ["/sbin/my_init"]
