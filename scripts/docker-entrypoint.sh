#!/bin/bash
set -e

ZEROCLAW_USER="65532"
ZEROCLAW_GROUP="65532"
DATA_DIR="/zeroclaw-data"

# Fix permissions on mounted volume if running as root
if [ "$(id -u)" = "0" ]; then
    echo "Running as root, fixing permissions on $DATA_DIR..."

    # Create group if it doesn't exist
    getent group "$ZEROCLAW_GROUP" > /dev/null 2>&1 || groupadd -g "$ZEROCLAW_GROUP" zeroclaw

    # Create user if it doesn't exist
    id -u "$ZEROCLAW_USER" > /dev/null 2>&1 || useradd -u "$ZEROCLAW_USER" -g "$ZEROCLAW_GROUP" -s /bin/bash -m zeroclaw

    # Fix ownership of data directory
    chown -R "$ZEROCLAW_USER:$ZEROCLAW_GROUP" "$DATA_DIR"

    echo "Permissions fixed. Switching to user $ZEROCLAW_USER..."
    exec gosu "$ZEROCLAW_USER" "$@"
fi

# If not root, just run the command
exec "$@"
