#!/bin/sh
# create container user to match expected environment

if [ -z "$USER_UID" ] || [ -z "$USER_GID" ]; then
    exec sh -c "$1"
fi

USER_NAME="builder"
GROUP_NAME="builders"
USER_HOME="/builder"

# Add the host's user and group to the container, and adjust ownership
groupadd -og "$USER_GID" -f "$GROUP_NAME"
useradd -s "/bin/sh" -oN -u "$USER_UID" -g "$USER_GID" -d "$USER_HOME" "$USER_NAME"
mkdir -p "$USER_HOME"
chown "$USER_UID:$USER_GID" "$USER_HOME"
chown -Rf "$USER_UID:$USER_GID" "/scan"
chown -Rf "$USER_UID:$USER_GID" "/cache"

# Drop the root privileges and run provided script using sudo
exec sudo --preserve-env --set-home -u "#$USER_UID" sh -c "$1"
