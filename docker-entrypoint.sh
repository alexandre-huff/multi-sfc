#!/usr/bin/env bash
set -e

if [ "$1" = "multisfc" ]; then

    if [ -e "/usr/sbin/shibd" ]; then
        service shibd start
    fi

    if [ -e "/usr/sbin/apache2" ]; then
        chown -R www-data:www-data repository
        rm -f /var/run/apache2/apache2.pid
        rm -f /var/run/apache2/wsgi*.sock
        exec /usr/sbin/apache2ctl -DFOREGROUND
    else
        # if apache is not installed we run the Flask server directly,
        # which means that the Multi-SFC API does not have federated authentication
        # While no auth is required from client applications, drivers can still require auth
        exec ./server.py
    fi

fi

exec "$@"
