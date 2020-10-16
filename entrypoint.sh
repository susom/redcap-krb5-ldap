#!/bin/sh

#/usr/bin/caddy --conf /etc/Caddyfile --log stdout
service apache2 start
/usr/sbin/cron -f -l 8