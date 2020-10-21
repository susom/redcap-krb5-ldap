#!/bin/sh

#/usr/bin/caddy --conf /etc/Caddyfile --log stdout
service apache2 start;
/usr/sbin/cron -f -l 8;

kinit -kt /etc/krb5kdc/krb5.keytab service/irt-webtools@stanford.edu ; chown www-data:www-data /tmp/krb5cc_0; klist > /var/log/krb5.log