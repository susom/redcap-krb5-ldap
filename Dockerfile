FROM php:8-apache

#ADD webtools-redcap-ldap /

COPY krb5.conf /etc/krb5kdc/
COPY krb5.conf /etc/

RUN apt-get update -qq && \
    apt-get install -yq --no-install-recommends  \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    git \
    libpng-dev \
    libaio1 \
    libzip-dev \
    libldap2-dev \
    libsasl2-dev \
    sasl2-bin libsasl2-2 libsasl2-modules libsasl2-modules-gssapi-mit ldap-utils krb5-kdc \
    libmemcached11 libmemcachedutil2 build-essential libmemcached-dev libz-dev libfontconfig1 libxrender1 libxext6 libxi6 openssl libssl-dev \
    libmemcached-tools  tzdata cron \
    # Other
    && docker-php-ext-install -j$(nproc) gettext zip \
    && docker-php-ext-configure gd --with-freetype=/usr/include/ --with-jpeg=/usr/include/ \
    && docker-php-ext-install -j$(nproc) gd \
    # Clean
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/*
#RUN composer global require hirak/prestissimo && composer install


# *********************** LDAP modules  ***********************************

RUN apt-get update \
     && ln -s /usr/include/sasl/sasl.h /usr/lib/$(uname -m)-linux-gnu/sasl.h \
     && apt-get install libldap2-dev -y \
     && rm -rf /var/lib/apt/lists/* \
     && docker-php-ext-configure ldap --with-libdir=lib/$(uname -m)-linux-gnu --with-ldap-sasl  \
     && docker-php-ext-install ldap

# *********************** END LDAP modules  ***********************************


#install composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer


# install and configure x-debug when running for first time then create xdebug.ini
#RUN yes | pecl install xdebug \
#    && echo "zend_extension=$(find /usr/local/lib /php/extensions/ -name xdebug.so)" > /usr/local/etc/php/conf.d/xdebug.ini \
#    && echo "xdebug.remote_enable=on" >> /usr/local/etc/php/conf.d/xdebug.ini \
#    && echo "xdebug.remote_autostart=off" >> /usr/local/etc/php/conf.d/xdebug.ini


EXPOSE 80
ADD webtools-redcap-ldap /var/www/html/webtools/redcap-ldap

ADD vendor /var/www/html/vendor

COPY .env /var/www/html

COPY index.php /var/www/html/

COPY krb5.keytab /etc/krb5kdc/

COPY krb5.keytab /etc/krb5kdc/kadm5.keytab


COPY krb5cc_ldap.new /etc/krb5kdc/



RUN printf '#!/bin/sh\nexit 0' > /usr/sbin/policy-rc.d

COPY docker/000-default.conf /etc/apache2/sites-available/000-default.conf
RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini && \
    chown -R www-data:www-data /var/www/html/ && \
    #echo "<?php echo phpinfo(); ?>" >> /var/www/html/index.php && \
    mkdir /var/log/webtools && \
    chown -R www-data:www-data /var/log/webtools && \
    a2enmod rewrite


# CRONJOB


ADD crontab.txt /crontab.txt
RUN /usr/bin/crontab /crontab.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod 777 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

RUN kinit -kt /etc/krb5kdc/krb5.keytab service/irt-webtools@stanford.edu

RUN chown www-data:www-data /tmp/krb5cc_0
