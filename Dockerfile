FROM php:7.3-apache

#ADD webtools-redcap-ldap /

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
    libmemcached11 libmemcachedutil2 build-essential libmemcached-dev libz-dev libfontconfig1 libxrender1 libxext6 libxi6 openssl libssl-dev \
    libmemcached-tools \
    # MySql
    && docker-php-ext-install -j$(nproc) mysqli pdo_mysql opcache \
    # Other
    && docker-php-ext-install -j$(nproc) gettext zip \
    && docker-php-ext-configure gd --with-freetype-dir=/usr/include/ --with-jpeg-dir=/usr/include/ \
    && docker-php-ext-install -j$(nproc) gd \
    # Clean
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/*
#RUN composer global require hirak/prestissimo && composer install


# *********************** LDAP modules  ***********************************

RUN apt-get update \
     && ln -s /usr/include/sasl/sasl.h /usr/lib/x86_64-linux-gnu/sasl.h \
     && apt-get install libldap2-dev -y \
     && rm -rf /var/lib/apt/lists/* \
     && docker-php-ext-configure ldap --with-libdir=lib/x86_64-linux-gnu --with-ldap-sasl  \
     && docker-php-ext-install ldap

# *********************** END LDAP modules  ***********************************


#install composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

#install krb5
#RUN dpkg-reconfigure krb5-kdc

# install and configure x-debug when running for first time then create xdebug.ini
RUN yes | pecl install xdebug \
    && echo "zend_extension=$(find /usr/local/lib/php/extensions/ -name xdebug.so)" > /usr/local/etc/php/conf.d/xdebug.ini \
    && echo "xdebug.remote_enable=on" >> /usr/local/etc/php/conf.d/xdebug.ini \
    && echo "xdebug.remote_autostart=off" >> /usr/local/etc/php/conf.d/xdebug.ini


EXPOSE 80
ADD webtools-redcap-ldap /var/www/html/webtools/redcap-ldap

COPY krb5.conf /etc/

COPY krb5.keytab /etc/


COPY krb5cc_ldap.new /etc/

RUN printf '#!/bin/sh\nexit 0' > /usr/sbin/policy-rc.d

COPY docker/000-default.conf /etc/apache2/sites-available/000-default.conf
RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini && \
    chown -R www-data:www-data /var/www/html/ && \
    echo "<?php echo phpinfo(); ?>" >> /var/www/html/index.php && \
    mkdir /var/log/webtools && \
    chown -R www-data:www-data /var/log/webtools && \
    a2enmod rewrite
