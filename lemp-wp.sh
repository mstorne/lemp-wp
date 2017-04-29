#/bin/bash

# http://nginx.org/en/download.html
NGINX_VERSION=1.11.5

# https://github.com/pagespeed/ngx_pagespeed/releases
PAGESPEED_VERSION=latest-stable

# Releases after 1.11.33.4 there will be a PSOL_BINARY_URL file that tells us where to look, until then this is hardcoded
PAGESPEED_PSOL_VERSION=1.11.33.4

# https://github.com/openresty/headers-more-nginx-module/tags
HEADERS_MORE_VERSION=0.31

# https://www.openssl.org/source
OPENSSL_VERSION=1.0.2j

#https://redis.io
REDIS_VERSION=3.2.5

	apt-get update 
	apt-get -y --no-install-recommends install vsftpd wget git-core autoconf automake libtool build-essential zlib1g-dev libpcre3-dev libxslt1-dev libxml2-dev libgd2-xpm-dev libgeoip-dev libgoogle-perftools-dev libperl-dev
	echo "Downloading nginx ${NGINX_VERSION} from http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz ..." && wget -qO - http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz | tar zxf - -C /tmp 
	echo "Downloading headers-more ${HEADERS_MORE_VERSION} from https://github.com/openresty/headers-more-nginx-module/archive/v${HEADERS_MORE_VERSION}.tar.gz ..." && wget -qO - https://github.com/openresty/headers-more-nginx-module/archive/v${HEADERS_MORE_VERSION}.tar.gz | tar zxf - -C /tmp 
	echo "Downloading ngx_pagespeed ${PAGESPEED_VERSION} from https://github.com/pagespeed/ngx_pagespeed/archive/${PAGESPEED_VERSION}.tar.gz..." && wget -qO - https://github.com/pagespeed/ngx_pagespeed/archive/${PAGESPEED_VERSION}.tar.gz | tar zxf - -C /tmp 
	echo "Downloading pagespeed psol ${PAGESPEED_PSOL_VERSION} from https://dl.google.com/dl/page-speed/psol/${PAGESPEED_PSOL_VERSION}.tar.gz..." && wget -qO - https://dl.google.com/dl/page-speed/psol/${PAGESPEED_PSOL_VERSION}.tar.gz | tar xzf  - -C /tmp/ngx_pagespeed-${PAGESPEED_VERSION} 
	echo "Downloading openssl v${OPENSSL_VERSION} from https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz ..." && wget -qO - https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz | tar xzf  - -C /tmp 
	echo "Installing libbrotli (latest) from https://github.com/bagder/libbrotli ..." && git clone https://github.com/bagder/libbrotli /tmp/libbrotli && cd /tmp/libbrotli && ./autogen.sh && ./configure && make && make install
        echo "Downloading ngx-brotli (latest) from https://github.com/google/ngx_brotli ..." && git clone https://github.com/google/ngx_brotli /tmp/ngx_brotli
	cd /tmp/nginx-${NGINX_VERSION}
	./configure \
                --prefix=/etc/nginx  \
		--sbin-path=/usr/sbin/nginx  \
		--conf-path=/etc/nginx/nginx.conf  \
		--error-log-path=/var/log/nginx/error.log \
		--http-log-path=/var/log/nginx/access.log \
		--pid-path=/var/run/nginx.pid \
		--lock-path=/var/run/nginx.lock \
		--http-client-body-temp-path=/var/cache/nginx/client_temp \
		--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
		--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp  \
		--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp  \
		--http-scgi-temp-path=/var/cache/nginx/scgi_temp  \
		--with-http_ssl_module  \
		--with-http_realip_module  \
		--with-http_addition_module  \
		--with-http_sub_module  \
		--with-http_dav_module  \
		--with-http_flv_module  \
		--with-http_mp4_module  \
		--with-http_gunzip_module  \
		--with-http_gzip_static_module  \
		--with-http_random_index_module  \
		--with-http_secure_link_module \
		--with-http_stub_status_module  \
		--with-http_auth_request_module  \
		--without-http_autoindex_module \
		--without-http_ssi_module \
		--with-threads  \
		--with-stream  \
		--with-stream_ssl_module  \
		--with-mail  \
		--with-mail_ssl_module  \
		--with-file-aio  \
		--with-http_v2_module \
		--with-cc-opt='-g -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2'  \
		--with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,--as-needed' \
		--with-ipv6 \
		--with-pcre-jit \
		--with-openssl=/tmp/openssl-${OPENSSL_VERSION} \
                --add-module=/tmp/headers-more-nginx-module-${HEADERS_MORE_VERSION} \
		--add-module=/tmp/ngx_pagespeed-${PAGESPEED_VERSION} \
		--add-module=/tmp/ngx_brotli
	make 
	make install
	apt-get purge -yqq automake autoconf libtool git-core build-essential zlib1g-dev libpcre3-dev libxslt1-dev libxml2-dev libgd2-xpm-dev libgeoip-dev libgoogle-perftools-dev libperl-dev
	apt-get autoremove -yqq
	apt-get clean
	rm -Rf /tmp/* /var/tmp/* /var/lib/apt/lists/*

# Set up automatic OS updates
cd /usr/bin
git clone https://github.com/mstorne/lemp-wp.git
chmod +x /usr/bin/lemp/*.sh
echo '0 3 * * * /usr/bin/lemp/ubuntu-update.sh' >> /var/spool/cron/root
echo '@reboot /usr/bin/lemp/ubuntu-update.sh' >> /var/spool/cron/root
wait ${!}

# Add netdata dashboard on port 19999
apt-get update
curl -Ss 'https://raw.githubusercontent.com/firehol/netdata-demo-site/master/install-required-packages.sh' >/tmp/kickstart.sh && bash /tmp/kickstart.sh -i netdata-all
git clone https://github.com/firehol/netdata.git --depth=1
cd netdata
./netdata-installer.sh

# Add nginx in /var/cache
mkdir /var/cache/nginx

# Make new config file for vsftpd
cp /etc/vsftpd.conf /etc/vsftpd.conf.orig

# Install php-fpm and php-mysql etc.
apt-get update
apt-get -y --no-install-recommends install php-fpm php-mysql php-curl php-gd php-mbstring php-mcrypt php-xml php-xmlrpc

# Install MySQL

apt-get -y --no-install-recommends install mysql-server

export DEBIAN_FRONTEND="noninteractive"
sudo debconf-set-selections <<< "mysql-server mysql-server/root_password password rootpassword123"
sudo debconf-set-selections <<< "mysql-server mysql-server/root_password_again password rootpassword123"
sudo apt-get install -y mysql-server-5.6

mysql_secure_installation


# Install WordPress
cd /tmp
curl -O https://wordpress.org/latest.tar.gz
tar xzvf latest.tar.gz
cp /tmp/wordpress/wp-config-sample.php /tmp/wordpress/wp-config.php
mkdir /tmp/wordpress/wp-content/upgrade
cp -a /tmp/wordpress/. /var/www/html
chown -R www-data:www-data /var/www/html
find /var/www/html -type d -exec chmod g+s {} \;
chmod g+w /var/www/html/wp-content
chmod -R g+w /var/www/html/wp-content/themes
chmod -R g+w /var/www/html/wp-content/plugins

apt-get purge -yqq automake autoconf libtool git-core build-essential tcl zlib1g-dev libpcre3-dev libxslt1-dev libxml2-dev libgd2-xpm-dev libgeoip-dev libgoogle-perftools-dev libperl-dev &&
apt-get autoremove -yqq &&
apt-get clean &&
rm -Rf /tmp/* /var/tmp/* /var/lib/apt/lists/*
