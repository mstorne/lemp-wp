#/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin
apt-get update && apt-get -y upgrade >> /var/log/system-update.log
date >> /var/log/system-update.log
wait ${!}
