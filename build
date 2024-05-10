#!/bin/bash

auto/configure  --without-http_rewrite_module --without-http_gzip_module  --with-debug\
 --add-module=./ngx_http_user_server_module --add-module=./ngx_http_user_server_token_module \
 --add-module=./ngx_http_user_server_key_module --without-http_fastcgi_module \
 --without-mail_pop3_module  --without-mail_imap_module --without-mail_smtp_module\
  --conf-path="./qwe.conf" --prefix=./