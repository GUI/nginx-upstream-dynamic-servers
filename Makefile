export PATH := $(PWD)/t/build/sbin:$(PWD)/t/build/bin:$(PATH)
export PERL5LIB := $(PWD)/t/build/lib/perl5
export UNBOUND_PID := $(PWD)/t/build/etc/unbound/unbound.pid

unbound_version=1.6.7
lua_jit_version=2.1.0-beta3
lua_nginx_module_version=0.10.11
lua_upstream_nginx_module_version=0.07
nginx_version=1.13.6
nginx_no_pool_version=1.9.15
nginx_url=http://nginx.org/download/nginx-$(nginx_version).tar.gz

clean:
	rm -rf t/build t/servroot t/tmp

prepare: t/build/lib/perl5 t/build/sbin/unbound t/build/sbin/nginx

test: prepare
	echo "" > /tmp/nginx_upstream_dynamic_servers_unbound_active_test.conf
	echo "" > /tmp/unbound.log
	if [ -f $(UNBOUND_PID) ] && ps -p `cat $(UNBOUND_PID)` > /dev/null; then kill -QUIT `cat $(UNBOUND_PID)`; fi
	sleep 0.2
	env PATH=$(PATH) unbound -c $(PWD)/t/unbound/unbound.conf -vvv
	env PATH=$(PATH) PERL5LIB=$(PERL5LIB) UNBOUND_PID=$(UNBOUND_PID) LD_LIBRARY_PATH=$(PWD)/t/build/lib:$(LD_LIBRARY_PATH) prove
	STATUS=$$?
	if [ -f $(UNBOUND_PID) ] && ps -p `cat $(UNBOUND_PID)` > /dev/null; then kill -QUIT `cat $(UNBOUND_PID)`; fi
	exit $$STATUS

grind:
	env TEST_NGINX_USE_VALGRIND=1 TEST_NGINX_SLEEP=5 $(MAKE) test

t/tmp:
	mkdir -p $@
	touch $@

t/tmp/cpanm: | t/tmp
	curl -o $@ -L http://cpanmin.us
	chmod +x $@
	touch $@

t/build/lib/perl5: t/tmp/cpanm
	$< -L t/build --notest LWP::Protocol::https
	$< -L t/build --notest https://github.com/openresty/test-nginx/archive/ddb1b46b2757382fc5b311c1874d1e9306fc6f59.tar.gz
	touch $@

t/tmp/unbound-$(unbound_version).tar.gz: | t/tmp
	curl -o $@ "http://unbound.net/downloads/unbound-$(unbound_version).tar.gz"

t/tmp/unbound-$(unbound_version): t/tmp/unbound-$(unbound_version).tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/unbound-$(unbound_version)/Makefile: | t/tmp/unbound-$(unbound_version)
	cd t/tmp/unbound-$(unbound_version) && ./configure --prefix=$(PWD)/t/build
	touch $@

t/tmp/unbound-$(unbound_version)/unbound: t/tmp/unbound-$(unbound_version)/Makefile
	cd t/tmp/unbound-$(unbound_version) && make
	touch $@

t/build/sbin/unbound: t/tmp/unbound-$(unbound_version)/unbound
	cd t/tmp/unbound-$(unbound_version) && make install
	touch $@

t/tmp/LuaJIT-$(lua_jit_version).tar.gz: | t/tmp
	curl -o $@ "http://luajit.org/download/LuaJIT-$(lua_jit_version).tar.gz"

t/tmp/LuaJIT-$(lua_jit_version): t/tmp/LuaJIT-$(lua_jit_version).tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/LuaJIT-$(lua_jit_version)/src/luajit: | t/tmp/LuaJIT-$(lua_jit_version)
	cd t/tmp/LuaJIT-$(lua_jit_version) && make PREFIX=$(PWD)/t/build
	touch $@

t/build/bin/luajit: t/tmp/LuaJIT-$(lua_jit_version)/src/luajit
	cd t/tmp/LuaJIT-$(lua_jit_version) && make install PREFIX=$(PWD)/t/build
	touch $@

t/tmp/lua-nginx-module-$(lua_nginx_module_version).tar.gz: | t/tmp
	curl -Lo $@ "https://github.com/openresty/lua-nginx-module/archive/v$(lua_nginx_module_version).tar.gz"

t/tmp/lua-nginx-module-$(lua_nginx_module_version): t/tmp/lua-nginx-module-$(lua_nginx_module_version).tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/lua-upstream-nginx-module-$(lua_upstream_nginx_module_version).tar.gz: | t/tmp
	curl -Lo $@ "https://github.com/openresty/lua-upstream-nginx-module/archive/v$(lua_upstream_nginx_module_version).tar.gz"

t/tmp/lua-upstream-nginx-module-$(lua_upstream_nginx_module_version): t/tmp/lua-upstream-nginx-module-$(lua_upstream_nginx_module_version).tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/nginx-$(nginx_version).tar.gz: | t/tmp
	curl -o $@ $(nginx_url)

t/tmp/nginx-$(nginx_version): t/tmp/nginx-$(nginx_version).tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/nginx-$(nginx_no_pool_version)-no_pool.patch: | t/tmp
	curl -o $@ https://raw.githubusercontent.com/openresty/no-pool-nginx/master/nginx-$(nginx_no_pool_version)-no_pool.patch

t/tmp/nginx-$(nginx_version)/.patches-applied: | t/tmp/nginx-$(nginx_version) t/tmp/nginx-$(nginx_no_pool_version)-no_pool.patch
	cat t/tmp/nginx-$(nginx_no_pool_version)-no_pool.patch | sed "s,.*nginx_version.*, `cat t/tmp/nginx-$(nginx_version)/src/core/nginx.h | grep nginx_version`," | sed 's,"$(nginx_no_pool_version),"$(nginx_version),' | patch -d t/tmp/nginx-$(nginx_version) -p1 --quiet
	touch $@

t/tmp/nginx-$(nginx_version)/Makefile: config | t/tmp/nginx-$(nginx_version) t/tmp/nginx-$(nginx_version)/.patches-applied t/build/bin/luajit t/tmp/lua-nginx-module-$(lua_nginx_module_version) t/tmp/lua-upstream-nginx-module-$(lua_upstream_nginx_module_version)
	cd t/tmp/nginx-$(nginx_version) && env \
		LUAJIT_LIB=$(PWD)/t/build/lib \
		LUAJIT_INC=$(PWD)/t/build/include/luajit-2.1 \
		./configure \
		--prefix=$(PWD)/t/build \
		--with-debug \
		--with-ipv6 \
		--add-module=$(PWD)/t/tmp/lua-nginx-module-$(lua_nginx_module_version) \
		--add-module=$(PWD)/t/tmp/lua-upstream-nginx-module-$(lua_upstream_nginx_module_version) \
		--add-module=$(PWD) \
		--with-stream \
		--with-stream_ssl_module \
		--without-http_charset_module \
		--without-http_userid_module \
		--without-http_auth_basic_module \
		--without-http_autoindex_module \
		--without-http_geo_module \
		--without-http_split_clients_module \
		--without-http_referer_module \
		--without-http_fastcgi_module \
		--without-http_uwsgi_module \
		--without-http_scgi_module \
		--without-http_memcached_module \
		--without-http_limit_conn_module \
		--without-http_limit_req_module \
		--without-http_empty_gif_module \
		--without-http_browser_module \
		--without-http_upstream_ip_hash_module

t/tmp/nginx-$(nginx_version)/objs/nginx: t/tmp/nginx-$(nginx_version)/Makefile *.c
	cd t/tmp/nginx-$(nginx_version) && make

t/build/sbin/nginx: t/tmp/nginx-$(nginx_version)/objs/nginx
	cd t/tmp/nginx-$(nginx_version) && make install
