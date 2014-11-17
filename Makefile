export PATH := $(PWD)/t/build/sbin:$(PWD)/t/build/bin:$(PATH)
export PERL5LIB := $(PWD)/t/build/lib/perl5
export UNBOUND_PID := $(PWD)/t/build/etc/unbound/unbound.pid

nginx=nginx-1.7.7
nginx_url=http://nginx.org/download/$(nginx).tar.gz

clean:
	rm -rf t/build t/servroot t/tmp

test: t/build/lib/perl5 t/build/sbin/unbound t/build/sbin/nginx
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
	$< -L t/build --notest https://github.com/openresty/test-nginx/archive/8d5c8668364251cdae01ccf1ef933d80b642982d.tar.gz
	touch $@

t/tmp/unbound-1.4.22.tar.gz: | t/tmp
	curl -o $@ "http://unbound.net/downloads/unbound-1.4.22.tar.gz"

t/tmp/unbound-1.4.22: t/tmp/unbound-1.4.22.tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/unbound-1.4.22/Makefile: | t/tmp/unbound-1.4.22
	cd t/tmp/unbound-1.4.22 && ./configure --prefix=$(PWD)/t/build
	touch $@

t/tmp/unbound-1.4.22/unbound: t/tmp/unbound-1.4.22/Makefile
	cd t/tmp/unbound-1.4.22 && make
	touch $@

t/build/sbin/unbound: t/tmp/unbound-1.4.22/unbound
	cd t/tmp/unbound-1.4.22 && make install
	touch $@

t/tmp/LuaJIT-2.0.3.tar.gz: | t/tmp
	curl -o $@ "http://luajit.org/download/LuaJIT-2.0.3.tar.gz"

t/tmp/LuaJIT-2.0.3: t/tmp/LuaJIT-2.0.3.tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/LuaJIT-2.0.3/src/luajit: | t/tmp/LuaJIT-2.0.3
	cd t/tmp/LuaJIT-2.0.3 && make PREFIX=$(PWD)/t/build
	touch $@

t/build/bin/luajit: t/tmp/LuaJIT-2.0.3/src/luajit
	cd t/tmp/LuaJIT-2.0.3 && make install PREFIX=$(PWD)/t/build
	touch $@

t/tmp/lua-nginx-module-0.9.13rc1.tar.gz: | t/tmp
	curl -Lo $@ "https://github.com/openresty/lua-nginx-module/archive/v0.9.13rc1.tar.gz"

t/tmp/lua-nginx-module-0.9.13rc1: t/tmp/lua-nginx-module-0.9.13rc1.tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/lua-upstream-nginx-module-0.02.tar.gz: | t/tmp
	curl -Lo $@ "https://github.com/openresty/lua-upstream-nginx-module/archive/v0.02.tar.gz"

t/tmp/lua-upstream-nginx-module-0.02: t/tmp/lua-upstream-nginx-module-0.02.tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/$(nginx).tar.gz: | t/tmp
	curl -o $@ $(nginx_url)

t/tmp/$(nginx): t/tmp/$(nginx).tar.gz
	tar -C t/tmp -xf $<
	touch $@

t/tmp/$(nginx)/.patches-applied: | t/tmp/$(nginx)
	curl https://raw.githubusercontent.com/openresty/no-pool-nginx/master/$(nginx)-no_pool.patch | patch -d t/tmp/$(nginx) -p1 --quiet
	touch $@

t/tmp/$(nginx)/Makefile: config | t/tmp/$(nginx) t/tmp/$(nginx)/.patches-applied t/build/bin/luajit t/tmp/lua-nginx-module-0.9.13rc1 t/tmp/lua-upstream-nginx-module-0.02
	cd t/tmp/$(nginx) && env \
		LUAJIT_LIB=$(PWD)/t/build/lib \
		LUAJIT_INC=$(PWD)/t/build/include/luajit-2.0 \
		./configure \
		--prefix=$(PWD)/t/build \
		--with-debug \
		--with-ipv6 \
		--add-module=$(PWD)/t/tmp/lua-nginx-module-0.9.13rc1 \
		--add-module=$(PWD)/t/tmp/lua-upstream-nginx-module-0.02 \
		--add-module=$(PWD) \
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

t/tmp/$(nginx)/objs/nginx: t/tmp/$(nginx)/Makefile *.c
	cd t/tmp/$(nginx) && make

t/build/sbin/nginx: t/tmp/$(nginx)/objs/nginx
	cd t/tmp/$(nginx) && make install
