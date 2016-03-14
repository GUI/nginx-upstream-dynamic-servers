# vi:filetype=perl

use Test::Nginx::Socket;

add_block_preprocessor(sub {
  my $block = shift;
  `echo 'local-data: "use.opendns.com 1 A 208.69.38.205"' > /tmp/nginx_upstream_dynamic_servers_unbound_active_test.conf`;
  `kill -HUP \`cat $ENV{UNBOUND_PID}\``;
  sleep 0.1;
  return $block;
});

no_shuffle();
plan tests => 2 * blocks();

$ENV{TEST_NGINX_RESOLVER} = "127.0.0.1:1982";

$ENV{TEST_NGINX_BASE_HTTP_CONF} = <<_EOC_;
  init_by_lua '
    function set_dns_records(records)
      local file = io.open("/tmp/nginx_upstream_dynamic_servers_unbound_active_test.conf", "w")
      for index, record in pairs(records) do
        file:write("local-data: \\\\"" .. record .. "\\\\"\\\\n")
      end
      file:close()
      os.execute("kill -HUP `cat $ENV{UNBOUND_PID}`")
    end
  ';
_EOC_

$ENV{TEST_NGINX_PRINT_UPSTREAMS_LOCATION} = <<_EOC_;
  location = /print-upstreams {
    content_by_lua '
      local concat = table.concat
      local upstream = require "ngx.upstream"
      local get_servers = upstream.get_servers
      local get_upstreams = upstream.get_upstreams
      local srv_keys={"addr","weight","fail_timeout","backup","down","max_fails"}

      local us = get_upstreams()
      for _, u in ipairs(us) do
        ngx.say("upstream ", u, ":")
        local srvs, err = get_servers(u)
        if not srvs then
          ngx.say("failed to get servers in upstream ", u)
        else
          for _, srv in ipairs(srvs) do
            local first = true
            for _, k in ipairs(srv_keys) do
              local v = srv[k]
              if v then
                if first then
                  first = false
                  ngx.print("  ")
                else
                  ngx.print(", ")
                end
                if type(v) == "table" then
                  table.sort(v)
                  ngx.print(k, " = {", concat(v, ", "), "}")
                else
                  ngx.print(k, " = ", v)
                end
              end
            end
            ngx.print("\\\\n")
          end
        end
      end
    ';
  }
_EOC_

no_long_string();
run_tests();

__DATA__


=== TEST 1: allows nginx to start with an invalid hostname, but places the server in a down state
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server foo.blah resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION
--- request
    GET /print-upstreams
--- response_body
upstream test_upstream:
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1


=== TEST 2: resolves a host with the default port
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server use.opendns.com resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 1 A 128.0.0.12"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 1 A 208.69.38.205"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 208.69.38.205:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 128.0.0.12:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 208.69.38.205:80, weight = 1, fail_timeout = 10, max_fails = 1
--- timeout: 10s


=== TEST 3: resolves a host with a custom port
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server use.opendns.com:8080 resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 1 A 128.0.0.70"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 1 A 208.69.38.205"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 208.69.38.205:8080, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 128.0.0.70:8080, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 208.69.38.205:8080, weight = 1, fail_timeout = 10, max_fails = 1
--- timeout: 10s


=== TEST 4: IP given
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server 10.10.10.10 resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 10.10.10.10:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 10.10.10.10:80, weight = 1, fail_timeout = 10, max_fails = 1


=== TEST 5: IPv6 given
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server [fe80::0202:b3ff:fe1e:8329] resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = [fe80::0202:b3ff:fe1e:8329]:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = [fe80::0202:b3ff:fe1e:8329]:80, weight = 1, fail_timeout = 10, max_fails = 1


=== TEST 6: IPv6 with port given
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server [fe80::0202:b3ff:fe1e:8329]:8081 resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = [fe80::0202:b3ff:fe1e:8329]:8081, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = [fe80::0202:b3ff:fe1e:8329]:8081, weight = 1, fail_timeout = 10, max_fails = 1


=== TEST 7: fails to start if the http level resolver is missing and a server is present
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    upstream test_upstream {
      server use.opendns.com resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION
--- must_die
--- error_log
resolver must be defined

=== TEST 8: starts if the http level resolver is missing and a server is not present
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    upstream test_upstream {
      server use.opendns.com;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION
--- request
    GET /print-upstreams
--- response_body
upstream test_upstream:
  addr = 208.69.38.205:80, weight = 1, fail_timeout = 10, max_fails = 1


=== TEST 9: updates the domain's resolved IP while running
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server use.opendns.com resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 60 A 128.0.0.2"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 208.69.38.205:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 128.0.0.2:80, weight = 1, fail_timeout = 10, max_fails = 1
--- timeout: 5s


=== TEST 10: doesn't refresh the IP address until the specified TTL expires
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server use.opendns.com resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        set_dns_records({"use.opendns.com 15 A 128.0.0.2"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 15 A 128.3.3.3"})
        ngx.sleep(3)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        ngx.sleep(3)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        ngx.sleep(3)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        ngx.sleep(8)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 128.0.0.2:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 128.0.0.2:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 128.0.0.2:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 128.0.0.2:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 128.3.3.3:80, weight = 1, fail_timeout = 10, max_fails = 1
--- timeout: 30s


=== TEST 11: brings unresolvable domains up if they begin to resolve
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server foo.blah resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"foo.blah 60 A 127.5.5.5"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
upstream test_upstream:
  addr = 127.5.5.5:80, weight = 1, fail_timeout = 10, max_fails = 1
--- timeout: 5s


=== TEST 12: takes servers down if resolving fails
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server foo.blah resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        set_dns_records({"foo.blah 1 A 127.5.5.5"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 127.5.5.5:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
--- timeout: 5s


=== TEST 13: handles ongoing changes to a domain name
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server use.opendns.com resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 1 A 127.0.0.10"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 1 A 127.0.0.11"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 1 A 127.0.0.12"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"use.opendns.com 1 A 127.0.0.13"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 208.69.38.205:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 127.0.0.10:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 127.0.0.11:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 127.0.0.12:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 127.0.0.13:80, weight = 1, fail_timeout = 10, max_fails = 1
--- timeout: 30s


=== TEST 14: adds multiple servers if the domain returns multiple IPs
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server multi.blah resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        set_dns_records({
          "multi.blah 60 A 127.1.1.100",
          "multi.blah 60 A 127.1.1.101",
          "multi.blah 60 A 127.1.1.102",
          "multi.blah 60 A 127.1.1.103",
        })
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = {127.1.1.100:80, 127.1.1.101:80, 127.1.1.102:80, 127.1.1.103:80}, weight = 1, fail_timeout = 10, max_fails = 1
--- timeout: 5s


=== TEST 15: allows setting the default nginx server attributes
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server use.opendns.com weight=4 max_fails=8 fail_timeout=7 resolve;
      server 127.0.0.8 backup down resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION
--- request
    GET /print-upstreams
--- response_body
upstream test_upstream:
  addr = 208.69.38.205:80, weight = 4, fail_timeout = 7, max_fails = 8
  addr = 127.0.0.8:80, weight = 1, fail_timeout = 10, backup = true, down = true, max_fails = 1


=== TEST 16: resolves multiple upstreams and servers concurrently
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server google.blah resolve;
      server yahoo.blah resolve;
      server bing.blah resolve;
    }

    upstream test_upstream2 {
      server youtube.blah resolve;
      server vimeo.blah resolve;
      server netflix.blah resolve;
    }

    upstream test_upstream3 {
      server a.blah resolve;
      server b.blah resolve;
      server c.blah resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({
          "google.blah  1 A 127.2.2.10",
          "yahoo.blah   1 A 127.2.2.11",
          "bing.blah    1 A 127.2.2.12",
          "youtube.blah 1 A 127.3.3.10",
          "vimeo.blah   1 A 127.3.3.11",
          "netflix.blah 1 A 127.3.3.12",
          "a.blah       1 A 127.4.4.10",
          "b.blah       1 A 127.4.4.11",
          "c.blah       1 A 127.4.4.12",
        })
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({
          "google.blah  1 A 127.2.2.110",
          "yahoo.blah   1 A 127.2.2.111",
          "bing.blah    1 A 127.2.2.112",
          "youtube.blah 1 A 127.3.3.110",
          "vimeo.blah   1 A 127.3.3.111",
          "netflix.blah 1 A 127.3.3.112",
          "a.blah       1 A 127.4.4.110",
          "b.blah       1 A 127.4.4.111",
          "c.blah       1 A 127.4.4.112",
        })
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
upstream test_upstream2:
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
upstream test_upstream3:
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
upstream test_upstream:
  addr = 127.2.2.10:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.2.2.11:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.2.2.12:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream2:
  addr = 127.3.3.10:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.3.3.11:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.3.3.12:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream3:
  addr = 127.4.4.10:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.4.4.11:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.4.4.12:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream:
  addr = 127.2.2.110:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.2.2.111:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.2.2.112:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream2:
  addr = 127.3.3.110:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.3.3.111:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.3.3.112:80, weight = 1, fail_timeout = 10, max_fails = 1
upstream test_upstream3:
  addr = 127.4.4.110:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.4.4.111:80, weight = 1, fail_timeout = 10, max_fails = 1
  addr = 127.4.4.112:80, weight = 1, fail_timeout = 10, max_fails = 1
--- timeout: 10s


=== TEST 17: successfully proxies requests and deals with IP changes with keepalive enabled
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    server {
      listen 1983;
      server_name _;

      location / {
        return 200 "proxied";
      }
    }

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      keepalive 30;
      server local.blah:1983 resolve;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test-proxy {
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_pass http://test_upstream;
    }

    location = /test {
      content_by_lua '
        ngx.print(ngx.location.capture("/print-upstreams").body)
        ngx.say(ngx.location.capture("/test-proxy").status)
        set_dns_records({"local.blah 1 A 127.0.0.1"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        local res = ngx.location.capture("/test-proxy")
        ngx.say(res.status)
        ngx.say(res.body)
        set_dns_records({})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        ngx.say(ngx.location.capture("/test-proxy").status)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 127.255.255.255:1983, weight = 1, fail_timeout = 10, down = true, max_fails = 1
502
upstream test_upstream:
  addr = 127.0.0.1:1983, weight = 1, fail_timeout = 10, max_fails = 1
200
proxied
upstream test_upstream:
  addr = 127.255.255.255:1983, weight = 1, fail_timeout = 10, down = true, max_fails = 1
502
--- timeout: 20s

=== TEST 18: do not resolve the IP if the server isn't set to do it
--- http_config
    $TEST_NGINX_BASE_HTTP_CONF

    resolver $TEST_NGINX_RESOLVER;
    upstream test_upstream {
      server foo.blah;
    }
--- config
    $TEST_NGINX_PRINT_UPSTREAMS_LOCATION

    location = /test {
      content_by_lua '
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
        set_dns_records({"foo.blah 1 A 127.5.5.5"})
        ngx.sleep(2.1)
        ngx.print(ngx.location.capture("/print-upstreams").body)
      ';
    }
--- request
    GET /test
--- response_body
upstream test_upstream:
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
upstream test_upstream:
  addr = 127.255.255.255:80, weight = 1, fail_timeout = 10, down = true, max_fails = 1
--- timeout: 5s
