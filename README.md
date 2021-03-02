# nginx-upstream-dynamic-servers

An nginx module to resolve domain names inside upstreams and keep them up to date.

By default, servers defined in nginx upstreams are only resolved when nginx starts. This module provides an additional `resolve` parameter for `server` definitions that can be used to asynchronously resolve upstream domain names. This keeps the upstream definition up to date according to the DNS TTL of each domain names. This can be useful if you want to use upstreams for dynamic types of domain names that may frequently change IP addresses.

This module also allows nginx to start if an upstream contains a defunct domain name that no longer resolves. By default, nginx will fail to start if an upstream server contains an unresolvable domain name. With this module, nginx is still allowed to start with invalid domain names, but an error will be logged and the unresolvable domain names will be marked as down.

## Installation

```sh
./configure --add-module=/path/to/nginx-upstream-dynamic-servers
make && make install
```

## Usage

Use the `server` definition inside your upstreams and specify the `resolve` parameter.

*Note:* A `resolver` must be defined at the `http` level of nginx's config for `resolve` to work.

```
http {
  resolver 8.8.8.8;

  upstream example {
    server example.com resolve;
  }
}
```

## Directives

### server

**Syntax:** `server address [parameters];`  
**Context** `upstream`

Defines a server for an upstream. The module adds the ability to specify a `resolve` parameter. When specified:

- Domain names will be resolved on an ongoing basis and kept up to date according to the TTL of each domain name.
- Unresolvable domain names are considered non-fatal errors (but logged). nginx is allowed to startup if a domain name can't be resolved, but the server is marked as down.

The following parameters can be used (see nginx's [server documentation](http://nginx.org/en/docs/http/ngx_http_upstream_module.html#server) for details):

`weight=number`  
`max_fails=number`  
`fail_timeout=time`  
`backup`  
`down`  
`resolve`  

# Compatibility

Tested and in production on a large website (10+ machines) running nginx 1.12. 

It may work with other versions, but I have not tested it. 

## Incompatibility
Currently only works with round robin and keepalive connections. The system could possibly
be extended to work with other types of connecitons, but I have not tested it. 

## Alternatives

- [proxy_pass + resolver](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass): If you only need to proxy to 1 domain and don't need the additional capabilities of upstreams, nginx's `proxy_pass` can perform resolving at run-time.
- [ngx_upstream_jdomain](http://wiki.nginx.org/HttpUpstreamJdomainModule): An nginx module that asyncronously resolves domain names. The primary differences between jdomain and this module is that this module keeps domain names up to date even if no server traffic is being generated (jdomain requires traffic to each upstream in order to keep it up to date). This module also allows nginx to startup if unresolvable domain names are given.
- [tengine's dynamic_resolve](https://github.com/alibaba/tengine/blob/master/docs/modules/ngx_http_upstream_dynamic.md): If you're using tengine (an nginx fork), there's a new feature (currently unreleased) to support resolving domain names in upstreams at run-time.
- [NGINX Plus](http://nginx.com/resources/admin-guide/load-balancer/#resolve)

## License

nginx-upstream-dynamic-servers is open sourced under the [MIT license](https://github.com/GUI/nginx-upstream-dynamic-servers/blob/master/LICENSE.txt).

## Difference with GUI/nginx-upstream-dynamic-servers: 

* This module resolves issues with fast DNS TTL and keepalive/persistant connections. 
  * S3 has such a TTL scheme.  
    
Ideally, the DNS TTL on an upstream URI should be at least the maximum connection time. 
If this isn't the case, segfaults can occur due to the peer data structure being freed before
the request is finished.

This module adds a reference counting scheme on requests that reference the current resolution. 
Once all requests that are referencing a set of peers have been closed, the peer data is no longer needed
we then ensure that the stored SSL contexts are all freed and free the pool that the peers were allocated
on to ensure that the system does not leak, and that the system does not refrence unallocated memory.


# Future Enhancement
* Some DNS (Like S3) send one balanced DNS, instead of the multitude of servers that are available.  This means that we only get one upstream and it changes every minute or so  (Whatever the TTL is).  Instead, we could supply our own ttl and keep the last N upstreams. 

Something like this: 
```
server domain.dns resolve rotate=5 force_ttl=60;
```

* Make other peer types work as well.  
