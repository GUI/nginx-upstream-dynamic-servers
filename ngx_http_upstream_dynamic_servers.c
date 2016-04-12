#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#define ngx_resolver_node(n)                                                 \
    (ngx_resolver_node_t *)                                                  \
        ((u_char *) (n) - offsetof(ngx_resolver_node_t, node))

typedef struct {
    ngx_pool_t                   *pool;
    ngx_pool_t                   *previous_pool;
    ngx_http_upstream_server_t   *server;
    ngx_http_upstream_srv_conf_t *upstream_conf;
    ngx_str_t                     host;
    in_port_t                     port;
    ngx_event_t                   timer;
} ngx_http_upstream_dynamic_server_conf_t;

typedef struct {
    ngx_resolver_t               *resolver;
    ngx_msec_t                    resolver_timeout;
    ngx_array_t                   dynamic_servers;
    ngx_http_conf_ctx_t          *conf_ctx;
} ngx_http_upstream_dynamic_server_main_conf_t;

static ngx_str_t ngx_http_upstream_dynamic_server_null_route = ngx_string("127.255.255.255");

static void *ngx_http_upstream_dynamic_server_main_conf(ngx_conf_t *cf);

static char *ngx_http_upstream_dynamic_server_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_dynamic_servers_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_upstream_dynamic_servers_init_process(ngx_cycle_t *cycle);
static void ngx_http_upstream_dynamic_servers_exit_process(ngx_cycle_t *cycle);
static void ngx_http_upstream_dynamic_server_resolve(ngx_event_t *ev);
static void ngx_http_upstream_dynamic_server_resolve_handler(ngx_resolver_ctx_t *ctx);
static ngx_resolver_node_t *ngx_resolver_lookup_name(ngx_resolver_t *r, ngx_str_t *name, uint32_t hash);

static ngx_command_t ngx_http_upstream_dynamic_servers_commands[] = {
    {
        ngx_string("server"),
        NGX_HTTP_UPS_CONF | NGX_CONF_1MORE,
        ngx_http_upstream_dynamic_server_directive,
        0,
        0,
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_upstream_dynamic_servers_module_ctx = {
    NULL,                                         /* preconfiguration */
    NULL,                                         /* postconfiguration */

    ngx_http_upstream_dynamic_server_main_conf,   /* create main configuration */
    NULL,                                         /* init main configuration */

    NULL,                                         /* create server configuration */
    ngx_http_upstream_dynamic_servers_merge_conf, /* merge server configuration */

    NULL,                                         /* create location configuration */
    NULL                                          /* merge location configuration */
};

ngx_module_t ngx_http_upstream_dynamic_servers_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_dynamic_servers_module_ctx,  /* module context */
    ngx_http_upstream_dynamic_servers_commands,     /* module directives */
    NGX_HTTP_MODULE,                                /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    ngx_http_upstream_dynamic_servers_init_process, /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    ngx_http_upstream_dynamic_servers_exit_process, /* exit process */
    NULL,                                           /* exit master */
    NGX_MODULE_V1_PADDING
};

// Overwrite the nginx "server" directive based on its
// implementation of "ngx_http_upstream_server" from
// src/http/ngx_http_upstream.c (nginx version 1.7.7), and should be kept in
// sync with nginx's source code. Customizations noted in comments.
// This make possible use the same syntax of nginx comercial version.
static char * ngx_http_upstream_dynamic_server_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy) {
    // BEGIN CUSTOMIZATION: differs from default "server" implementation
    ngx_http_upstream_srv_conf_t                  *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    ngx_http_upstream_dynamic_server_main_conf_t  *udsmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_dynamic_servers_module);
    ngx_http_upstream_dynamic_server_conf_t       *dynamic_server = NULL;
    // END CUSTOMIZATION

    time_t                       fail_timeout;
    ngx_str_t                   *value, s;
    ngx_url_t                    u;
    ngx_int_t                    weight, max_fails;
    ngx_uint_t                   i;
    ngx_http_upstream_server_t  *us;

#if nginx_version <= 1007002
    if (uscf->servers == NULL) {
        uscf->servers = ngx_array_create(cf->pool, 4,
                                         sizeof(ngx_http_upstream_server_t));
        if (uscf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }
#endif

    us = ngx_array_push(uscf->servers);
    if (us == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(us, sizeof(ngx_http_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = ngx_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NGX_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = ngx_parse_time(&s, 1);

            if (fail_timeout == (time_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (ngx_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        // BEGIN CUSTOMIZATION: differs from default "server" implementation
        if (ngx_strcmp(value[i].data, "resolve") == 0) {
            // Determine if the server given is an IP address or a hostname by running
            // through ngx_parse_url with no_resolve enabled. Only if a hostname is given
            // will we add this to the list of dynamic servers that we will resolve again.

            ngx_memzero(&u, sizeof(ngx_url_t));
            u.url = value[1];
            u.default_port = 80;
            u.no_resolve = 1;
            ngx_parse_url(cf->pool, &u);
            if (!u.addrs || !u.addrs[0].sockaddr) {
                dynamic_server = ngx_array_push(&udsmcf->dynamic_servers);
                if (dynamic_server == NULL) {
                    return NGX_CONF_ERROR;
                }

                ngx_memzero(dynamic_server, sizeof(ngx_http_upstream_dynamic_server_conf_t));
                dynamic_server->server = us;
                dynamic_server->upstream_conf = uscf;

                dynamic_server->host = u.host;
                dynamic_server->port = (in_port_t) (u.no_port ? u.default_port : u.port);
            }

            continue;
        }
        // END CUSTOMIZATION

        goto invalid;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 80;

    // BEGIN CUSTOMIZATION: differs from default "server" implementation
    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        // If the domain fails to resolve on start up, mark this server as down,
        // and assign a static IP that should never route. This is to account for
        // various things inside nginx that seem to expect a server to always have
        // at least 1 IP.
        us->down = 1;

        u.url = ngx_http_upstream_dynamic_server_null_route;
        u.default_port = u.port;
        u.no_resolve = 1;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                                   "%s in upstream \"%V\"", u.err, &u.url);
            }

            return NGX_CONF_ERROR;
        }
    }
    // END CUSTOMIZATION

#if nginx_version >= 1007002
    us->name = u.url;
#endif
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;

not_supported:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return NGX_CONF_ERROR;
}

static void *ngx_http_upstream_dynamic_server_main_conf(ngx_conf_t *cf) {
    ngx_http_upstream_dynamic_server_main_conf_t  *udsmcf;

    udsmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_dynamic_server_main_conf_t));
    if (udsmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&udsmcf->dynamic_servers, cf->pool, 1, sizeof(ngx_http_upstream_dynamic_server_conf_t)) != NGX_OK) {
        return NULL;
    }

    udsmcf->resolver_timeout = NGX_CONF_UNSET_MSEC;

    return udsmcf;
}

static char *ngx_http_upstream_dynamic_servers_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    // If any dynamic servers are present, verify that a "resolver" is setup as
    // the http level.
    ngx_http_upstream_dynamic_server_main_conf_t  *udsmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_dynamic_servers_module);

    if (udsmcf->dynamic_servers.nelts > 0) {
        ngx_http_core_loc_conf_t *core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
#if nginx_version >= 1009011
        if (core_loc_conf->resolver == NULL || core_loc_conf->resolver->connections.nelts == 0) {
#else
        if (core_loc_conf->resolver == NULL || core_loc_conf->resolver->udp_connections.nelts == 0) {
#endif
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "resolver must be defined at the 'http' level of the config");
            return NGX_CONF_ERROR;
        }
        udsmcf->conf_ctx = cf->ctx;
        udsmcf->resolver = core_loc_conf->resolver;
        ngx_conf_merge_msec_value(udsmcf->resolver_timeout, core_loc_conf->resolver_timeout, 30000);
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_upstream_dynamic_servers_init_process(ngx_cycle_t *cycle) {
    ngx_http_upstream_dynamic_server_main_conf_t  *udsmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upstream_dynamic_servers_module);
    ngx_http_upstream_dynamic_server_conf_t       *dynamic_server = udsmcf->dynamic_servers.elts;
    ngx_uint_t i;
    ngx_event_t *timer;
    ngx_uint_t refresh_in;

    for (i = 0; i < udsmcf->dynamic_servers.nelts; i++) {
        timer = &dynamic_server[i].timer;
        timer->handler = ngx_http_upstream_dynamic_server_resolve;
        timer->log = cycle->log;
        timer->data = &dynamic_server[i];

        refresh_in = ngx_random() % 1000;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, cycle->log, 0, "upstream-dynamic-servers: Initial DNS refresh of '%V' in %ims", &dynamic_server[i].host, refresh_in);
        ngx_add_timer(timer, refresh_in);
    }

    return NGX_OK;
}

static void ngx_http_upstream_dynamic_servers_exit_process(ngx_cycle_t *cycle) {
    ngx_http_upstream_dynamic_server_main_conf_t  *udsmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upstream_dynamic_servers_module);
    ngx_http_upstream_dynamic_server_conf_t       *dynamic_server = udsmcf->dynamic_servers.elts;
    ngx_uint_t i;

    for (i = 0; i < udsmcf->dynamic_servers.nelts; i++) {
        if (dynamic_server[i].pool) {
            ngx_destroy_pool(dynamic_server[i].pool);
            dynamic_server[i].pool = NULL;
        }
    }
}

static void ngx_http_upstream_dynamic_server_resolve(ngx_event_t *ev) {
    ngx_http_upstream_dynamic_server_main_conf_t  *udsmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_dynamic_servers_module);
    ngx_http_upstream_dynamic_server_conf_t *dynamic_server;
    ngx_resolver_ctx_t *ctx;

    dynamic_server = ev->data;

    ctx = ngx_resolve_start(udsmcf->resolver, NULL);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "upstream-dynamic-servers: resolver start error for '%V'", &dynamic_server->host);
        return;
    }

    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "upstream-dynamic-servers: no resolver defined to resolve '%V'", &dynamic_server->host);
        return;
    }

    ctx->name = dynamic_server->host;
    ctx->handler = ngx_http_upstream_dynamic_server_resolve_handler;
    ctx->data = dynamic_server;
    ctx->timeout = udsmcf->resolver_timeout;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ev->log, 0, "upstream-dynamic-servers: Resolving '%V'", &ctx->name);
    if (ngx_resolve_name(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "upstream-dynamic-servers: ngx_resolve_name failed for '%V'", &ctx->name);
        ngx_add_timer(&dynamic_server->timer, 1000);
    }
}

static void ngx_http_upstream_dynamic_server_resolve_handler(ngx_resolver_ctx_t *ctx) {
    ngx_http_upstream_dynamic_server_main_conf_t  *udsmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_dynamic_servers_module);
    ngx_http_upstream_dynamic_server_conf_t *dynamic_server;
    ngx_conf_t cf;
    uint32_t hash;
    ngx_resolver_node_t  *rn;
    ngx_pool_t *new_pool;
    ngx_addr_t                      *addrs;

    dynamic_server = ctx->data;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0, "upstream-dynamic-servers: Finished resolving '%V'", &ctx->name);

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0, "upstream-dynamic-servers: '%V' could not be resolved (%i: %s)", &ctx->name, ctx->state, ngx_resolver_strerror(ctx->state));

        ngx_url_t                    u;
        ngx_memzero(&u, sizeof(ngx_url_t));

        // If the domain fails to resolve on start up, assign a static IP that
        // should never route (we'll also mark it as down in the upstream later
        // on). This is to account for various things inside nginx that seem to
        // expect a server to always have at least 1 IP.
        u.url = ngx_http_upstream_dynamic_server_null_route;
        u.default_port = 80;
        u.no_resolve = 1;
        if (ngx_parse_url(ngx_cycle->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
                              "%s in upstream \"%V\"", u.err, &u.url);
            }

            goto end;
        }
        ctx->addr.sockaddr = u.addrs[0].sockaddr;
        ctx->addr.socklen = u.addrs[0].socklen;
        ctx->addr.name = u.addrs[0].name;
        ctx->addrs = &ctx->addr;
        ctx->naddrs = u.naddrs;
    }

    if (ctx->naddrs != dynamic_server->server->naddrs) {
        goto reinit_upstream;
    }

    ngx_uint_t i, j, founded;
    ngx_addr_t *existing_addr;
    for (i = 0; i < ctx->naddrs; i++) {
        founded = 0;

        for (j = 0; j < ctx->naddrs; j++) {
            existing_addr = &dynamic_server->server->addrs[j];
            if (ngx_cmp_sockaddr(existing_addr->sockaddr, existing_addr->socklen, ctx->addrs[i].sockaddr, ctx->addrs[i].socklen, 0) == NGX_OK) {
                founded = 1;
                break;
            }
        }

        if (!founded) {
            goto reinit_upstream;
        }
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0, "upstream-dynamic-servers: No DNS changes for '%V' - keeping existing upstream configuration", &ctx->name);
    goto end;

reinit_upstream:

    new_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ctx->resolver->log);
    if (new_pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0, "upstream-dynamic-servers: Could not create new pool");
        goto end;
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0, "upstream-dynamic-servers: DNS changes for '%V' detected - reinitializing upstream configuration", &ctx->name);

    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.name = "dynamic_server_init_upstream";
    cf.cycle = (ngx_cycle_t *) ngx_cycle;
    cf.pool = new_pool;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.log = ngx_cycle->log;
    cf.ctx = udsmcf->conf_ctx;

    addrs = ngx_pcalloc(new_pool, ctx->naddrs * sizeof(ngx_addr_t));
    ngx_memcpy(addrs, ctx->addrs, ctx->naddrs * sizeof(ngx_addr_t));

    struct sockaddr *sockaddr;
    ngx_addr_t *addr;
    socklen_t socklen;
    for (i = 0; i < ctx->naddrs; i++) {
        addr = &addrs[i];

        socklen = ctx->addrs[i].socklen;

        sockaddr = ngx_palloc(new_pool, socklen);
        ngx_memcpy(sockaddr, ctx->addrs[i].sockaddr, socklen);
        switch(sockaddr->sa_family) {
        case AF_INET6:
            ((struct sockaddr_in6 *)sockaddr)->sin6_port = htons((u_short) dynamic_server->port);
            break;
        default:
            ((struct sockaddr_in *)sockaddr)->sin_port = htons((u_short) dynamic_server->port);
        }

        addr->sockaddr = sockaddr;
        addr->socklen = socklen;

        u_char *p;
        size_t len;

        p = ngx_pnalloc(new_pool, NGX_SOCKADDR_STRLEN);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0, "upstream-dynamic-servers: Error initializing sockaddr");
            ngx_destroy_pool(new_pool);
            goto end;
        }
        len = ngx_sock_ntop(sockaddr, socklen, p, NGX_SOCKADDR_STRLEN, 1);
        addr->name.len = len;
        addr->name.data = p;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0, "upstream-dynamic-servers: '%V' was resolved to '%V'", &ctx->name, &addr->name);
    }

    // If the domain failed to resolve, mark this server as down.
    dynamic_server->server->down = ctx->state ? 1 : 0;
    dynamic_server->server->addrs = addrs;
    dynamic_server->server->naddrs = ctx->naddrs;

    ngx_http_upstream_init_pt init;
    init = dynamic_server->upstream_conf->peer.init_upstream ? dynamic_server->upstream_conf->peer.init_upstream : ngx_http_upstream_init_round_robin;

    if (init(&cf, dynamic_server->upstream_conf) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0, "upstream-dynamic-servers: Error re-initializing upstream after DNS changes");
    }

    if (dynamic_server->previous_pool != NULL) {
        ngx_destroy_pool(dynamic_server->previous_pool);
        dynamic_server->previous_pool = NULL;
    }

    dynamic_server->previous_pool = dynamic_server->pool;
    dynamic_server->pool = new_pool;

end:

    if (ctx->resolver->log->log_level & NGX_LOG_DEBUG_CORE) {
        hash = ngx_crc32_short(ctx->name.data, ctx->name.len);
        rn = ngx_resolver_lookup_name(ctx->resolver, &ctx->name, hash);
        uint32_t refresh_in;
        if (rn != NULL && rn->ttl) {
            refresh_in = (rn->valid - ngx_time()) * 1000;

            if (!refresh_in || refresh_in < 1000) {
                refresh_in = 1000;
            }
        } else {
            refresh_in = 1000;
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0, "upstream-dynamic-servers: Refreshing DNS of '%V' in %ims", &ctx->name, refresh_in);
    }

    ngx_resolve_name_done(ctx);

    if (ngx_exiting) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "upstream-dynamic-servers: worker is about to exit, do not set the timer again");
        return;
    }

    ngx_add_timer(&dynamic_server->timer, 1000);
}

// Copied from src/core/ngx_resolver.c (nginx version 1.7.7).
static ngx_resolver_node_t * ngx_resolver_lookup_name(ngx_resolver_t *r, ngx_str_t *name, uint32_t hash) {
    ngx_int_t rc;
    ngx_rbtree_node_t *node, *sentinel;
    ngx_resolver_node_t *rn;

    node = r->name_rbtree.root;
    sentinel = r->name_rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        rn = ngx_resolver_node(node);

        rc = ngx_memn2cmp(name->data, rn->name, name->len, rn->nlen);

        if (rc == 0) {
            return rn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /* not found */

    return NULL;
}
