# Name

lua-resty-redis_cluster - lua redis cluster client driver implement for the ngx_lua based on the cosocket API
# Status

This library is considered production ready.
# Description

This Lua library is a redis cluster client driver implement for the ngx_lua nginx module:
# Synopsis

```
local conf = {
    name    = "test",
    servers = {
        { "127.0.0.1", 7000 },
        { "127.0.0.1", 7001 },
        { "127.0.0.1", 7002 },
        { "127.0.0.1", 7003 },
        { "127.0.0.1", 7004 },
        { "127.0.0.1", 7005 },
    },
    password        = "",
    timeout         = 3000,
    idle_timeout    = 1000,
    pool_size       = 200,
}

local cjson = require "cjson"
local redis_cluster = require "resty.redis_cluster"

local credis = redis_cluster:new(conf)

credis:init_pipeline()
credis:mset('a', 1, 'b', 2, 'c', 3)
credis:msetnx('a1', 1, 'b2', 2, 'c3', 3)
credis:mget('a1','b2','c3')
credis:del('a1','b2','c3')
local res, err = credis:commit_pipeline()

ngx.say(cjson.encode(res))
```
# Requires

1. Lua Bit Operations Module, see:[http://bitop.luajit.org/](http://bitop.luajit.org/ "http://bitop.luajit.org/")
2. lua-resty-redis: [https://github.com/openresty/lua-resty-redis](https://github.com/openresty/lua-resty-redis "https://github.com/openresty/lua-resty-redis")
# TODO

# See Also

