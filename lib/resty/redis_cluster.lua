-- Copyright (C) yuewenhu see: https://github.com/hyw97m/redis_cluster
-- Copyright (C) yunfengmeng

local redis        = require "resty.redis"
local bit          = require "bit";
local bxor         = bit.bxor
local band         = bit.band
local lshift       = bit.lshift
local rshift       = bit.rshift
local str_len      = string.len
local str_sub      = string.sub
local concat       = table.concat
local insert       = table.insert
local type         = type
local pairs        = pairs
local pcall        = pcall
local ipairs       = ipairs
local unpack       = unpack
local time         = ngx.time
local ngx_log      = ngx.log
local ERR          = ngx.ERR
local re_match     = ngx.re.match
local timer_at     = ngx.timer.at
local randomseed   = math.randomseed
local random       = math.random
local tostring     = tostring
local sleep        = ngx.sleep
local setmetatable = setmetatable


local crc16tab  = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
}


local function crc16(str)
    local crc = 0
    for i = 1, #str do
        crc = bxor(lshift(crc, 8), crc16tab[band(bxor(rshift(crc, 8), str:byte(i)), 0x00ff) + 1]);
    end

    return crc
end


local function keyhashslot(key)
    local s, e
    local keylen = str_len(key)
    for i = 1, keylen do
        s = i
        if key:byte(s) == 123 then break end
    end

    if s == keylen then
        return band(crc16(key), 0x3fff) + 1
    end

    for i = s + 1, keylen do
        e = i
        if key:byte(e) == 125 then break end
    end

    if e == keylen or e == s + 1 then
        return band(crc16(key), 0x3fff) + 1
    else
        return band(crc16(str_sub(key, s + 1, e - 1)), 0x3fff) + 1
    end
end


local ok, new_tab = pcall(require, "table.new")
if not ok or type(new_tab) ~= "function" then
    new_tab = function (narr, nrec) return {} end
end


redis.add_commands("cluster")


local commands = {
    "append",               --[["auth",]]           --[["bgrewriteaof",]]
    --[["bgsave",]]         "bitcount",             --[["bitop",]]
    "blpop",                "brpop",
    --[["brpoplpush",]]     --[["client",]]         --[["config",]]
    --[["dbsize",]]
    --[["debug",]]          "decr",                 "decrby",
    --[["del",]]            --[["discard",]]        --[["dump",]]
    --[["echo",]]
    --[["eval",]]           --[["exec",]]           "exists",
    "expire",               "expireat",             --[["flushall",]]
    --[["flushdb",]]        "get",                  "getbit",
    "getrange",             "getset",               "hdel",
    "hexists",              "hget",                 "hgetall",
    "hincrby",              "hincrbyfloat",         "hkeys",
    "hlen",
    "hmget",                "hmset",                --[["hscan",]]
    "hset",
    "hsetnx",               "hvals",                "incr",
    "incrby",               "incrbyfloat",          --[["info",]]
    --[["keys",]]
    --[["lastsave",]]       "lindex",               "linsert",
    "llen",                 "lpop",                 "lpush",
    "lpushx",               "lrange",               "lrem",
    "lset",                 "ltrim",                --[["mget",]]
    --[["migrate",]]
    --[["monitor",]]        --[["move",]]           --[["mset",]]
    --[["msetnx",]]         --[["multi",]]          --[["object",]]
    "persist",              "pexpire",              "pexpireat",
    --[["ping",]]           "psetex",               --[["psubscribe",]]
    "pttl",
    --[["publish",]]        --[["punsubscribe",]]   --[["pubsub",]]
    --[["quit",]]
    --[["randomkey",]]      --[["rename",]]         --[["renamenx",]]
    --[["restore",]]
    "rpop",                 --[["rpoplpush",]]      "rpush",
    "rpushx",               "sadd",                 --[["save",]]
    "scan",                 "scard",                --[["script",]]
    --[["sdiff",]]          --[["sdiffstore",]]
    --[["select",]]         "set",                  "setbit",
    "setex",                "setnx",                "setrange",
    --[["shutdown",]]       --[["sinter",]]         --[["sinterstore",]]
    --[["sismember",]]      --[["slaveof",]]        --[["slowlog",]]
    "smembers",             --[["smove",]]          "sort",
    "spop",                 --[["srandmember",]]    "srem",
    "sscan",
    --[["strlen",]]         --[["subscribe",]]      --[["sunion",]]
    --[["sunionstore",]]    --[["sync",]]           --[["time",]]
    "ttl",
    --[["type",]]           --[["unsubscribe",]]    --[["unwatch",]]
    --[["watch",]]          "zadd",                 "zcard",
    "zcount",               "zincrby",              --[["zinterstore",]]
    "zrange",               "zrangebyscore",        "zrank",
    "zrem",                 "zremrangebyrank",      "zremrangebyscore",
    "zrevrange",            "zrevrangebyscore",     "zrevrank",
    --[["zscan",]]
    "zscore",               --[["zunionstore",]]    --[["evalsha"]]
}


local _M = {}

local cache_nodes = {}


local function _connect(self, host, port)
    local red = redis:new()

    if self.config.timeout > 0 then
        red:set_timeout(self.config.timeout)
    end

    local ok, err = red:connect(host, port)
    if not ok then
        ngx_log(ERR, host, ":", port, ", connect err: ", err)
        return nil, err
    end

    if self.config.password ~= "" then
        local ok, err = red:auth(self.config.password)
        if not ok then
            ngx_log(ERR, host, ":", port, ", auth err: ", err)
        end
    end

    return red
end


-- shuffle data
randomseed(tostring(os.time()):reverse():sub(1, 6))
local function _shuffle(t)
    local count = #t
    for i = 1, count do
        local j = random(i, count)
        t[i], t[j] = t[j], t[i]
    end
end


local function _fetch_slots(self)
    if not cache_nodes[self.config.name] then
        cache_nodes[self.config.name] = { nodes = {}, slots = {} }
    end

    if cache_nodes[self.config.name]._lock then
        local ms = random(10, 100) / 1000
        sleep(ms)
        if not cache_nodes[self.config.name]._lock then -- After sleep, maybe it's done
            return true
        end
    end

    cache_nodes[self.config.name]._lock  = time()

    _shuffle(self.config.servers) -- shuffle servers sequence

    local nodes, slots = {}, {}
    for _, server in ipairs(self.config.servers) do
        local red, err = _connect(self, server[1], server[2])
        if red then
            local info, err = red:cluster("slots")
            if err then
                ngx_log(ERR, "get cluster slots err: ", err)
            end

            if info and type(info) == "table" and #info > 0 then
                for i=1, #info do
                    local nodeidx = #nodes + 1
                    local item = info[i]
                    local node = {
                        master = { item[3][1], item[3][2] },
                        slave  = { }
                    }

                    for j = 4, #item do
                        local slaveidx = #node["slave"] + 1
                        node["slave"][slaveidx] = { item[j][1], item[j][2] }
                    end

                    for slot = item[1], item[2] do
                        slots[slot + 1] = nodeidx
                    end
                    nodes[nodeidx] = node
                end

                cache_nodes[self.config.name] = { nodes = nodes, slots = slots }

                red:set_keepalive(self.config.idle_timeout, self.config.pool_size)
                return true
            end
        end
    end

    return nil, "cluster init failed"
end


-- async fetch slots
local function _async_fetch_slots(self)

    local handler = function(premature)
        if premature then
            return
        end
        _fetch_slots(self)
    end

    local ok, err = timer_at(0, handler)
    if not ok then
        ngx_log(ERR, "failed to create timer: ", err)
        return
    end
end


-- get node by nodeidx
local function _get_node(self, nodeidx)
    local nodes = cache_nodes[self.config.name]["nodes"]
    local node  = nodes[nodeidx] or nil
    if not node then
        return nil, "cluster slots moved"
    end
    return node
end


-- fetch node by CRC16 key
-- return nodeidx, node, err
local function _fetch_node(self, key)

    local m, err = re_match(key, "\\{(.+?)\\}", "jo") -- Match Hash Tag
    if m then
        key = m[1]
    end

    local slots   = cache_nodes[self.config.name]["slots"]
    local slot    = keyhashslot(key)
    local nodeidx = slots[slot] or -1

    local node, err = _get_node(self, nodeidx)
    return nodeidx, node, err
end


-- return host, port or nil
local function _parse_slot_moved(err)
    if str_sub(err, 1, 5) == "MOVED" then
        local m, err = re_match(err, "MOVED [0-9]+ ([0-9.]+):([0-9]+)", "jo")
        if m then
            return m[1], m[2]
        end
    end

    return nil
end


-- Direct retry to the server and run cmd
local function _do_retry(self, host, port, cmd, key, ...)
    local red, err = _connect(self, host, port)
    if err then
        return false, err
    end

    local res, err
    if ... then
        res, err = red[cmd](red, key, ...)
    else
        res, err = red[cmd](red, key)
    end

    red:set_keepalive(self.config.idle_timeout, self.config.pool_size)
    return res, err
end


-- return res, err, errcode
-- errcode = 1, connection refused
-- errcode = 2, slot moved
local function _do_cmd(self, cmd, key, ...)

    if self._reqs then -- use pipeline
        if not self[cmd] then
            return false, "cmd not found"
        end

        insert(self._group, { size = 1 })
        insert(self._reqs, { cmd = cmd, key = key, args = { ... } })
        return true
    end

    local _, node, err = _fetch_node(self, key)
    if not node then
        return false, err
    end

    local errcode

    local host, port = node.master[1], node.master[2]
    local red, err   = _connect(self, host, port)
    if err then
        if err == 'connection refused' then
            errcode = 1
        end
        return false, err, errcode
    end

    local res, err = red[cmd](red, key, ...)
    if not res and err then
        local host, port = _parse_slot_moved(err)
        if host and port then
            res, err = _do_retry(self, host, port, cmd, key, ...)
            errcode = 2
        end
    end

    red:set_keepalive(self.config.idle_timeout, self.config.pool_size)
    return res, err, errcode
end


for i = 1, #commands do
    local cmd = commands[i]
    _M[cmd] = function (self, ...)
        local res, err, errcode =_do_cmd(self, cmd, ...)

        if errcode then
            _async_fetch_slots(self)
        end

        return res, err
    end
end


function _M.init_pipeline(self)
    self._reqs  = {}
    self._group = {}
end


function _M.cancel_pipeline(self)
    self._reqs  = nil
    self._group = nil
end


local mcommands = {
    mset = {
        cmd  = "set",
        func = function(i, item, res) -- return ok
            local data = "OK"
            for j = i + 1, i + item.size do
                if type(res[j]) == "table" and res[j][1] == false then
                    data = res[j]
                    break
                end
            end
            return data
        end
    },
    msetnx = {
        cmd  = "setnx",
        func = function(i, item, res) -- return 1 or 0
            local data = 1
            for j = i + 1, i + item.size do
                if (type(res[j]) == "number" and res[j] < 1) or (type(res[j]) == "table" and res[j][1] == false) then
                    data = res[j]
                    break
                end
            end
            return data
        end
    },
    mget = {
        cmd  = "get",
        func = function(i, item, res) -- return list
            local data = {}
            for j = i + 1, i + item.size do
                data[#data + 1] = res[j]
            end
            return data
        end
    },
    del = {
        cmd  = "del",
        func = function(i, item, res) -- reutrn affected
            local data = 0
            for j = i + 1, i + item.size do
                if type(res[j]) == "number" and res[j] > 0 then
                    data = data + res[j]
                elseif type(res[j]) == "table" and res[j][1] == false then
                    data = res[j]
                    break
                end
            end
            return data
        end
    }
}


local function _merge(group, res)
    local ret = {}
    local i   = 0
    for _, item in ipairs(group) do

        local data

        if item.mcmd and mcommands[item.mcmd] then
            data = mcommands[item.mcmd].func(i, item, res)
        else
            data = res[i + 1]
        end

        i = i + item.size
        ret[#ret + 1] = data
    end

    return ret
end


-- return res, err, errcode
-- errcode = 1, connection refused
-- errcode = 2, slot moved
local function _commit(self, nodeidx, reqs)

    local node, err = _get_node(self, nodeidx)
    if not node then
        return nil, err, 1
    end

    local errcode

    local host, port = node.master[1], node.master[2]
    local red, err   = _connect(self, host, port)
    if err then
        if err == 'connection refused' then
            errcode = 1
        end
        return nil, err, errcode
    end

    red:init_pipeline()
    for _, req in pairs(reqs) do
        if req.args and #req.args > 0 then
            red[req.cmd](red, req.key, unpack(req.args))
        else
            red[req.cmd](red, req.key)
        end
    end

    local result, err = red:commit_pipeline()

    if err then
        return nil, err
    end

    red:set_keepalive(self.config.idle_timeout, self.config.pool_size)

    local ret = {}
    for i, rs in ipairs(result) do

        ret[i] = rs
        if type(rs) == "table" and rs[1] == false then

            -- like: {false, "MOVED 15501 127.0.0.1:7002"}
            local host, port = _parse_slot_moved(rs[2])
            if host and port then
                local res, err

                if reqs[i].args and #reqs[i].args > 0 then
                    res, err = _do_retry(self, host, port, reqs[i].cmd, reqs[i].key, unpack(reqs[i].args))
                else
                    res, err = _do_retry(self, host, port, reqs[i].cmd, reqs[i].key)
                end

                ret[i] = res and res or { false, err }

                errcode = 2
            end
        end
    end

    return ret, nil, errcode
end


function _M.commit_pipeline(self)
    local reqs  = self._reqs
    local group = self._group
    if not reqs then
        return nil, "no pipeline"
    end

    self._reqs  = nil
    self._group = nil

    local servers = {}
    for idx, req in ipairs(reqs) do
        local nodeidx, node, err = _fetch_node(self, req.key)
        if not node then
            _async_fetch_slots(self)
            return nil, err
        end

        if not servers[nodeidx] then
            servers[nodeidx] = { nodeidx = nodeidx, reqs = {}, idxs = {} }
        end

        local mreqs = servers[nodeidx].reqs
        local midxs = servers[nodeidx].idxs
        mreqs[#mreqs + 1] = req
        midxs[#midxs + 1] = idx
    end

    local refetch = false

    local ret = new_tab(0, #reqs)
    for nodeidx, item in pairs(servers) do
        local res, err, errcode = _commit(self, nodeidx, item.reqs)

        if errcode then
            refetch = true
        end

        for i, idx in ipairs(item.idxs) do
            ret[idx] = res and res[i] or { false, err } -- see: https://github.com/openresty/lua-resty-redis
        end
    end

    if refetch then
        _async_fetch_slots(self)
    end

    -- merge results
    if #group > 0 then
        ret = _merge(group, ret)
    end

    return ret
end


-- like: mget mset msetnx del
local function _do_mcmd(self, mcmd, cmd, ...)

    local pipeline = self._reqs and true or nil
    if not pipeline then
        _M.init_pipeline(self)
    end

    local args = { ... }
    if mcmd == "mset" or mcmd == "msetnx" then -- k1, v1, k2, v2
        insert(self._group, { size = #args / 2, mcmd = mcmd })
        for i = 1, #args, 2 do
            insert(self._reqs, { cmd = cmd, key = args[i], args = { args[i + 1] } })
        end
    else
        insert(self._group, { size = #args, mcmd = mcmd })
        for _, key in ipairs(args) do
            insert(self._reqs, { cmd = cmd, key = key })
        end
    end

    if not pipeline then
        local res, err = _M.commit_pipeline(self)
        if not res then
            return res, err
        end

        if type(res[1]) == "table" and res[1][1] == false then
            return unpack(res[1])
        else
            return res[1]
        end
    end
end


for mcmd, item in pairs(mcommands) do
    local cmd = item.cmd
    _M[mcmd] = function (self, ...)
        return _do_mcmd(self, mcmd, cmd, ...)
    end
end


function _M.new(self, conf)
    local config = {
        name         = conf.name or "redis_cluster",
        servers      = conf.servers,
        password     = conf.password,
        timeout      = conf.timeout,
        idle_timeout = conf.idle_timeout or 1000,
        pool_size    = conf.pool_size or 100,
    }

    local mt = setmetatable({ config = config }, { __index = _M })
    if not cache_nodes[config.name] then
        local ok, err = _fetch_slots(mt)
        if not ok then
            return nil, err
        end
    end

    return mt
end


return _M

