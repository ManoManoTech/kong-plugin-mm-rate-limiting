local BasePlugin = require "kong.plugins.base_plugin"
local ipmatcher = require "resty.ipmatcher"
local lrucache = require "resty.lrucache"
local timestamp = require "kong.tools.timestamp"

local EXPIRATION = require "kong.plugins.mm-rate-limiting.expiration"
local datadog = require "kong.plugins.mm-rate-limiting.datadog"
local logger = nil

local RateLimitingHandler = BasePlugin:extend()

local null    = ngx.null
local re_find = ngx.re.find
local shm     = ngx.shared
local time    = ngx.time
local fmt     = string.format

local EMPTY_UUID = "00000000-0000-0000-0000-000000000000"

RateLimitingHandler.VERSION  = "1.0.0"
RateLimitingHandler.PRIORITY = 10

local function get_ip(conf)
  local ip
  if conf.ip_source == "connection" then
    ip = kong.client.get_ip()
  elseif conf.ip_source == "header" then
    ip = kong.request.get_header(conf.ip_header_source)
  end

  return ip or kong.client.get_forwarded_ip()
end

local function inTable(tbl, item)
  for key, value in pairs(tbl) do
    if value == item then return key end
  end
  return false
end


local function finalize(conf, blocked, mode, reset)
  if blocked then
    if conf.mark_action == "all" or conf.mark_action == "deny" then
      kong.service.request.set_header(conf.mark_header, "Block "..mode)
      logger:log({"status:flagged", "mode:"..mode})
      return
    else
      reset = reset or 0
      logger:log({"status:blocked", "mode:"..mode})
      return kong.response.error(429, "Too Many Requests", {
        ["Retry-After"] = conf.retry_after + reset
      })
    end
  elseif conf.mark_action == "all" or conf.mark_action == "allow" then
    kong.service.request.set_header(conf.mark_header, "Allow "..mode)
  end
    logger:log({"status:allowed", "mode:"..mode})
end

local function check_header(conf, header)
  local val = ""
  if header and header.name then
    val = kong.request.get_header(header.name)
    if inTable(header.allow, val) then
      finalize(conf, false, "by header")
      return true, val
    end
    if inTable(header.deny, val) then
      finalize(conf, true, "by header")
      return true, val
    end
  end
  return false, val
end

-- per-worker cache of matched UAs
-- we use a weak table, index by the `conf` parameter, so once the plugin config
-- is GC'ed, the cache follows automatically
local ua_caches = setmetatable({}, { __mode = "k" })
local UA_CACHE_SIZE = 10 ^ 4
local MATCH_EMPTY   = 0
local MATCH_ALLOW   = 1
local MATCH_DENY    = 2


local function get_user_agent()
  local user_agent = kong.request.get_headers()["user-agent"]
  if type(user_agent) == "table" then
    return nil, "Only one User-Agent header allowed"
  end
  return user_agent
end

local function examine_agent(conf, user_agent)
  if conf.user_agent_allow and #conf.user_agent_allow > 0 then
    for _, rule in ipairs(conf.user_agent_allow) do
      if re_find(user_agent, rule, "jo") then
        return MATCH_ALLOW
      end
    end
  end
  if conf.user_agent_deny and #conf.user_agent_deny > 0 then
    for _, rule in ipairs(conf.user_agent_deny) do
      if re_find(user_agent, rule, "jo") then
        return MATCH_DENY
      end
    end
  end
  return MATCH_EMPTY
end


local function check_ua(conf, user_agent)
  if #conf.user_agent_allow == 0 and #conf.user_agent_deny == 0 then
    return false
  end
  local ua_cache = ua_caches[conf]
  if not ua_cache then
    ua_cache = lrucache.new(UA_CACHE_SIZE)
    ua_caches[conf] = ua_cache
  end
  local match = ua_cache:get(user_agent)
  if not match then
    match = examine_agent(conf, user_agent)
    ua_cache:set(user_agent, match)
  end

  if match == MATCH_ALLOW then
    finalize(conf, false, "by user agent")
    return true
  elseif match == MATCH_DENY then
    finalize(conf, true, "by user agent")
    return true
  end

  return false
end

local function get_service_and_route_ids(conf)
  conf = conf or {}

  local service_id = conf.service_id
  local route_id   = conf.route_id

  if not service_id or service_id == null then
    service_id = EMPTY_UUID
  end

  if not route_id or route_id == null then
    route_id = EMPTY_UUID
  end

  return service_id, route_id
end

function RateLimitingHandler:access(conf)
  RateLimitingHandler.super.access(self)
  logger = datadog(conf.datadog)
  local ip = get_ip(conf)
  local user_agent, err = get_user_agent()
  if err or not user_agent or user_agent == "" then
    return
  end
  local header
  local fin

  if conf.ip_allow and #conf.ip_allow > 0 then
    local ip_a = ipmatcher.new(conf.ip_allow)
    if ip_a:match(ip) then
      return finalize(conf, false, "by ip")
    end
  end
  if conf.ip_deny and #conf.ip_deny > 0 then
    local ip_d = ipmatcher.new(conf.ip_deny)
    if ip_d:match(ip) then
      return finalize(conf, true, "by ip")
    end
  end
  fin, header = check_header(conf, conf.header)
  if fin then
    return
  end
  if conf.header_extra and #conf.header_extra > 0 then
    for _, h in ipairs(conf.header_extra) do
      if check_header(conf, h) then
        return
      end
    end
  end
  if check_ua(conf, user_agent) then
    return
  end
  -- Load current metric for configured period
  local limits = {
    second = conf.second,
    minute = conf.minute,
    hour = conf.hour,
    day = conf.day,
    month = conf.month,
    year = conf.year,
  }
  -- Compute if allowed by local rate
  local service_id, route_id = get_service_and_route_ids(conf)
  local cache_key = fmt("manorate:%s:%s:%s:", service_id, route_id, conf.limit_by)
  if conf.limit_by == "ip" then
    cache_key = cache_key .. ip
  elseif conf.limit_by == "header" then
    cache_key = cache_key .. header
  elseif conf.limit_by == "user agent" then
    cache_key = cache_key .. user_agent
  else
    --Shouldn't happen
    return finalize(conf, false, "bad limit_by" .. conf.limit_by)
  end
  local now = time()
  local periods = timestamp.get_timestamps(now * 1000)
  local reset = 0
  local period_block = nil
  for period, period_date in pairs(periods) do
    if limits[period] then
      local cache_key_p = cache_key .. ":" .. period:sub(1, 2) .. ":" .. period_date

      local newval, err = shm[conf.dictionary_name]:incr(cache_key_p, 1, 0, EXPIRATION[period])
      if not newval then
        kong.log.err("could not increment counter for period '", period, "': ", err)
        return nil, err
      end
      if newval > limits[period] then
        reset = EXPIRATION[period] - now % EXPIRATION[period]
        period_block = period
      end
    end
  end
  if period_block then
    return finalize(conf, true, "by rate[" .. period_block .. "]", reset)
  end
  logger:log({"status:pass"})
end


return RateLimitingHandler
