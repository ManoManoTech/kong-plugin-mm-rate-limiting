local typedefs = require "kong.db.schema.typedefs"
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")
local ORDERED_PERIODS = { "second", "minute", "hour", "day", "month", "year"}


local function shared_dict_validator(name)
  if not ngx.shared[name] then
    return nil, "ngx shared dict '" .. name .. "' not found"
  end

  return true
end

local function validate_periods_order(config)
  for i, lower_period in ipairs(ORDERED_PERIODS) do
    local v1 = config[lower_period]
    if type(v1) == "number" then
      for j = i + 1, #ORDERED_PERIODS do
        local upper_period = ORDERED_PERIODS[j]
        local v2 = config[upper_period]
        if type(v2) == "number" and v2 < v1 then
          return nil, string.format("The limit for %s(%.1f) cannot be lower than the limit for %s(%.1f)",
                                    upper_period, v2, lower_period, v1)
        end
      end
    end
  end

  return true
end

local header_schema = {
  type = "record",
  fields = {
    { name = typedefs.header_name },
    { allow = {
      type = "array",
      elements = { type = "string" },
      default = {}
    } },
    { deny = {
      type = "array",
      elements = { type = "string" },
      default = {}
    } },
  },
  entity_checks = {
    { conditional = {
      if_field = "allow", if_match = { len_min = 1 },
      then_field = "name", then_match = { required = true },
    } },
    { conditional = {
      if_field = "deny", if_match = { len_min = 1 },
      then_field = "name", then_match = { required = true },
    } },
  }
}

return {
  name = plugin_name,
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
      type = "record",
      fields = {
        { second = { type = "number", gt = 0 }, },
        { minute = { type = "number", gt = 0 }, },
        { hour = { type = "number", gt = 0 }, },
        { day = { type = "number", gt = 0 }, },
        { month = { type = "number", gt = 0 }, },
        { year = { type = "number", gt = 0 }, },
        -- header field to by pass the rate limiting
        { header = header_schema },
        { header_extra = {
          type = "array",
          elements =  header_schema ,
        } },
        -- user_agent to by pass the rate limiting
        { user_agent_allow = {
          type = "array",
          elements = { type = "string", is_regex = true },
          default = {},
        }, },
        { user_agent_deny = {
          type = "array",
          elements = { type = "string", is_regex = true },
          default = {},
        }, },
        -- For CDN the ip is in general into the true-client-ip header
        { ip_source = {
          type = "string",
          default = "forwarded_ip",
          one_of = {"connection", "forwarded_ip", "header"},
        } },
        { ip_header_source = typedefs.header_name },

        { ip_allow = { type = "array", elements = typedefs.ip_or_cidr, },},
        { ip_deny =  { type = "array", elements = typedefs.ip_or_cidr, },},

        -- Kind of ratelimiting
        { limit_by = {
          type = "string",
          default = "ip",
          one_of = {"ip", "header", "user agent"},
        } },
        { retry_after = { type = "number", default = 5 },},
        -- Header to flag query
        { mark_header = typedefs.header_name },
        -- deny and all mode will not block the query just flag it
        { mark_action = { type = "string", default = "none", one_of = {"none", "allow", "deny", "all"}, } },
        -- Use a dedicated dictionnary to isolate the cache from Kong
        { dictionary_name = {
          type = "string",
          default = "kong_rate_limiting_counters",
          custom_validator= shared_dict_validator,
        } },
        { datadog = {
          type = "record",
          fields = {
            { activated = {type = "boolean",  default = false} },
            { host = typedefs.host({ default = "localhost" }), },
            { port = typedefs.port({ default = 8125 }), },
            { prefix = { type = "string", default = "kong.mm-rate-limiting" }, },
          },
        } },
      },
      custom_validator = validate_periods_order,
    } },
  },
  entity_checks = {
    { at_least_one_of = { "config.second", "config.minute", "config.hour", "config.day", "config.month", "config.year" } },
    { conditional = {
      if_field = "config.limit_by", if_match = { eq = "header" },
      then_field = "config.header.name", then_match = { required = true },
    } },
    { conditional = {
      if_field = "config.ip_source", if_match = { eq = "header" },
      then_field = "config.ip_header_source", then_match = { required = true },
    } },
    { conditional = {
      if_field = "config.mark_action", if_match = { ne = "none" },
      then_field = "config.mark_header", then_match = { required = true },
    } },
  },
}
