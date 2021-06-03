local setmetatable = setmetatable

local _M = {}


local function init(conf)
  local statsd_logger
  local logger = nil
  local function requiref()
    statsd_logger = require('kong.plugins.datadog.statsd_logger')
  end
  local status = pcall(requiref)
  if not status then
    kong.log.info("Datadog not present")
    return nil, "Cannot load datadog"
  end
  if statsd_logger and conf.activated then
    local err
    logger, err = statsd_logger:new(conf)
    if err then
      kong.log.err("failed to create Statsd logger: ", err)
      return nil, err
    end
  end
  return logger, nil
end

function _M.new(conf)
  local self = {
    logger = init(conf)
  }
  return setmetatable(self, {
    __index = _M,
  })
end


function _M:log(tags)
  if self.logger then
    self.logger:send_statsd("queries", 1, "c", 1, tags)
  end
end

return setmetatable(_M, {
  __call = function (cls, ...)
    return cls.new(...)
  end,
})
