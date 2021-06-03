package = "kong-plugin-mm-rate-limiting"
version = "0.0.5-1"

local pluginName = package:match("^kong%-plugin%-(.+)$")  -- "mm-rate-limiting"

supported_platforms = {"linux", "macosx"}
source = {
  url = "https://git.manomano.tech/core-utils/kong-rate-limiting",
  tag = "v0.0.5"
}

description = {
  summary = "Manomano plugin to handle rate limiting",
  homepage = "https://www.manomano.fr",
  license = "Private"
}

dependencies = {
  "lua >= 5.1"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..pluginName..".handler"] = "kong/plugins/"..pluginName.."/handler.lua",
    ["kong.plugins."..pluginName..".schema"] = "kong/plugins/"..pluginName.."/schema.lua",
    ["kong.plugins."..pluginName..".expiration"] = "kong/plugins/"..pluginName.."/expiration.lua",
    ["kong.plugins."..pluginName..".datadog"] = "kong/plugins/"..pluginName.."/datadog.lua",
  }
}
