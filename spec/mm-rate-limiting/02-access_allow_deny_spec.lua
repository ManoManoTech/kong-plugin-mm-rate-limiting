local helpers = require "spec.helpers"
local cjson   = require "cjson"


local PLUGIN_NAME = "mm-rate-limiting"

local UA_WPT = "Mozilla/5.0 (Linux; Android 6.0.1; Moto G (4) Build/MPJ24.139-64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.146 Mobile Safari/537.36 PTST/20.06"
local UA_PETAL = "Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot;+https://aspiegel.com/petalbot)"
local UA_CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"

for _, strategy in helpers.each_strategy() do
  describe("Plugin: " .. PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
    local client

    lazy_setup(function()
      local bp = helpers.get_db_utils(strategy, nil, { PLUGIN_NAME })
      local route1 = bp.routes:insert({
        hosts = { "test1.com" },
      })
      local route2 = bp.routes:insert({
        hosts = { "test2.com" },
      })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route1.id },
        config = {
          ip_allow = {"10.0.0.1", "10.0.1.0/24"},
          ip_deny  = {"10.1.0.1", "10.1.1.0/24"},
          ip_source = "header",
          ip_header_source = "x-true-client-ip",
          mark_header = "x-limit",
          mark_action = "allow",
          header = {
            name = "x-source",
            allow = {"trust"},
            deny = {"bad", "vilain"}
          },
          header_extra = {
            {
              name = "header1",
              allow = {"a1"},
              deny = {"d1"},
            },
            {
              name = "header2",
              allow = {"a2"},
              deny = {"d2"},
            },
          },
          user_agent_allow = {"ManoAgent"},
          user_agent_deny = {"bot", [[ PTST/\d+(?:\.)?\d+$]] },
          second = 10,
        },
      }
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route2.id },
        config = {
          ip_allow = {"10.0.0.1", "10.0.1.0/24"},
          ip_deny  = {"10.1.0.1", "10.1.1.0/24"},
          ip_source = "header",
          ip_header_source = "x-true-client-ip",
          mark_header = "x-limit",
          mark_action = "all",
          header = {
            name = "x-source",
            allow = {"trust", "good"},
            deny = {"bad"},
          },
          user_agent_allow = {"ManoAgent"},
          user_agent_deny = {"[[bot.*$]]", [[ PTST/\d+(?:\.)?\d+$]] },
          second = 10,
        },
      }
      -- start kong
      assert(helpers.start_kong({
        -- set the strategy
        database   = strategy,
        -- use the custom test template to create a local mock server
        nginx_conf = "spec/fixtures/custom_nginx.template",
        -- make sure our plugin gets loaded
        plugins = "bundled," .. PLUGIN_NAME,
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong(nil, true)
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      if client then client:close() end
    end)

    describe("Header", function()
      describe("Allow:", function()
        it("a request when the header is out of allow and deny", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["x-source"] = "unknown",
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end)
        it("flag a request when it is allowed", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["x-source"] = "trust",
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("Allow by header", json.headers["x-limit"])
        end)
        it("flag a request when it is allowed via extra", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["header1"] = "a1",
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("Allow by header", json.headers["x-limit"])
        end)
      end)

      describe("Deny:", function()
        it("blocks a request when it is denied", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["x-source"] = "vilain",
            }
          })
          local body = assert.res_status(429, res)
          local json = cjson.decode(body)
          assert.same({ message = "Too Many Requests" }, json)
        end)
        it("blocks a request when it is denied via extra", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["header1"] = "d1",
            }
          })
          local body = assert.res_status(429, res)
          local json = cjson.decode(body)
          assert.same({ message = "Too Many Requests" }, json)
        end)
        it("flags a request when it is denied", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test2.com",
              ["x-source"] = "bad",
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("Block by header", json.headers["x-limit"])
        end)
      end)
    end)

    describe("User Agent", function()
      describe("Allow:", function()
        it("a request when the user agent is out of allow and deny", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["User-Agent"] = UA_CHROME,
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end)
        it("flag a request when it is allowed", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["User-Agent"] = "ManoAgent",
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("Allow by user agent", json.headers["x-limit"])
        end)
      end)

      describe("Deny:", function()
        it("blocks a request when it is denied", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["User-Agent"] = UA_PETAL,
            }
          })
          local body = assert.res_status(429, res)
          local json = cjson.decode(body)
          assert.same({ message = "Too Many Requests" }, json)
        end)
        it("flags a request when it is denied", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test2.com",
              ["User-Agent"] = UA_WPT,
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("Block by user agent", json.headers["x-limit"])
        end)
      end)
    end)

    describe("IP", function()
      describe("Allow:", function()
        it("a request when the IP is out of allow and deny", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["x-true-client-ip"] = "11.0.0.1",
            }
          })
          assert.res_status(200, res)
        end)
        it("a request when the IP is allowed", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["x-true-client-ip"] = "10.0.0.1",
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("Allow by ip", json.headers["x-limit"])
        end)
        it("a request when the IP is allowed", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test2.com",
              ["x-true-client-ip"] = "10.0.0.1",
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("Allow by ip", json.headers["x-limit"])
        end)
      end)

      describe("Deny:", function()
        it("blocks a request when the IP is denied", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["x-true-client-ip"] = "10.1.0.1",
            }
          })
          local body = assert.res_status(429, res)
          local json = cjson.decode(body)
          assert.same({ message = "Too Many Requests" }, json)
        end)
        it("flags a request when the IP is denied", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test2.com",
              ["x-true-client-ip"] = "10.1.0.1",
            }
          })
          local body = assert.res_status(200, res)
          local json = cjson.decode(body)
          assert.equal("Block by ip", json.headers["x-limit"])
        end)
        it("blocks a request when the IP is into the denied range", function()
          local res = assert(client:send {
            method  = "GET",
            path    = "/status/200",
            headers = {
              ["Host"] = "test1.com",
              ["x-true-client-ip"] = "10.1.1.42",
            }
          })
          local body = assert.res_status(429, res)
          local json = cjson.decode(body)
          assert.same({ message = "Too Many Requests" }, json)
        end)
      end)
    end)
  end)
end
