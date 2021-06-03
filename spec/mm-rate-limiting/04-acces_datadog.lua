local helpers = require "spec.helpers"
local cjson   = require "cjson"


local PLUGIN_NAME = "mm-rate-limiting"

-- The reason why we allow to wait for next minute is because
-- tests are dependent on the value of the current minute. If the minute
-- flips during the test (i.e. going from 03:43:59 to 03:44:00), the result
-- will fail. Since each test takes less than a couple of seconds to run, waiting
-- some seconds the next minute prevents flaky test.
local MAX_WAIT = 5 -- number of second before minute rotation to trigger wait

local UA_ADSBOT = "AdsBot-Google (+http://www.google.com/adsbot.html)"
local UA_WPT = "Mozilla/5.0 (Linux; Android 6.0.1; Moto G (4) Build/MPJ24.139-64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.146 Mobile Safari/537.36 PTST/20.06"

local function GET(headers, res_status)
  local client = helpers.proxy_client()
  local res, err = assert(client:send {
    method  = "GET",
    headers = headers,
    path    = "/status/200",
  })
  if not res then
    client:close()
    return nil, err
  end

  local body, err = assert.res_status(res_status, res)
  client:close()
  if not body then
    return nil, err
  end
  return body
end

for _, strategy in helpers.each_strategy() do
  describe("Plugin: " .. PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()

    lazy_setup(function()
      local bp = helpers.get_db_utils(strategy, nil, { PLUGIN_NAME })
      local route1 = bp.routes:insert({
        hosts = { "test1.com" },
      })
      local route2 = bp.routes:insert({
        hosts = { "test2.com" },
      })
      local route3 = bp.routes:insert({
        hosts = { "test3.com" },
      })
      local route4 = bp.routes:insert({
        hosts = { "test4.com" },
      })
      local route5 = bp.routes:insert({
        hosts = { "test5.com" },
      })
      local route6 = bp.routes:insert({
        hosts = { "test6.com" },
      })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route1.id },
        config = {
          ip_source = "header",
          ip_header_source = "x-true-client-ip",
          ip_allow = {"10.0.1.1"},
          ip_deny  = {"10.1.1.0/24"},
          mark_header = "x-limit",
          mark_action = "allow",
          header = {
            name = "x-source",
            allow = {"trust"},
            deny = {"bad", "vilain"}
          },
          minute = 3,
          limit_by = "ip",
          user_agent_allow = {"ManoAgent"},
          user_agent_deny = {"bot", [[ PTST/\d+(?:\.)?\d+$]] },
          datadog = {
            activated = true,
            host    = "127.0.0.1",
            port    = 9999,
          },

        },
      }
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route2.id },
        config = {
          ip_source = "header",
          ip_header_source = "x-true-client-ip",
          mark_header = "x-limit",
          mark_action = "all",
          header = {
            name = "x-source",
            allow = {"trust"},
            deny = {"bad", "vilain"}
          },
          limit_by = "ip",
          user_agent_allow = {"ManoAgent"},
          user_agent_deny = {"bot", [[ PTST/\d+(?:\.)?\d+$]] },
          minute = 3,
          datadog = {
            activated = true,
            host    = "127.0.0.1",
            port    = 9999,
          },
        },
      }
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route3.id },
        config = {
          ip_source = "header",
          ip_header_source = "x-true-client-ip",
          mark_header = "x-limit",
          mark_action = "allow",
          header = { name ="x-source" },
          limit_by = "header",
          minute = 3,
          datadog = {
            activated = true,
            host    = "127.0.0.1",
            port    = 9999,
          },
        },
      }
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route4.id },
        config = {
          ip_source = "header",
          ip_header_source = "x-true-client-ip",
          mark_header = "x-limit",
          mark_action = "all",
          header = { name = "x-source" },
          limit_by = "header",
          minute = 3,
          datadog = {
            activated = true,
            host    = "127.0.0.1",
            port    = 9999,
          },
        },
      }
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route5.id },
        config = {
          ip_source = "header",
          ip_header_source = "x-true-client-ip",
          mark_header = "x-limit",
          mark_action = "allow",
          header = { name = "x-source" },
          limit_by = "user agent",
          minute = 3,
          datadog = {
            activated = true,
            host    = "127.0.0.1",
            port    = 9999,
          },
        },
      }
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route6.id },
        config = {
          ip_source = "header",
          ip_header_source = "x-true-client-ip",
          mark_header = "x-limit",
          mark_action = "all",
          header = { name =  "x-source" },
          limit_by = "user agent",
          minute = 3,
          datadog = {
            activated = true,
            host    = "127.0.0.1",
            port    = 9999,
          },
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
      -- XXX
      -- Wait the minute to rotate
      local next_minute = 61 - (ngx.now() % 60)
      if next_minute < MAX_WAIT then
        ngx.sleep(next_minute)
      end

    end)

    describe("Per ip", function()
      it("allow if in the allow list", function()
        local thread = helpers.udp_server(9999, 1, MAX_WAIT)
          local body = GET({
            Host = "test1.com",
            ["x-true-client-ip"] = "10.0.1.1",
          }, 200)
          local json = cjson.decode(body)
          assert.equal("Allow by ip", json.headers["x-limit"])

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.equal("kong.mm-rate-limiting.queries:1|c|#status:allowed,mode:by ip" , gauges)
      end)
      it("block if in deny list", function()
        local thread = helpers.udp_server(9999, 1, MAX_WAIT)
        local body = GET({
          Host = "test1.com",
          ["x-true-client-ip"] = "10.1.1.3",
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.equal("kong.mm-rate-limiting.queries:1|c|#status:blocked,mode:by ip", gauges)
      end)
      it("block if exceeding limit", function()
        local thread = helpers.udp_server(9999, 4, MAX_WAIT)
        for i = 1, 3 do
          local body = GET({
            Host = "test1.com",
            ["x-true-client-ip"] = "10.0.0.1",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test1.com",
          ["x-true-client-ip"] = "10.0.0.1",
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.not_equal(nil, gauges)
        assert.equal(4, #gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:pass" , gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:blocked,mode:by rate[minute]", gauges)

      end)

      it("flag if exceeding limit", function()
        local thread = helpers.udp_server(9999, 4, MAX_WAIT)
        for i = 1, 3 do
          local body = GET({
            Host = "test2.com",
            ["x-true-client-ip"] = "10.0.0.1",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test2.com",
          ["x-true-client-ip"] = "10.0.0.1",
        }, 200)
        local json = cjson.decode(body)
        assert.equal("Block by rate[minute]", json.headers["x-limit"])

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.not_equal(nil, gauges)
        assert.equal(4, #gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:pass" , gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:flagged,mode:by rate[minute]", gauges)
      end)
    end)

    describe("Per header", function()
      it("allow if in the allow list", function()
        local thread = helpers.udp_server(9999, 1, MAX_WAIT)
          local body = GET({
            Host = "test1.com",
            ["x-source"] = "trust",
          }, 200)
          local json = cjson.decode(body)
          assert.equal("Allow by header", json.headers["x-limit"])

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.equal("kong.mm-rate-limiting.queries:1|c|#status:allowed,mode:by header" , gauges)
      end)
      it("block if in deny list", function()
        local thread = helpers.udp_server(9999, 1, MAX_WAIT)
        local body = GET({
          Host = "test1.com",
          ["x-source"] = "vilain",
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.equal("kong.mm-rate-limiting.queries:1|c|#status:blocked,mode:by header", gauges)
      end)
      it("block if exceeding limit", function()
        local thread = helpers.udp_server(9999, 4, MAX_WAIT)
        for i = 1, 3 do
          local body = GET({
            Host = "test3.com",
            ["x-source"] = "source1",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test3.com",
          ["x-source"] = "source1",
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
        local ok, gauges = thread:join()
        assert.True(ok)
        assert.not_equal(nil, gauges)
        assert.equal(4, #gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:pass" , gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:blocked,mode:by rate[minute]", gauges)
      end)
      it("flag if exceeding limit", function()
        local thread = helpers.udp_server(9999, 4, MAX_WAIT)
        for i = 1, 3 do
          local body = GET({
            Host = "test4.com",
            ["x-source"] = "source1",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test4.com",
          ["x-source"] = "source1",
        }, 200)
        local json = cjson.decode(body)
        assert.equal("Block by rate[minute]", json.headers["x-limit"])

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.not_equal(nil, gauges)
        assert.equal(4, #gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:pass" , gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:flagged,mode:by rate[minute]", gauges)
      end)
    end)

    describe("Per user agent", function()
      it("allow if in the allow list", function()
        local thread = helpers.udp_server(9999, 1, MAX_WAIT)
          local body = GET({
            Host = "test1.com",
            ["User-agent"] = "ManoAgent",
          }, 200)
          local json = cjson.decode(body)
          assert.equal("Allow by user agent", json.headers["x-limit"])

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.equal("kong.mm-rate-limiting.queries:1|c|#status:allowed,mode:by user agent" , gauges)
      end)
      it("block if in deny list", function()
        local thread = helpers.udp_server(9999, 1, MAX_WAIT)
        local body = GET({
          Host = "test1.com",
          ["User-agent"] = UA_WPT,
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.equal("kong.mm-rate-limiting.queries:1|c|#status:blocked,mode:by user agent", gauges)
      end)
      it("block if exceeding limit", function()
        local thread = helpers.udp_server(9999, 4, MAX_WAIT)
        for i = 1, 3 do
          local body = GET({
            Host = "test5.com",
            ["User-Agent"] = UA_ADSBOT,
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test5.com",
          ["User-Agent"] = UA_ADSBOT,
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)

        local ok, gauges = thread:join()
        assert.True(ok)
        assert.not_equal(nil, gauges)
        assert.equal(4, #gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:pass" , gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:blocked,mode:by rate[minute]", gauges)
      end)
      it("flag if exceeding limit", function()
        local thread = helpers.udp_server(9999, 4, MAX_WAIT)
        for i = 1, 3 do
          local body = GET({
            Host = "test6.com",
            ["User-Agent"] = UA_ADSBOT,
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test6.com",
          ["User-Agent"] = UA_ADSBOT,
        }, 200)
        local json = cjson.decode(body)
        assert.equal("Block by rate[minute]", json.headers["x-limit"])
        local ok, gauges = thread:join()
        assert.True(ok)
        assert.not_equal(nil, gauges)
        assert.equal(4, #gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:pass" , gauges)
        assert.contains("kong.mm-rate-limiting.queries:1|c|#status:flagged,mode:by rate[minute]", gauges)
      end)
    end)
  end)
end
