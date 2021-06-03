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
local UA_GBOT = "Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1 (compatible; AdsBot-Google-Mobile; +http://www.google.com/mobile/adsbot.html)"
local UA_BING = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
local UA_PINTEREST = "Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)"
local UA_APPLEBOT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"

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
          mark_header = "x-limit",
          mark_action = "allow",
          header = { name ="x-source" },
          minute = 3,
          limit_by = "ip",
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
          header = { name ="x-source" },
          limit_by = "ip",
          minute = 3,
          hour = 4,
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
      it("block if exceeding limit", function()
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
      end)
      it("flag if exceeding limit", function()
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
        local body = GET({
          Host = "test2.com",
          ["x-true-client-ip"] = "10.0.0.1",
        }, 200)
        local json = cjson.decode(body)
        assert.equal("Block by rate[hour]", json.headers["x-limit"])
      end)
      it("block if exceeding limit, only if same ip", function()
        for i = 1, 3 do
          local body = GET({
            Host = "test1.com",
            ["x-true-client-ip"] = "10.0.0.2",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        for i = 1, 3 do
          local body = GET({
            Host = "test1.com",
            ["x-true-client-ip"] = "10.0.0.3",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test1.com",
          ["x-true-client-ip"] = "10.0.0.2",
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
        body = GET({
          Host = "test1.com",
          ["x-true-client-ip"] = "10.0.0.3",
        }, 429)
        json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
      end)
      it("block if exceeding limit, only if same host", function()
        for i = 1, 3 do
          local body = GET({
            Host = "test1.com",
            ["x-true-client-ip"] = "10.0.0.4",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        for i = 1, 3 do
          local body = GET({
            Host = "test2.com",
            ["x-true-client-ip"] = "10.0.0.4",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test1.com",
          ["x-true-client-ip"] = "10.0.0.4",
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
        body = GET({
          Host = "test2.com",
          ["x-true-client-ip"] = "10.0.0.4",
        }, 200)
        json = cjson.decode(body)
        assert.equal("Block by rate[minute]", json.headers["x-limit"])
      end)
    end)

    describe("Per header", function()
      it("block if exceeding limit", function()
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
      end)
      it("flag if exceeding limit", function()
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
      end)
      it("block if exceeding limit, only if same header", function()
        for i = 1, 3 do
          local body = GET({
            Host = "test3.com",
            ["x-source"] = "source2",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        for i = 1, 3 do
          local body = GET({
            Host = "test3.com",
            ["x-source"] = "source3",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test3.com",
          ["x-source"] = "source2",
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
        body = GET({
          Host = "test3.com",
          ["x-source"] = "source3",
        }, 429)
        json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
      end)
      it("block if exceeding limit, only if same host", function()
        for i = 1, 3 do
          local body = GET({
            Host = "test3.com",
            ["x-source"] = "source4",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        for i = 1, 3 do
          local body = GET({
            Host = "test4.com",
            ["x-source"] = "source4",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test3.com",
          ["x-source"] = "source4",
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
        body = GET({
          Host = "test4.com",
          ["x-source"] = "source4",
        }, 200)
        json = cjson.decode(body)
        assert.equal("Block by rate[minute]", json.headers["x-limit"])
      end)
    end)

    describe("Per user agent", function()
      it("block if exceeding limit", function()
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
      end)
      it("flag if exceeding limit", function()
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
      end)
      it("block if exceeding limit, only if same user agent", function()
        for i = 1, 3 do
          local body = GET({
            Host = "test5.com",
            ["User-Agent"] = UA_GBOT,
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        for i = 1, 3 do
          local body = GET({
            Host = "test5.com",
            ["User-Agent"] = UA_BING,
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test5.com",
          ["User-Agent"] = UA_GBOT,
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
        body = GET({
          Host = "test5.com",
          ["User-Agent"] = UA_BING,
        }, 429)
        json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
      end)
      it("block if exceeding limit, only if same host", function()
        for i = 1, 3 do
          local body = GET({
            Host = "test5.com",
            ["User-Agent"] = UA_PINTEREST,
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        for i = 1, 3 do
          local body = GET({
            Host = "test6.com",
            ["User-Agent"] = UA_PINTEREST,
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test5.com",
          ["User-Agent"] = UA_PINTEREST,
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
        body = GET({
          Host = "test6.com",
          ["User-Agent"] = UA_PINTEREST,
        }, 200)
        json = cjson.decode(body)
        assert.equal("Block by rate[minute]", json.headers["x-limit"])
      end)
      it("block if exceeding limit even if different ip", function()
        for i = 1, 3 do
          local body = GET({
            Host = "test5.com",
            ["User-Agent"] = UA_APPLEBOT,
            ["x-true-client-ip"] = "10.0.0.3",
          }, 200)
          local json = cjson.decode(body)
          assert.equal(nil, json.headers["x-limit"])
        end
        local body = GET({
          Host = "test5.com",
          ["User-Agent"] = UA_APPLEBOT,
          ["x-true-client-ip"] = "11.0.0.3",
        }, 429)
        local json = cjson.decode(body)
        assert.same({ message = "Too Many Requests" }, json)
      end)
    end)
  end)
end
