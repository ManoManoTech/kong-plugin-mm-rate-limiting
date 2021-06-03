local PLUGIN_NAME = "mm-rate-limiting"
local schema_def = require "kong.plugins.mm-rate-limiting.schema"
local v = require("spec.helpers").validate_plugin_config_schema


describe("Plugin: " .. PLUGIN_NAME .. " (schema), ", function()
  describe("Limit", function()
    it("minimal conf validates", function()
      assert(v({second = 1 }, schema_def))
    end)
    it("full conf validates", function()
      assert(v({ second = 10, minute = 20, hour = 30, day = 40, month = 50, year = 60 }, schema_def))
    end)
    describe("Errors", function()
      it("limits: smaller unit is less than bigger unit", function()
        local config = { second = 20, hour = 10 }
        local ok, err = v(config, schema_def)
        assert.falsy(ok)
        assert.equal("The limit for hour(10.0) cannot be lower than the limit for second(20.0)", err.config)
      end)

      it("limits: smaller unit is less than bigger unit (bis)", function()
        local config = { second = 10, minute = 20, hour = 30, day = 40, month = 60, year = 50 }
        local ok, err = v(config, schema_def)
        assert.falsy(ok)
        assert.equal("The limit for year(50.0) cannot be lower than the limit for month(60.0)", err.config)
      end)

      it("invalid limit", function()
        local config = {}
        local ok, err = v(config, schema_def)
        assert.falsy(ok)
        assert.same({"at least one of these fields must be non-empty: 'config.second', 'config.minute', 'config.hour', 'config.day', 'config.month', 'config.year'" },
        err["@entity"])
      end)
      it("limit_by invalid value", function()
        local config = { second = 20, limit_by = "foo" }
        local ok, err = v(config, schema_def)
        assert.falsy(ok)
        assert.same({
          limit_by = 'expected one of: ip, header, user agent'
        }, err.config)
      end)
      it("mark_action invalid value", function()
        local config = { second = 20, mark_action = "foo" }
        local ok, err = v(config, schema_def)
        assert.falsy(ok)
        assert.same({
          mark_action = 'expected one of: none, allow, deny, all'
        }, err.config)
      end)
      it("mark_action without mark_header", function()
        local config = { second = 20, mark_action = "all" }
        local ok, err = v(config, schema_def)
        assert.falsy(ok)
        assert.same({
          mark_header = 'required field missing'
        }, err.config)
      end)
    end)
  end)

  describe("Header:", function()
    it("should accept a valid header name", function()
      assert(v({ header = { name = "x-header" }, second = 1 }, schema_def))
    end)
    it("should accept an allow list", function()
      assert(v({
        header = {
          name = "x-header",
          allow = {"trust"}
        },
        second = 1 },
        schema_def))
    end)
    it("should accept a deny list", function()
      assert(v({
        header = {
          name = "x-header",
          deny = {"bad"},
        },
        second = 1 },
        schema_def))
    end)
    it("should accept allow and deny list", function()
      assert(v({
        header = {
          name = "x-header",
          allow = {"trust"},
          deny = {"bad"},
        },
        second = 1 },
        schema_def))
    end)
  end)
  describe("header errors:", function()
    it("header_name should not accept invalid type", function()
      local ok, err = v({ header = { name = 42 } }, schema_def)
      assert.falsy(ok)
      assert.same({ header = { name = "expected a string" }}, err.config)
    end)
    it("header_name should not accept invalid header", function()
      local ok, err = v({ header = { name = "badchar/" } }, schema_def)
      assert.falsy(ok)
      assert.same({
        header = { name ="bad header name 'badchar/', allowed characters are A-Z, a-z, 0-9, '_', and '-'" }
      }, err.config)
    end)
    it("should not accept allow without header_name", function()
      local ok, err =v({
        header = { allow = {"trust"} },
        second = 1 },
        schema_def)
      assert.falsy(ok)
      assert.same("required field missing", err.config.header.name)
    end)
    it("should not accept deny without header_name", function()
      local ok, err =v({
        header = { deny = { "bad", "vilain" } },
        second = 1 },
        schema_def)
      assert.falsy(ok)
      assert.same("required field missing", err.config.header.name)
    end)
    it("should not accept allow and deny without header_name", function()
      local ok, err =v({
        header = {
          allow = { "trust" } ,
          deny = { "bad", "vilain" },
        },
        second = 1 },
        schema_def)
      assert.falsy(ok)
      assert.same("required field missing", err.config.header.name)
    end)
  end)
  describe("IP:", function()
    it("should accept a valid ip_allow", function()
      assert(v({ ip_allow = { "10.0.0.1", "10.0.0.10" }, second = 1 }, schema_def))
    end)
    it("should accept a valid cidr range for ip_allow", function()
      assert(v({ ip_allow = { "10.0.0.1/24" }, second = 1 }, schema_def))
    end)
    it("should accept a valid ip_deny", function()
      assert(v({ ip_deny = { "10.0.0.1", "10.0.0.10" }, second = 1 }, schema_def))
    end)
    it("should accept a valid cidr range for ip_deny", function()
      assert(v({ ip_deny = { "10.0.0.1/24" }, second = 1 }, schema_def))
    end)
    it("should accept both non-empty ip_allow and ip_deny", function()
      local schema = {
        ip_allow = {
          "10.0.0.1"
        },
        ip_deny = {
          "10.0.0.2"
        },
        second = 1,
      }
      assert(v(schema, schema_def))
    end)
    it("should accept both empty ip_allow and ip_deny", function()
      local schema = { ip_deny = {}, ip_allow = {}, second = 1 }
      assert(v(schema, schema_def))
    end)
    it("should accept valid ipv6 cidr ranges", function()
      local schema = {
        ip_allow = { "::/0",  "::/1", "::/128"  },
        second = 1
      }
      assert(v(schema, schema_def))
    end)
  end)

  describe("IP errors:", function()
    it("ip_allow should not accept invalid type", function()
      local ok, err = v({ ip_allow = 42 }, schema_def)
      assert.falsy(ok)
      assert.same({ ip_allow = "expected an array" }, err.config)
    end)
    it("ip_allow should not accept invalid IPs", function()
      local ok, err = v({ ip_allow = { "257.0.0.1", "10.0.0.10" } }, schema_def)
      assert.falsy(ok)
      assert.same({
        ip_allow = { "invalid ip or cidr range: '257.0.0.1'" }
      }, err.config)
    end)
    it("ip_allow should not accept strings that are not an IP or a CIDR range", function()
      local ok, err = v({ ip_allow = { "foo" } }, schema_def)
      assert.falsy(ok)
      assert.same({
        ip_allow = { "invalid ip or cidr range: 'foo'" }
      }, err.config)

      ok, err = v({ ip_allow = { "10.0.0.1", "10.0.0.10", "foo" } }, schema_def)
      assert.falsy(ok)
      assert.same({
        ip_allow = { [3] = "invalid ip or cidr range: 'foo'" }
      }, err.config)
    end)
    it("ip_deny should not accept invalid type", function()
      local ok, err = v({ ip_deny = 42 }, schema_def)
      assert.falsy(ok)
      assert.same({ ip_deny = "expected an array" }, err.config)
    end)
    it("ip_deny should not accept invalid IPs", function()
      local ok, err = v({ ip_deny = { "257.0.0.1", "10.0.0.10" } }, schema_def)
      assert.falsy(ok)
      assert.same({
        ip_deny = { "invalid ip or cidr range: '257.0.0.1'" }
      }, err.config)
    end)
    it("ip_deny should not accept strings that are not an IP or a CIDR range", function()
      local ok, err = v({ ip_deny = { "foo" } }, schema_def)
      assert.falsy(ok)
      assert.same({
        ip_deny = { "invalid ip or cidr range: 'foo'" }
      }, err.config)

      ok, err = v({ ip_deny = { "10.0.0.1", "10.0.0.10", "foo" } }, schema_def)
      assert.falsy(ok)
      assert.same({
        ip_deny = { [3] = "invalid ip or cidr range: 'foo'" }
      }, err.config)
    end)

    it("should not accept invalid cidr ranges", function()
      local ok, err = v({ ip_allow = { "10.0.0.0/a", "10.0.0.0/-1", "10.0.0.0/33" } }, schema_def)
      assert.falsy(ok)
      assert.same({
        ip_allow = {
          "invalid ip or cidr range: '10.0.0.0/a'",
          "invalid ip or cidr range: '10.0.0.0/-1'",
          "invalid ip or cidr range: '10.0.0.0/33'",
        }
      }, err.config)
    end)
    it("should not accept invalid ipv6 cidr ranges", function()
      local ok, err = v({ ip_allow = { "::/a", "::/-1", "::/129", "::1/a", "::1/-1", "::1/129" } }, schema_def)
      assert.falsy(ok)
      assert.same({
        ip_allow = {
          "invalid ip or cidr range: '::/a'",
          "invalid ip or cidr range: '::/-1'",
          "invalid ip or cidr range: '::/129'",
          "invalid ip or cidr range: '::1/a'",
          "invalid ip or cidr range: '::1/-1'",
          "invalid ip or cidr range: '::1/129'",
        }
      }, err.config)
    end)
    it("ip_source should not accept invalid type", function()
      local ok, err = v({ ip_source = 42 }, schema_def)
      assert.falsy(ok)
      assert.same({ ip_source = "expected a string" }, err.config)
    end)
    it("ip_source should not accept invalid values", function()
      local ok, err = v({ ip_source = "foo" }, schema_def)
      assert.falsy(ok)
      assert.same({ ip_source = "expected one of: connection, forwarded_ip, header" }, err.config)
    end)
    it("ip_header_source should not accept invalid type", function()
      local ok, err = v({ ip_header_source = 42 }, schema_def)
      assert.falsy(ok)
      assert.same({ ip_header_source = "expected a string" }, err.config)
    end)
    it("ip_header_source should not accept invalid header", function()
      local ok, err = v({ ip_header_source = "badchar/" }, schema_def)
      assert.falsy(ok)
      assert.same({
        ip_header_source = "bad header name 'badchar/', allowed characters are A-Z, a-z, 0-9, '_', and '-'"
      }, err.config)
    end)
    it("ip_header_source should be provided on ip by header", function()
      local ok, err = v({ ip_source = "header" }, schema_def)
      assert.falsy(ok)
      assert.same({ ip_header_source = "required field missing" }, err.config)
    end)

  end)
end)
