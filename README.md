[![Build Status](https://travis-ci.com/ManoManoTech/kong-plugin-mm-rate-limiting.svg?branch=main)](https://travis-ci.com/ManoManoTech/kong-plugin-mm-rate-limiting)
# A Kong plugin to allow, deny and rate limit the queries by ip, header or user agent

The goal is to protect the origin, that's why there is only local policy compared to the [rate limiting plugin](https://docs.konghq.com/hub/kong-inc/rate-limiting/) where there is 2 other policies for precision but with performance impact.
The plugin is inspired by
 * https://docs.konghq.com/hub/kong-inc/rate-limiting/
 * https://docs.konghq.com/hub/kong-inc/bot-detection/
 * https://docs.konghq.com/hub/kong-inc/ip-restriction/

## Install the plugin

## Enable the plugin

## Configuration

The rate limiting can be done by second, minute, hour, month or year. One of this limit should be set.
The ip can be retrieve via the `connection`, the `forwarded_ip` or a specific `header`.

Queries can be rejected by ip, header or user agent,
using respectively `ip_deny`, `header_value_deny` or `user_agent_deny`.

Queries can be allowed without rate limiting by ip, header or user agent
using respectively `ip_allow`, `header_value_allow` or `user_agent_allow`.

Name   | Required   | Type | Default | Description
------ | ---------- | ---- | ------- | -----------
`second` | semi | number | _None_ | The number of HTTP requests that can be made per second.
`minute` | semi | number | _None_ | The number of HTTP requests that can be made per minute.
`hour`   | semi | number | _None_ | The number of HTTP requests that can be made per hour.
`day`    | semi | number | _None_ | The number of HTTP requests that can be made per day.
`month`  | semi | number | _None_ | The number of HTTP requests that can be made per month.
`year`   | semi | number | _None_ | The number of HTTP requests that can be made per year.
`limit_by` | false | string | `ip` | The entity that will be used when aggregating the limits: <br /> `ip`, `header`, `user agent`.<br /> If the value for the entity chosen to aggregate the limit cannot be determined, the system will always fallback to `ip`. If value `header` is chosen, the `header_name` configuration must be provided.
`ip_source` | false | string | `forwarded_ip` | How to retrieve the ip, `connection` the remote address of the client making the request. `forwarded_ip` see [the doc](https://docs.konghq.com/gateway-oss/2.3.x/pdk/kong.client/#kongclientget_forwarded_ip) for more details on forwarded addresses, `header` get the ip from an http header
`ip_header_source` | semi | string | _None_ | Header name to be used to get the ip if `ip_source` is set to `header`
`ip_deny` | false | ip or [cidr](https://tools.ietf.org/html/rfc4632#section-3.1) array | _None_ | List of IPs or CIDR ranges to deny
`ip_allow` | false | ip or [cidr](https://tools.ietf.org/html/rfc4632#section-3.1) array  | _None_ | List of IPs or CIDR ranges to by pass the rate limiting
`user_agent_deny`  | false | regexp array | _None_ | A list of user agent to deny
`user_agent_allow`  | false | regexp array | _None_ | A list of user agent to bypass the rate limiting
`header`  | semi  | [header](#header)       | _None_ | Header, the header.name is the value to be used if `limit_by` is set to `header`
`header_extra` | false  | [header](#header) array | _None_ | a list of header, to add extra allow or deny (not used for limit by)
`mark_action`  | false | string | `none` | Four action are available `none`, `allow`, `deny`, `all`. `deny` and `all` will not block the traffic just flag it into the `mark_header`. `none` nothing is added into the headers of the **query**, `allow` add info into the **query** when a query by pass the rate limiting, `deny` don't block the traffic just mark it useful to check the rate values. `all` don't block the traffic and mark by passed and rate limited query.
`mark_header`  | semi | string | _None_ | The header where allow or deny information are added on the queries
`retry_after`  | false | number | 5 | Value to add as extra into the `Retry-After\` http header, this indicates how long to wait before making a new request.
`dictionary_name` | false | string | `kong_rate_limiting_counters` | The shared dictionary where counters will be stored
`datadog` | false | [datadog](#datadog) | _None_ | To configure datadog metrics

### Header

Name    | Required   | Type | Default   | Description
------- | ---------- | ---- | --------- | -----------
`name`  | semi  | string       | _None_ | Header name where to look for deny or allow values
`deny`  | false | string array | _None_ | A list of header value to deny
`allow` | false | string array | _None_ | A list of header value to by pass the rate limiting

### Datadog

Name        | Required   | Type | Default   | Description
----------- | ---------- | ---- | --------- | -----------
`activated` | false | boolean | false       | To activate Datadog metrics
`host`      | false | host    | localhost   | The datadog agent host
`port`      | false | port    | 8125        | The datadof agent port
`prefix`    | false | strin   | `kong.mm-rate-limiting` | The prefix to user, metric is _prefix_.queries, with two flags `status` and `mode`

`status` flag are `flagged`, `blocked`, `allowed` and `pass`
`mode` are `by header`, `by user agent`, `by ip` and `by rate[XXX]` XXX for second, minute, ...
