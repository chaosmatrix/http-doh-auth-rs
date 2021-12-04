# http-doh-auth-rs

**http-doh-auth-rs**: envoy wams filter, do reverse DNS lookups via **DoH** for incoming connections and provides simple access control of **PTR Record** by allow/deny rules. Only regular expressions supported.

It works like **ngx_http_rdns_module**, but via **DoH** use external sub http request, not **regular dns query**.

More details show in **example/envoy.yaml**.
