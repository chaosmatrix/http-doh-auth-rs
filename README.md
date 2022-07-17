# http-doh-auth-rs

**http-doh-auth-rs**: envoy wams filter, do reverse DNS lookups via **DoH** for incoming connections and provides simple access control of **PTR Record** by allow/deny rules. Only regular expressions supported.

It works like **ngx_http_rdns_module**, but via **DoH** use external sub http request, not **regular dns query**.

More details show in **example/envoy.yaml**.

## Usage

```
# pull image
docker pull envoyproxy/envoy:v1.23.0

# run envoy server
docker run -v ./etc/envoy/envoy-v1.23.yaml:/etc/envoy/envoy.yaml -v ./etc/envoy/http_doh_auth_rs.wasm:/etc/envoy/http_doh_auth_rs.wasm -p 0.0.0.0:10000:10000 envoyproxy/envoy:v1.23.0

# test
curl http://127.0.0.1:10000
```
