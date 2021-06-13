# get client ip
```

use_remote_addr


x-envoy-internal == true ? localhost -> get x-forwarded-for
x-envoy-external-address ? if external (x-forwarded-for has multi)
```
