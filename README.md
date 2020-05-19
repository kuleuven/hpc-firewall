# HPC Firewall

This project provides a web server, which registers client ips in a consul key value store.

The web server should be listening on a publicly reachable domain name, e.g. `example.com`, and two subdomains, e.g. `ipv4.example.com` and `ipv6.example.com`. The main domain should resolve both to an IPv4 and and IPv6 addresses, the two subdomains should only resolve of one of those addresses.

The same can be used with additional subdomains, if multiple client addresses should be detected.

Check `./hpc-firewall --help` for usage. 

Parameters:

* `--ouath-client-id` or `OAUTH_CLIENT_ID`: Oauth client id
* `--ouath-client-secret` or `OAUTH_CLIENT_SECRET`: Oauth client secret
* `--consul-addr` or `CONSUL_HTTP_ADDR`: Consul address for storage of ips
* `--consul-token` or `CONSUL_HTTP_TOKEN`: Consul token used to write to the key value store
* `--consul-path` or `CONSUL_PATH`: Root path in the consul kv store to write to
* `--hash-key` or `HASH_KEY`: Hash key for signing secure cookies. Should at least be 32 bytes long
* `--hash-key` or `BLOCK_KEY`: Block key for encrypting secure cookies. Should be either 16 (AES-128) or 32 (AES-256) bytes long
* `--domain` or `DOMAIN`: The main domain of the website (e.g. `example.com`)
* `--subdomains` or `SUBDOMAINS`: Comma-separated list of subdomains (e.g. `ipv4,ipv6`)

The command logs an admin password at startup, this can be used to retrieve the current ipset at `/ipset`. The result contains the `X-Last-Index` header which can be passed to the next GET request to make it blocking until the next change.

```bash
curl --header "Authorization: <PASSWORD>" https://example.com/ipset\?index\=<INDEX>
```

See `example/hpc-firewall.py` for a script using this endpoing.