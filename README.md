# elephant-socks5-client-py
python client of Elephant(L4) tunnel for SOCKS5 empowered by [py-netty](https://github.com/ruanhao/py-netty).

[Elephant Server](https://github.com/ruanhao/elephant-socks5-tunnel) should be deployed first, which is a L4 tunnel server designed to provide a secure and high-performance tunneling solution for TCP traffic.

## Installation

```commandline
pip install elephant-socks5 -U
```


## Usage

```
$ elephant -h
Usage: elephant [OPTIONS]

Options:
  -p, --port INTEGER             Local port to bind  [default: 1080]
  -g, --global                   Listen on all interfaces
  -s, --server TEXT              Elephant tunnel server URLs (like: ws[s]://localhost:4443/elephant/ws)  [required]
  -a, --alias TEXT               Alias for the client
  -q, --quiet                    Quiet mode
  -esp, --enable-shell-proxy     Enable Shell proxy
  -erp, --enable-reverse-proxy   Enable reverse proxy
  -rpo, --reverse-proxy-only     No SOCKS5 server, only for reverse proxy
  --reverse-ip TEXT              Reverse proxy IP
  --reverse-port INTEGER         Reverse proxy port  [default: -1]
  --no-reverse-global            Reverse proxy listen on localhost
  -l, --log-record               Save log to file (elephant-client.log)
  -t, --request-timeout INTEGER  Session request timeout (seconds)  [default: 3]
  --no-color                     Disable color output
  -v, --verbose                  Verbose mode
  -n, --tunnels INTEGER RANGE    Number of tunnels to achieve load balance  [default: 1; x>=1]
  --proxy-ip TEXT                Proxy IP
  --proxy-port INTEGER           Proxy port  [default: -1]
  --version                      Show the version and exit.
  -h, --help                     Show this message and exit.
```


