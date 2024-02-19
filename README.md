# elephant-sock5-client-py
python client of Elephant(L4) tunnel for SOCK5 empowered by [py-netty](https://github.com/ruanhao/py-netty).

[Elephant Server](https://github.com/ruanhao/elephant-sock5-tunnel) should be deployed first, which is a L4 tunnel server designed to provide a secure and high-performance tunneling solution for TCP traffic.

## Usage

```
$ elephant -h
Usage: elephant [OPTIONS]

Options:
  -p, --port INTEGER             Local port to bind  [default: 1080]
  -s, --server TEXT              Elephant tunnel server URL (like: ws[s]://localhost:4443/elephant/ws)  [required]
  -q, --quiet                    Quiet mode
  -l, --log-record               Save log to file (elephant-client.log)
  -t, --request-timeout INTEGER  Session request timeout (seconds)  [default: 3]
  --no-color                     Disable color output
  -v, --verbose                  Verbose mode
  -n, --tunnels INTEGER RANGE    Number of tunnels to achieve load balance  [default: 1; 1<=x<=8]
  --proxy-ip TEXT                Proxy IP
  --proxy-port INTEGER           Proxy port  [default: -1]
  --version                      Show the version and exit.
  -h, --help                     Show this message and exit.
```


