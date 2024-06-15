import click
import inspect
import socket
import time
from datetime import datetime
import threading
import ssl
import logging
from typing import Optional
import websocket
from concurrent.futures import Future, TimeoutError
from websocket._abnf import ABNF, STATUS_TRY_AGAIN_LATER
from elephant_socks5.protocol import bytes_to_frame, OP_CONTROL, OP_DATA, JRPCResponse, SessionRequest, Hello, Frame, TerminationRequest
from elephant_socks5.utils import LengthFieldBasedFrameDecoder, chunk_list, sneaky, socket_description, has_format_placeholders, Metric, my_ip, ShellContext
from elephant_socks5.version import __version__
from click import secho
import json
import string
from py_netty import Bootstrap, ServerBootstrap, ChannelHandlerAdapter, EventLoopGroup
from attrs import define, field
from itertools import cycle, count
import simple_proxy


logger = logging.getLogger("elephant-socks5")

URL = "ws[s]://localhost:4443/elephant/ws"

decoder = LengthFieldBasedFrameDecoder()

_enable_reverse_proxy = False
_enable_shell_proxy = False
_quiet = False
_trace_data = False
_session_request_timeout = 3
_no_color = False

_proxy_ip = None
_proxy_port = None

_tunnels = []                   # list of Tunnel
tunnels = None                  # cycle object
_counter = count(start=0, step=1)
_lock = threading.Lock()
_connected_counter = set()

ACCEPTOR = EventLoopGroup(1, 'Acceptor')
WORKER = EventLoopGroup(1, 'Worker')
RECONNECT = 10                  # seconds


def _actives():
    return len([t for t in _tunnels if t.check_connected()])


def log_print(msg, *args, fg=None, underline=None, level=logging.INFO, force_print=False, **kwargs):
    logger.log(level, msg, *args, **kwargs)
    if not _quiet or force_print:
        message = msg
        if has_format_placeholders(msg):
            try:
                message = string.Formatter().format(msg, *args, **kwargs)
            except Exception:
                pass
            if has_format_placeholders(message):
                try:
                    message = message % args
                except Exception:
                    pass
        else:
            message = ' '.join(map(str, (msg, *args)))

        if _no_color:
            fg = None
            underline = None
        message = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] {message}"
        secho(message, fg=fg, underline=underline)


@define(slots=False)
class Tunnel:

    url: str = field()
    hello_params: dict = field(factory=dict)

    def __attrs_post_init__(self):
        self._clients = {}      # session_id -> ctx
        self._responseFutures = {}  # id -> (method, Future(jrpc))
        self._thread = None     # WebSocket thread
        self._localport = -1
        self._count = next(_counter)  # sequence
        self.hello_params.update({
            'version': __version__,
            'seq': self._count
        })
        self._session_create_metric = None
        self._ws = None

    def create_session_create_metric(self):
        self._session_create_metric = Metric.of(f"session-create-rtt @{self._count}")

    @sneaky()
    def start(self):
        if not self._ws:
            self._ws = websocket.WebSocketApp(
                self.url,
                on_open=self._on_open,
                on_message=self._on_message,
                on_error=self._on_error,
                on_close=self._on_close
            )

        # ws.run_forever(dispatcher=rel, reconnect=5)
        log_print(f"Starting Tunnel#{self._count} (URL: {self.url}) ...", underline=True, force_print=True)
        self._ws.run_forever(reconnect=RECONNECT, sslopt={"cert_reqs": ssl.CERT_NONE}, ping_interval=60 * 3, ping_timeout=30)
        # rel.signal(2, rel.abort)
        # rel.dispatch()

    def check_connected(self, throw=False):
        if not self._ws:
            if throw:
                raise Exception("Tunnel not ready (Init Connecting))")
            return False
        try:
            _ = self._ws.sock.sock.getpeername()
            connected = self._ws.sock.connected
        except Exception:
            if throw:
                raise Exception(">>Tunnel Disconnected")
            return False
        if not connected:
            if throw:
                raise Exception(">>>Tunnel Disconnected")
            return False
        return True

    def send_data(self, session_id: str, bytebuf: bytes):
        for sub_bytebuf in chunk_list(bytebuf, 1024):
            data_frame = Frame(
                op_type=OP_DATA,
                session_id=session_id,
                payload=sub_bytebuf,
            )
            self._send_frame(data_frame)

    def _send_frame(self, frame: Frame, method: str = None) -> None:
        self.check_connected(throw=True)
        self._trace(frame, True, method)
        self._ws.send(frame.to_bytes(), ABNF.OPCODE_BINARY)

    def _handle_frame(self, ws, frame_bytes):
        frame = bytes_to_frame(frame_bytes)
        self._trace(frame, send=False)
        if frame.op_type == OP_CONTROL:
            payload = frame.payload
            jrpc = json.loads(payload.decode('utf-8'))
            jrpc_id = jrpc['id']

            if jrpc_id in self._responseFutures:
                method, future = self._responseFutures.get(jrpc_id)
                del self._responseFutures[jrpc_id]
            else:                   # request
                method = jrpc.get('method')

            if method == 'echo-request':
                self._send_frame(JRPCResponse.of(jrpc_id).to_frame(), 'echo-response')
            elif method == 'termination-response':
                pass
            elif method == 'termination-request':
                try:
                    session_id = jrpc['params']['session-id']
                    if session_id in self._clients:
                        ctx = self._clients[session_id]
                        if isinstance(ctx, simple_proxy.ShellChannelHandler):
                            handler = ctx
                            handler.channel_inactive(ShellContext(self, session_id))
                        else:
                            ctx.close()
                        self.remove_session(session_id)
                finally:
                    self._send_frame(JRPCResponse.of(jrpc_id).to_frame(), 'termination-response')
            elif method == 'session-request-response':
                future.set_result(jrpc)
            elif method == 'agent-hello-ack':
                pass
            elif method == 'session-request':
                session_id = jrpc['params']['session-id']
                if jrpc['params'].get('shell'):
                    if not _enable_shell_proxy:
                        self._send_frame(JRPCResponse.of(jrpc_id, error={
                            'reason': "shell proxy not enabled"
                        }).to_frame(), 'session-request-response')
                        return
                    ok = self._create_shell_proxy(session_id)
                    if ok:
                        self._send_frame(JRPCResponse.of(jrpc_id).to_frame(), 'session-request-response')
                    else:
                        self._send_frame(JRPCResponse.of(jrpc_id, error={
                            'reason': f"fail to create shell proxy for session:{session_id}"
                        }).to_frame(), 'session-request-response')
                elif not _enable_reverse_proxy:
                    self._send_frame(JRPCResponse.of(jrpc_id, error={
                        'reason': "reverse proxy not enabled"
                    }).to_frame(), 'session-request-response')
                    return
                else:
                    ip = jrpc['params']['ip']
                    port = jrpc['params']['port']
                    ok = self._create_reverse_proxy(session_id, ip, port)
                    if ok:
                        self._send_frame(JRPCResponse.of(jrpc_id).to_frame(), 'session-request-response')
                    else:
                        self._send_frame(JRPCResponse.of(jrpc_id, error={
                            'reason': f"fail to connect {ip}:{port}/session:{session_id}"
                        }).to_frame(), 'session-request-response')
            else:
                log_print(f"Unknown method: {method}", fg='red')
        elif frame.op_type == OP_DATA:
            session_id = frame.session_id
            payload = frame.payload
            if session_id in self._clients:
                ctx = self._clients[session_id]
                if isinstance(ctx, simple_proxy.ShellChannelHandler):
                    handler = ctx
                    handler.channel_read(ShellContext(self, session_id), payload)
                else:
                    ctx.write(payload)

    def _create_reverse_proxy(self, session_id: int, ip: str, port: int) -> bool:
        try:
            b = Bootstrap(
                eventloop_group=WORKER,
                handler_initializer=lambda: ReverseProxyChannelHandler(self, session_id)
            )
            channel = b.connect(ip, port).sync().channel()
            if not channel.is_active():
                log_print(f"[Reverse]Failed to connect to {ip}:{port}", fg='red', level=logging.ERROR)
                return False
        except Exception as e:
            log_print(f"[Reverse]Failed to connect to {ip}:{port} ({e})", fg='red', level=logging.ERROR)
            return False
        self._clients[session_id] = channel.context()
        return True

    def _create_shell_proxy(self, session_id: int) -> bool:
        handler = simple_proxy.ShellChannelHandler()
        try:
            handler.channel_active(ShellContext(self, session_id))
            self._clients[session_id] = handler
            return True
        except Exception as e:
            log_print(f"[Shell]Failed to create shell: {e}", fg='red', level=logging.ERROR)
            return False

    def remove_session(self, session_id: int) -> None:
        self._clients.pop(session_id, None)

    def send_termination_request(self, session_id: int) -> None:
        assert self._thread is not None and threading.current_thread() != self._thread
        if session_id not in self._clients:
            return
        tr = TerminationRequest.of(session_id)
        self._responseFutures[tr.id] = ('termination-response', Future())
        self._send_frame(tr.to_frame())

    def send_session_request(self, ctx) -> int:  # return session_id
        """This method is called by the client (Netty thread) to request a new session."""
        assert self._thread is not None and threading.current_thread() != self._thread
        if _proxy_ip and _proxy_port:
            sr = SessionRequest.of(_proxy_ip, _proxy_port)
        else:
            sr = SessionRequest.socks5()
        future = Future()
        self._responseFutures[sr.id] = ('session-request-response', future)
        s = time.perf_counter()
        self._send_frame(sr.to_frame())
        try:
            jrpc = future.result(_session_request_timeout)  # wait for response
            e = time.perf_counter()
            self._session_create_metric.record(e - s)
        except TimeoutError:
            raise Exception(f"Session request timeout [{self._session_create_metric}]")
        session_id = jrpc['result']['session-id']
        self._clients[session_id] = ctx
        return session_id

    @sneaky()
    def _on_open(self, ws):
        with _lock:
            log_print(f"[on_open {_actives()}/{len(_tunnels)}] Opened connection @{self._count} {socket_description(ws.sock.sock)} (threads/frames:{threading.active_count()}/{len(inspect.stack())})", fg='bright_blue', force_print=True)
            # for thread in threading.enumerate():
            #     print(thread.name)

        self._localport = ws.sock.sock.getsockname()[1]
        self._thread = threading.current_thread()
        self._ws = ws
        if self._clients:
            clients_count = len(self._clients)
            log_print(f"Closing {clients_count} stale connections ...", fg='magenta')
        for ctx in self._clients.values():
            ctx.close()
        self._responseFutures = {}
        self._clients = {}
        self.create_session_create_metric()

        obj = Hello()
        obj.params.update(self.hello_params)
        obj.params['myip'] = my_ip()
        obj.params['reverse'] = _enable_reverse_proxy
        obj.params['shell'] = _enable_shell_proxy
        self._responseFutures[obj.id] = ('agent-hello-ack', Future())
        self._send_frame(obj.to_frame())

    @sneaky()
    def _on_message(self, ws, bytes):
        frames = decoder.decode(bytes)
        for frame in frames:
            self._handle_frame(ws, frame)

    def _on_close(self, ws, close_status_code, close_msg):
        with _lock:
            log_print(f"[on_close {_actives()}/{len(_tunnels)}] Connection closed @{self._count}, status code: {close_status_code}, message: {close_msg} [{self._session_create_metric}]", fg='red', force_print=True)
        if close_status_code == STATUS_TRY_AGAIN_LATER:
            log_print(f"Reconnecting @{self._count} in {RECONNECT} seconds ...", fg='magenta', force_print=True, level=logging.WARNING)
            time.sleep(RECONNECT)
            wst = threading.Thread(target=self.start)
            wst.daemon = True
            wst.start()
            # self.start()
        else:
            log_print(f"No reconnection @{self._count}", fg='magenta', force_print=True, level=logging.WARNING)

    def _on_error(self, ws, error):
        with _lock:
            log_print(f"[on_error @{self._count} {_actives()}/{len(_tunnels)}] {error} [{self._session_create_metric}]", fg='red', level=logging.ERROR, force_print=True)

    def _trace(self, frame: Frame, send=True, method: str = None):
        if _quiet:
            return
        tunnel_identifier = f"#{self._count}:{self._localport}".center(10)
        direction = '>>>' if send else '<<<'
        fg = 'yellow' if not send else None
        now = f"{str(datetime.now()):<20}"
        if frame.op_type == OP_CONTROL:
            jrpc = json.loads(frame.payload.decode('utf-8'))
            jrpc_id = jrpc['id']
            method = method or jrpc.get('method')
            if not method:
                if jrpc_id in self._responseFutures:
                    method, _ = self._responseFutures.get(jrpc_id)
                else:
                    method = '?'

            if 'agent-hello' == method:
                msg0 = jrpc.get('params')
            elif 'agent-hello-ack' == method:
                msg0 = jrpc.get('result')
            elif 'response' in method:
                e = jrpc.get('error')
                msg0 = e or jrpc.get('result')
                if e:
                    fg = 'red'
            elif 'request' in method:
                msg0 = jrpc.get('params', jrpc)
            else:
                msg0 = jrpc

            if isinstance(msg0, dict):
                msg0 = json.dumps(msg0)

            session_count = len(self._clients)
            if method == 'session-request-response' and not send:
                session_count += 1

            msg = f"{now} | {tunnel_identifier} | {direction} | {method:<25} | {jrpc_id} | sessions: {session_count}"

            if logger.isEnabledFor(logging.DEBUG):
                msg += f" | futures: {len(self._responseFutures)}"
            msg += f" | {msg0}"
        elif frame.op_type == OP_DATA:
            if not _trace_data:
                return
            session_id = frame.session_id
            msg = f"{now} | {tunnel_identifier} | {direction} | [{'OP_DATA: ' + str(session_id):<25}] <<{len(frame.payload)} bytes>>"
            ctx = self._clients.get(session_id)
            if ctx:
                msg += f" {ctx.channel()}"
            if not send and not ctx:
                fg = 'red'
        else:
            msg = f"{now} | {tunnel_identifier} | {direction} | Are you kidding me?"

        log_print(msg, fg=fg, level=logging.DEBUG)


class ReverseProxyChannelHandler(ChannelHandlerAdapter):

    def __init__(self, tunnel: Tunnel, session_id: int):
        self._session_id = session_id
        self._tunnel = tunnel
        self._tunnel_seq = tunnel._count

    def exception_caught(self, ctx, exception):
        logger.error("[Reverse][Exception Caught #%d @%d] %s : %s",
                     self._session_id, self._tunnel_seq, ctx.channel(), str(exception), exc_info=exception)
        click.secho(f"[Reverse][Exception Caught #{self._session_id} @{self._tunnel_seq}] {ctx.channel()} : {str(exception)}", fg='red')
        ctx.close()

    def channel_active(self, ctx):
        log_print(f"[Reverse][channel_active #{self._session_id} @{self._tunnel_seq}] {ctx.channel()}", fg='green', level=logging.DEBUG)

    def channel_read(self, ctx, bytebuf):
        self._tunnel.send_data(self._session_id, bytebuf)

    def channel_inactive(self, ctx):
        log_print(f"[Reverse][channel_inactive #{self._session_id} @{self._tunnel_seq}] {ctx.channel()}", fg='bright_black', level=logging.DEBUG)
        try:
            self._tunnel.send_termination_request(self._session_id)
        finally:
            self._tunnel.remove_session(self._session_id)


class ProxyChannelHandler(ChannelHandlerAdapter):

    def __init__(self):
        self._session_id = None
        self._tunnel = self._next_valid_tunnel()
        self._tunnel_seq = self._tunnel._count if self._tunnel else '?'

    @staticmethod
    def _next_valid_tunnel() -> Optional[Tunnel]:
        for _ in range(len(_tunnels)):
            t = next(tunnels)
            if t.check_connected():
                return t

    def exception_caught(self, ctx, exception):
        exception_str = str(exception)
        internal = 'Tunnel Disconnected' in exception_str
        logger.error("[Exception Caught #%s @%s] %s : %s", self._session_id or '?', self._tunnel_seq, ctx.channel(), exception_str, exc_info=exception if not internal else None)
        click.secho(f"[Exception Caught #{self._session_id or '?'} @{self._tunnel_seq}] {ctx.channel()} : {exception_str}", fg='red')
        ctx.close()

    def channel_read(self, ctx, bytebuf):
        if not self._session_id:
            ctx.close()         # failed to get seesion_id and there is incoming data here
            return
        self._tunnel.send_data(self._session_id, bytebuf)

    def channel_active(self, ctx):
        log_print(f"[channel_active @{self._tunnel_seq}] {ctx.channel()}", fg='green', level=logging.DEBUG)
        if self._tunnel is None:
            log_print(f"{ctx.channel()} All tunnels disconnected!!", fg='red', level=logging.ERROR)
            ctx.close()
            return
        self._session_id = self._tunnel.send_session_request(ctx)
        if self._session_id < 0:
            log_print(f"Failed to establish session with {ctx.channel()}", fg='red', level=logging.ERROR)
            ctx.close()
            return

    def channel_inactive(self, ctx):
        log_print(f"[channel_inactive #{self._session_id or '?'} @{self._tunnel_seq}] {ctx.channel()}", fg='bright_black', level=logging.DEBUG)
        if self._session_id:
            try:
                self._tunnel.send_termination_request(self._session_id)
            finally:
                self._tunnel.remove_session(self._session_id)


def _config_logging():
    from logging.handlers import RotatingFileHandler

    logging.basicConfig(
        handlers=[
            RotatingFileHandler(
                filename="elephant-client.log",
                maxBytes=10 * 1024 * 1024,  # 10M
                backupCount=10,
            ),
            # logging.StreamHandler(),  # default to stderr
        ],
        level=logging.INFO,
        format='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(threadName)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger.setLevel(logging.INFO)


@click.command(short_help="Elephant SOCKS5 client", context_settings=dict(help_option_names=['-h', '--help'], max_content_width=120))
@click.option('--port', '-p', default=1080, help="Local port to bind", show_default=True, type=int)
@click.option('--global', '-g', 'global_', is_flag=True, help="Listen on all interfaces")
@click.option('--server', '-s', 'urls', help=f"Elephant tunnel server URLs (like: {URL})", type=str, required=True)
@click.option('--alias', '-a', help="Alias for the client", type=str)
@click.option('--quiet', '-q', is_flag=True, help="Quiet mode")
@click.option('--enable-shell-proxy', '-esp', 'enable_shell_proxy', is_flag=True, help="Enable Shell proxy")
@click.option('--enable-reverse-proxy', '-erp', 'enable_reverse_proxy', is_flag=True, help="Enable reverse proxy")
@click.option('--reverse-proxy-only', '-rpo', 'reverse_proxy_only', is_flag=True, help="No SOCKS5 server, only for reverse proxy")
@click.option('--reverse-endpoint', '-re', 'reverse_endpoints', help="Endpoints(host:port) for reverse proxy", multiple=True, type=str)
@click.option('--reverse-ip', help="Reverse proxy IP", type=str, hidden=True)
@click.option('--reverse-port', help="Reverse proxy port", type=int, default=-1, show_default=True, hidden=True)
@click.option('--no-reverse-global', 'no_reverse_global', is_flag=True, help="Reverse proxy listen on localhost")
@click.option('--log-record', '-l', 'save_log', is_flag=True, help="Save log to file (elephant-client.log)")
@click.option('--request-timeout', '-t', 'session_request_timeout', default=3, help="Session request timeout (seconds)", show_default=True, type=int)
@click.option('--no-color', is_flag=True, help="Disable color output")
@click.option('--verbose', '-v', 'verbose', is_flag=True, help="Verbose mode")
@click.option('--tunnels', '-n', 'tunnel_count', default=1, help="Number of tunnels to achieve load balance", show_default=True, type=click.IntRange(1, clamp=True))
@click.option('--proxy-ip', help="Proxy IP", type=str)
@click.option('--proxy-port', help="Proxy port", type=int, default=-1, show_default=True)
@click.version_option(version=__version__, prog_name="Elephant SOCKS5 Client")
def _cli(
        port, urls, alias, tunnel_count,
        quiet, save_log, session_request_timeout, no_color,
        proxy_ip, proxy_port, global_,
        enable_shell_proxy,
        enable_reverse_proxy, reverse_endpoints, reverse_ip, reverse_port, no_reverse_global,
        verbose, reverse_proxy_only,
):
    global _quiet
    global _session_request_timeout
    global _no_color
    global _tunnels
    global tunnels              # cycle list of tunnels
    global _proxy_ip
    global _proxy_port
    global _enable_reverse_proxy
    global _enable_shell_proxy

    if proxy_ip:
        _proxy_ip = proxy_ip
        assert 0 < proxy_port < 65536, "Invalid proxy port"
        _proxy_port = proxy_port

    if reverse_endpoints:
        nomalized = []
        for ep in reverse_endpoints:
            if ':' in ep:
                h, p = ep.split(':')
                p = int(p)
                nomalized.append((h, p))
            else:
                if reverse_port > 0:
                    nomalized.append((ep, reverse_port))
                else:
                    nomalized.append((ep, 8080))
        reverse_endpoints = [{'host': h, 'port': p} for h, p in nomalized]
    else:
        reverse_endpoints = []
    if reverse_ip and reverse_port > 0:
        reverse_endpoints.append({'host': reverse_ip, 'port': reverse_port})

    _no_color = no_color
    _quiet = quiet
    _session_request_timeout = session_request_timeout
    _enable_reverse_proxy = enable_reverse_proxy or reverse_proxy_only or reverse_endpoints
    _enable_shell_proxy = enable_shell_proxy

    hello_params = {}
    hello_params['alias'] = alias or socket.gethostname()
    hello_params['reverseEndpoints'] = reverse_endpoints
    hello_params['reverseGlobal'] = not no_reverse_global

    if save_log or quiet:
        _config_logging()

    if verbose:
        logger.setLevel(logging.DEBUG)

    if enable_shell_proxy and not quiet:
        simple_proxy._stderr = True

    urls = set(urls.split(','))
    tunnel_count = max(tunnel_count, len(urls))
    urls = cycle(urls)
    _tunnels = [Tunnel(next(urls), hello_params.copy()) for _ in range(tunnel_count)]
    tunnels = cycle(_tunnels)
    for t in _tunnels:
        wst = threading.Thread(target=t.start)
        wst.daemon = True
        wst.start()

    log_print(f"Waiting for all {len(_tunnels)} tunnels to be ready ...", underline=True, force_print=True)
    count = 10
    while not all(t.check_connected() for t in _tunnels):
        count -= 1
        time.sleep(0.5)
        if count <= 0:
            log_print("Timeout waiting for all tunnels to be ready, abort", fg='red', level=logging.ERROR, force_print=True)
            return

    if reverse_proxy_only:
        log_print("Reverse proxy only mode!!", underline=True, force_print=True)
        while True:
            time.sleep(86400)
        return

    log_print(f"Proxy server started and listening on port {port} ...", fg='green', underline=True, force_print=True)
    sb = ServerBootstrap(
        parant_group=ACCEPTOR,
        child_group=WORKER,
        child_handler_initializer=ProxyChannelHandler
    )

    sb.bind(address='0.0.0.0' if global_ else '127.0.0.1', port=port).close_future().sync()


def _run():
    _cli()
