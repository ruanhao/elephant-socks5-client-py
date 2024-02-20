import click
import time
from datetime import datetime
import threading
import ssl
import logging
import websocket
from concurrent.futures import Future
from websocket._abnf import ABNF
from elephant_sock5.protocol import bytes_to_frame, OP_CONTROL, OP_DATA, JRPCResponse, SessionRequest, Hello, Frame, TerminationRequest
from elephant_sock5.utils import LengthFieldBasedFrameDecoder, chunk_list, sneaky, socket_description, has_format_placeholders
from elephant_sock5.version import __version__
from click import secho
import json
import string
from py_netty import Bootstrap, ServerBootstrap, ChannelHandlerAdapter, EventLoopGroup
from attrs import define, field
from itertools import cycle, count


logger = logging.getLogger("elephant-sock5")

URL = "ws[s]://localhost:4443/elephant/ws"

decoder = LengthFieldBasedFrameDecoder()

_quiet = False
_trace_data = False
_session_request_timeout = 3
_no_color = False

_proxy_ip = None
_proxy_port = None

tunnels = None                  # cycle
_counter = count(start=0, step=1)

ACCEPTOR = EventLoopGroup(1, 'Acceptor')
WORKER = EventLoopGroup(1, 'Worker')


def log_print(msg, *args, fg=None, underline=None, level=logging.INFO, **kwargs):
    logger.log(level, msg, *args, **kwargs)
    if not _quiet:
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
        secho(message, fg=fg, underline=underline)


@define(slots=False)
class Tunnel:

    url: str = field()

    def __attrs_post_init__(self):
        self._clients = {}      # session_id -> ctx
        self._responseFutures = {}  # id -> (method, Future(jrpc))
        self._ever_active = False
        self._thread = None     # WebSocket thread
        self._localport = -1
        self._count = next(_counter)

    @sneaky()
    def start(self):
        self._ws = websocket.WebSocketApp(
            self.url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close
        )

        # ws.run_forever(dispatcher=rel, reconnect=5)
        log_print(f"Starting Tunnel#{self._count} (URL: {self.url}) ...", underline=True)
        self._ws.run_forever(reconnect=10, sslopt={"cert_reqs": ssl.CERT_NONE})
        # rel.signal(2, rel.abort)
        # rel.dispatch()

    def _send_frame(self, frame: Frame, method: str = None) -> None:
        if not self._ever_active or not self._ws:
            raise Exception("Tunnel not ready (Init Connecting))")
        if not self._ws.sock:
            raise Exception(">Tunnel Disconnected (Reconnecting)")
        connected = False
        try:
            connected = self._ws.sock.connected
        except Exception:
            raise Exception(">>Tunnel Disconnected (Reconnecting)")
        if not connected:
            raise Exception(">>>Tunnel Disconnected (Reconnecting)")

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
                self._send_frame(JRPCResponse.of(jrpc_id).to_frame(), 'termination-response')
                session_id = jrpc['params']['session-id']
                if session_id in self._clients:
                    ctx = self._clients[session_id]
                    ctx.close()
                    self.remove_session(session_id)
            elif method == 'session-request-response':
                future.set_result(jrpc)
            elif method == 'agent-hello-ack':
                pass
            elif method == 'session-request':
                ip = jrpc['params']['ip']
                port = jrpc['params']['port']
                session_id = jrpc['params']['session-id']
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
            sr = SessionRequest.sock5()
        future = Future()
        self._responseFutures[sr.id] = ('session-request-response', future)
        self._send_frame(sr.to_frame())
        jrpc = future.result(_session_request_timeout)  # wait for response
        session_id = jrpc['result']['session-id']
        self._clients[session_id] = ctx
        return session_id

    @sneaky()
    def _on_open(self, ws):
        log_print(f"[on_open] Opened connection#{self._count} {socket_description(ws.sock.sock)}", fg='bright_blue')
        self._localport = ws.sock.sock.getsockname()[1]
        self._thread = threading.current_thread()
        self._ws = ws
        self._ever_active = True
        if self._clients:
            clients_count = len(self._clients)
            log_print(f"Closing {clients_count} stale connections ...", fg='magenta')
        for ctx in self._clients.values():
            ctx.close()
        self._responseFutures = {}
        self._clients = {}

        obj = Hello()
        self._responseFutures[obj.id] = ('agent-hello-ack', Future())
        self._send_frame(obj.to_frame())

    @sneaky()
    def _on_message(self, ws, bytes):
        frames = decoder.decode(bytes)
        for frame in frames:
            self._handle_frame(ws, frame)

    def _on_close(self, ws, close_status_code, close_msg):
        log_print(f"[on_close] Connection closed, status code: {close_status_code}, message: {close_msg}", fg='red')

    def _on_error(self, ws, error):
        if error and str(error):
            log_print(f"[on_error] {error}", fg='red', level=logging.ERROR)

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
                    method = '??????'

            if 'hello' in method:
                msg0 = jrpc.get('jrpc', jrpc.get('jsonrpc', "???"))
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

            msg = f"{now} | {tunnel_identifier} | {direction} | {method:<25} | {jrpc_id}"

            current_total = None
            if method == 'session-request-response':
                current_total = (len(self._clients) + 1) if not send else len(self._clients)
            elif method == 'termination-request':
                current_total = len(self._clients) - 1
            elif method == 'termination-response':
                current_total = len(self._clients)
            if current_total is not None:
                msg += f" | sessions: {current_total}"
            if logger.isEnabledFor(logging.DEBUG):
                msg += f" | futures: {max(len(self._responseFutures) - 1, 0)}"
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

    def exception_caught(self, ctx, exception):
        logger.error("[Reverse][Exception Caught] %s : %s", ctx.channel(), str(exception), exc_info=exception)
        click.secho(f"[Reverse][Exception Caught] {ctx.channel()} : {str(exception)}", fg='red')
        ctx.close()

    def channel_active(self, ctx):
        log_print(f"[Reverse][channel_active] {ctx.channel()}", fg='green', level=logging.DEBUG)

    def channel_read(self, ctx, bytebuf):
        for sub_bytebuf in chunk_list(bytebuf, 1024):
            data_frame = Frame(
                op_type=OP_DATA,
                session_id=self._session_id,
                payload=sub_bytebuf,
            )
            self._tunnel._send_frame(data_frame)

    def channel_inactive(self, ctx):
        log_print(f"[Reverse][channel_inactive] {ctx.channel()}", fg='bright_black', level=logging.DEBUG)
        try:
            self._tunnel.send_termination_request(self._session_id)
        finally:
            self._tunnel.remove_session(self._session_id)


class ProxyChannelHandler(ChannelHandlerAdapter):

    def __init__(self):
        self._session_id = None
        self._tunnel: Tunnel = next(tunnels)

    def exception_caught(self, ctx, exception):
        logger.error("[Exception Caught] %s : %s", ctx.channel(), str(exception), exc_info=exception)
        click.secho(f"[Exception Caught] {ctx.channel()} : {str(exception)}", fg='red')
        ctx.close()

    def channel_read(self, ctx, bytebuf):
        if not self._session_id:
            self._session_id = self._tunnel.send_session_request(ctx)
            if self._session_id < 0:
                log_print(f"Failed to establish session with {ctx.channel()}", fg='red', level=logging.ERROR)
                ctx.close()
                return

        for sub_bytebuf in chunk_list(bytebuf, 1024):
            data_frame = Frame(
                op_type=OP_DATA,
                session_id=self._session_id,
                payload=sub_bytebuf,
            )
            self._tunnel._send_frame(data_frame)

    def channel_active(self, ctx):
        log_print(f"[channel_active] {ctx.channel()}", fg='green', level=logging.DEBUG)

    def channel_inactive(self, ctx):
        log_print(f"[channel_inactive] {ctx.channel()}", fg='bright_black', level=logging.DEBUG)
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


@click.command(short_help="Elephant SOCK5 client", context_settings=dict(help_option_names=['-h', '--help'], max_content_width=120))
@click.option('--port', '-p', default=1080, help="Local port to bind", show_default=True, type=int)
@click.option('--global', '-g', 'global_', is_flag=True, help="Listen on all interfaces")
@click.option('--server', '-s', 'url', help=f"Elephant tunnel server URL (like: {URL})", type=str, required=True)
@click.option('--quiet', '-q', is_flag=True, help="Quiet mode")
@click.option('--log-record', '-l', 'save_log', is_flag=True, help="Save log to file (elephant-client.log)")
@click.option('--request-timeout', '-t', 'session_request_timeout', default=3, help="Session request timeout (seconds)", show_default=True, type=int)
@click.option('--no-color', is_flag=True, help="Disable color output")
@click.option('--verbose', '-v', 'verbose', is_flag=True, help="Verbose mode")
@click.option('--tunnels', '-n', 'tunnel_count', default=1, help="Number of tunnels to achieve load balance", show_default=True, type=click.IntRange(1, 8, clamp=True))
@click.option('--proxy-ip', help="Proxy IP", type=str)
@click.option('--proxy-port', help="Proxy port", type=int, default=-1, show_default=True)
@click.version_option(version=__version__, prog_name="Elephant SOCK5 Client")
def _cli(port, url, quiet, save_log, session_request_timeout, no_color, verbose, tunnel_count, proxy_ip, proxy_port, global_):
    global _quiet
    global _session_request_timeout
    global _no_color
    global tunnels
    global _proxy_ip
    global _proxy_port

    if proxy_ip:
        _proxy_ip = proxy_ip
        assert 0 < proxy_port < 65536, "Invalid proxy port"
        _proxy_port = proxy_port

    _no_color = no_color
    _session_request_timeout = session_request_timeout

    if save_log:
        _config_logging()

    if verbose:
        logger.setLevel(logging.DEBUG)

    if quiet:
        _quiet = True
        logger.setLevel(logging.ERROR)

    all_tunnels = [Tunnel(url) for _ in range(tunnel_count)]
    for t in all_tunnels:
        wst = threading.Thread(target=t.start)
        wst.daemon = True
        wst.start()

    log_print(f"Waiting for all {len(all_tunnels)} tunnels to be ready ...", underline=True)
    count = 10
    while not all(t._ever_active for t in all_tunnels):
        count -= 1
        time.sleep(0.5)
        if count <= 0:
            log_print("Timeout waiting for tunnels to be ready", fg='red', level=logging.ERROR)
            return
    tunnels = cycle(all_tunnels)

    log_print(f"Proxy server started and listening on port {port} ...", fg='green', underline=True)
    sb = ServerBootstrap(
        parant_group=ACCEPTOR,
        child_group=WORKER,
        child_handler_initializer=ProxyChannelHandler
    )

    sb.bind(address='0.0.0.0' if global_ else '127.0.0.1', port=port).close_future().sync()


def _run():
    _cli()


def _test():
    log_print("hello", "world")                  # hello world
    log_print("hello", "world", fg='green')      # hello world
    log_print("hello %s", "world")               # hello world
    log_print("hello %s", 123)                   # hello 123
    log_print("hello {}", "world")               # hello world
    log_print("hello {w}", w="world")            # hello world
    log_print("hello world {v}", "world", v=123)  # hello world world 123


if __name__ == '__main__':
    _test()
