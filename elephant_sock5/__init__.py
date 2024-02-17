import click
from datetime import datetime
import ssl
import logging
import websocket
from concurrent.futures import Future
from websocket._abnf import ABNF
from elephant_sock5.protocol import bytes_to_frame, OP_CONTROL, OP_DATA, JRPCResponse, SessionRequest, Hello, Frame, TerminationRequest
from elephant_sock5.utils import LengthFieldBasedFrameDecoder, chunk_list, sneaky, socket_description
from click import secho
import json
from py_netty import ServerBootstrap, ChannelHandlerAdapter, EventLoopGroup


logger = logging.getLogger(__name__)

URL = "ws[s]://localhost:4443/elephant/ws"

decoder = LengthFieldBasedFrameDecoder()

responseFuture = {}

tunnel = None

clients = {}

_quiet = False
_trace_data = False
_session_request_timeout = 3


def _trace(frame: Frame, send=True, method: str = None):
    if _quiet:
        return
    direction = '>>>' if send else '<<<'
    fg = 'yellow' if not send else None
    now = f"{str(datetime.now()):<20}"
    if frame.op_type == OP_CONTROL:
        jrpc = json.loads(frame.payload.decode('utf-8'))
        jrpc_id = jrpc['id']
        method = method or jrpc.get('method')
        if not method:
            if jrpc_id in responseFuture:
                method, _ = responseFuture.get(jrpc_id)
            else:
                method = '??????'

        if 'hello' in method:
            msg0 = jrpc.get('jrpc', jrpc.get('jsonrpc', "???"))
        elif 'response' in method:
            msg0 = jrpc.get('result', jrpc)
        elif 'request' in method:
            msg0 = jrpc.get('params', jrpc)
        else:
            msg0 = jrpc

        if isinstance(msg0, dict):
            msg0 = json.dumps(msg0)

        msg = f"{now} | {direction} | {method:<25} | {jrpc_id} | {msg0}"
        if method == 'session-request-response':
            current_total = len(clients) + 1
            msg += f" | current total: {current_total}"
    elif frame.op_type == OP_DATA:
        if not _trace_data:
            return
        session_id = frame.session_id
        msg = f"{now} | {direction} | [{'OP_DATA: ' + str(session_id):<25}] <<{len(frame.payload)} bytes>>"
        ctx = clients.get(session_id)
        if ctx:
            msg += f" {ctx.channel()}"
        if not send and not ctx:
            fg = 'red'
    else:
        msg = f"{now} | {direction} | Are you kidding me?"
    logger.debug(msg)
    click.secho(msg, fg=fg)


def handle_frame(ws, frame_bytes):
    frame = bytes_to_frame(frame_bytes)
    _trace(frame, send=False)
    if frame.op_type == OP_CONTROL:
        payload = frame.payload
        jrpc = json.loads(payload.decode('utf-8'))
        jrpc_id = jrpc['id']

        if jrpc_id in responseFuture:
            method, future = responseFuture.get(jrpc_id)
            del responseFuture[jrpc_id]
        else:                   # request
            method = jrpc.get('method')

        if method == 'echo-request':
            _send_frame(JRPCResponse.of(jrpc_id).to_frame(), 'echo-response')
        elif method == 'termination-request':
            _send_frame(JRPCResponse.of(jrpc_id).to_frame(), 'termination-response')
            session_id = jrpc['params']['session-id']
            if session_id in clients:
                ctx = clients[session_id]
                ctx.close()
                del clients[session_id]
        elif method == 'session-request-response':
            future.set_result(jrpc)
        elif method == 'agent-hello-ack':
            pass
    elif frame.op_type == OP_DATA:
        session_id = frame.session_id
        payload = frame.payload
        if session_id in clients:
            ctx = clients[session_id]
            ctx.write(payload)


@sneaky()
def on_message(ws, bytes):
    frames = decoder.decode(bytes)
    for frame in frames:
        handle_frame(ws, frame)


def on_close(ws, close_status_code, close_msg):
    msg = f"[on_close] Connection closed, status code: {close_status_code}, message: {close_msg}"
    logger.info(msg)
    click.secho(msg, underline=True, fg='red')


def on_error(ws, error):
    if error and str(error):
        secho(f"[on_error] {error}", fg='red')


def _send_frame(frame: Frame, method: str = None) -> None:
    global tunnel
    if not tunnel or not tunnel.sock:
        raise Exception("Tunnel is not ready")
    if tunnel.sock.fileno() < 0:
        raise Exception("Tunnel is not active")
    _trace(frame, True, method)
    tunnel.send(frame.to_bytes(), ABNF.OPCODE_BINARY)


@sneaky()
def on_open(ws):
    msg = f"[on_open] Opened connection {socket_description(ws.sock.sock)}"
    logger.info(msg)
    click.secho(msg, underline=True)
    for ctx in clients.copy().values():
        logger.info(f"Closing {ctx.channel()}")
        ctx.close()
    responseFuture.clear()
    clients.clear()
    global tunnel
    tunnel = ws
    obj = Hello()
    responseFuture[obj.id] = ('agent-hello-ack', Future())
    _send_frame(obj.to_frame())


@sneaky()
def start_client(url):
    ws = websocket.WebSocketApp(
        url,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    # ws.run_forever(dispatcher=rel, reconnect=5)
    if url.startswith('wss://'):
        ws.run_forever(reconnect=10, sslopt={"cert_reqs": ssl.CERT_NONE})
    else:
        ws.run_forever(reconnect=10)
    # ws.run_forever(reconnect=10)
    # rel.signal(2, rel.abort)
    # rel.dispatch()


class ProxyChannelHandler(ChannelHandlerAdapter):

    def __init__(self):
        self._session_id = None

    def exception_caught(self, ctx, exception):
        logger.error("[Exception Caught] %s : %s", ctx.channel(), str(exception), exc_info=exception)
        ctx.close()

    def channel_read(self, ctx, bytebuf):
        global tunnel
        if not self._session_id:
            # sr = SessionRequest.of('10.74.113.125', 8080)
            # sr = SessionRequest.of('localhost', 8080)
            sr = SessionRequest.sock5()
            future = Future()
            responseFuture[sr.id] = ('session-request-response', future)
            _send_frame(sr.to_frame())
            r = future.result(_session_request_timeout)
            self._session_id = r['result']['session-id']
            clients[self._session_id] = ctx

        for sub_bytebuf in chunk_list(bytebuf, 1024):
            data_frame = Frame(
                op_type=OP_DATA,
                session_id=self._session_id,
                payload=sub_bytebuf,
            )
            _send_frame(data_frame)

    def channel_active(self, ctx):
        msg = f"[channel_active] {ctx.channel()}"
        logger.info(msg)
        click.secho(msg, fg='green')

    def channel_inactive(self, ctx):
        msg = f"[channel_inactive] {ctx.channel()}"
        click.secho(msg, fg='bright_black')
        if self._session_id:
            tr = TerminationRequest.of(self._session_id)
            responseFuture[tr.id] = ('termination-response', Future())
            _send_frame(tr.to_frame())
            if self._session_id in clients:
                del clients[self._session_id]
        pass


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


@click.command(short_help="Elephant SOCK5 client", context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--port', '-p', default=1080, help="Local port to bind", show_default=True, type=int)
@click.option('--server', '-s', 'url', help=f"Elephant tunnel server URL (like: {URL})", type=str, required=True)
@click.option('--quiet', '-q', is_flag=True, help="Quiet mode")
@click.option('--log-record', '-l', 'save_log', is_flag=True, help="Save log to file (elephant-client.log)")
@click.option('--session-request-timeout', '-t', default=3, help="Session request timeout", show_default=True, type=int)
def _cli(port, url, quiet, save_log, session_request_timeout):
    global _quiet
    global _session_request_timeout
    _session_request_timeout = session_request_timeout
    if quiet:
        _quiet = True
        logger.setLevel(logging.ERROR)

    if save_log:
        _config_logging()

    sb = ServerBootstrap(
        parant_group=EventLoopGroup(1, 'Acceptor'),
        child_group=EventLoopGroup(1, 'Worker'),
        child_handler_initializer=ProxyChannelHandler
    )

    sb.bind(port=port)
    msg = f"Proxy server started at port {port}"
    logger.info(msg)
    click.echo(msg)
    start_client(url)


def _run():
    _cli()
