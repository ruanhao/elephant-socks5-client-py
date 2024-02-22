from typing import List, Tuple, Optional
import traceback
import os
import re
import sys
from functools import wraps
import inspect
import logging
from urllib.parse import urlparse, parse_qs


_logger = logging.getLogger(__name__)


class LengthFieldBasedFrameDecoder:

    def __init__(self, length_field_length=2, length_field_offset=4):
        self.length_field_length = length_field_length
        self.length_field_offset = length_field_offset
        self.cumulate = b''

    def decode(self, data) -> List[bytes]:
        data = self.cumulate + data
        result = []
        while True:
            frame, data = self._decode(data)
            if frame is None:
                break
            result.append(frame)
        self.cumulate = data
        return result

    def _decode(self, data) -> Tuple[Optional[bytes], bytes]:
        if len(data) < self.length_field_offset + self.length_field_length:
            return None, data

        length_field = data[self.length_field_offset:self.length_field_offset + self.length_field_length]
        frame_length = int.from_bytes(length_field, byteorder='big')
        full_frame_length = self.length_field_offset + self.length_field_length + frame_length
        if len(data) < full_frame_length:
            return None, data

        frame_data = data[:full_frame_length]
        return frame_data, data[full_frame_length:]


def chunk_list(lst, chunk_size=65535):
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def _all_args_repr(args, kw):
    try:
        args_repr = [repr(arg) for arg in args]
        kws = [f"{k}={repr(v)}" for k, v in kw.items()]
        return ', '.join(args_repr + kws)
    except (Exception,):
        return "(?)"


def _get_logger():
    frm = inspect.stack()[1]
    mod = inspect.getmodule(frm[0])
    for k, v in mod.__dict__.items():
        if isinstance(v, logging.Logger):
            return v
    return _logger


def sneaky(logger: logging.Logger = None, console: bool = False):
    logger = logger or _get_logger()

    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kw):
            all_args = _all_args_repr(args, kw)
            try:
                return func(*args, **kw)
            except Exception as e:
                emsg = f"[{e}] sneaky call: {func.__name__}({all_args})"
                if logger:
                    logger.exception(emsg)
                if console:
                    print(emsg, traceback.format_exc(), file=sys.stderr, sep=os.linesep, flush=True)
        return wrapper
    return decorate


def socket_description(sock):
    """[id: 0xd829bade, L:/127.0.0.1:2069 - R:/127.0.0.1:55666]"""
    sock_id = hex(id(sock))
    fileno = sock.fileno()
    s_addr = None
    try:
        s_addr, s_port = sock.getsockname()[:2]
        d_addr, d_port = sock.getpeername()[:2]
        return f"[id: {sock_id}, fd: {fileno}, L:/{s_addr}:{s_port} - R:/{d_addr}:{d_port}]"
    except (Exception,):
        if s_addr:
            return f"[id: {sock_id}, fd: {fileno}, LISTENING]"
        else:
            return f"[id: {sock_id}, fd: {fileno}, CLOSED]"


def has_format_placeholders(s):
    pattern = re.compile(r'{.*}|%[sd]')
    return bool(re.search(pattern, s))


def parse_uri(uri):
    # Parse the URI
    parsed_uri = urlparse(uri)

    # Extract parameters from the query string
    params = parse_qs(parsed_uri.query)

    return params
