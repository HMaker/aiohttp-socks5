import socket
import struct
import asyncio
import ipaddress
import typing as t
from yarl import URL
from enum import IntEnum
from dataclasses import dataclass
from ssl import create_default_context, Purpose, SSLContext


SOCKS_VER = 0x05
SOCKS_RSV = 0x00

class SOCKSEnum(IntEnum):

    @classmethod
    def has(cls, value: int):
        return value in cls._value2member_map_

class SOCKSAuthMethod(SOCKSEnum):
    NO_AUTH = 0
    USERNAME = 2

class SOCKSCommand(SOCKSEnum):
    CONNECT = 1
    UDP_ASSOCIATE = 3

class SOCKSAddressType(SOCKSEnum):
    IPV4 = 1
    DOMAIN = 3
    IPV6 = 4

class SOCKSResponseCode(IntEnum):
    SUCCESS = 0
    GENERAL_ERROR = 1
    BLOCKED_BY_RULESET = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    UNSUPPORTED_COMMAND = 7
    UNSUPPORTED_ADDR_TYPE = 8


class SOCKSServerError(Exception):
    pass

class SOCKSAuthError(SOCKSServerError):
    pass


class StreamBuffer:
    """A buffer for StreamMessageReaders."""

    def __init__(self, data: bytearray) -> None:
        self._data = data
        self._index = 0

    @property
    def index(self):
        return self._index

    @property
    def unread(self):
        return len(self._data) - self._index

    def seek(self, offset: int):
        self._index += offset

    def goto(self, index: int):
        self._index = index

    def append(self, data: t.Union[bytes, bytearray, memoryview]) -> None:
        self._data += data

    def read(self, size: int):
        if self._index + size > len(self._data):
            raise IndexError('read out of bounds')
        data = (memoryview(self._data)[self._index:self._index + size]).toreadonly()
        self._index += size
        return data

    def readall(self):
        return self.read(len(self._data) - self._index)

    def can_read_string(self):
        if self.unread > 1:
            length = self.read(1)[0]
            self.seek(-1)
            if self.unread >= length + 1:
                return True
        return False

    def read_string(self) -> bytes:
        return bytes(self.read(self.read(1)[0]))

    def discard_readed(self):
        self._data = self._data[self._index:]
        self._index = 0


_T = t.TypeVar('_T')
class StreamMessageReader(t.Generic[_T]):
    """Handles message reading of stream-oriented protocols.
    
    Subclasses must declare a class-level "fields" list with method names for the message fields
    readers, these methods MUST return True if the field was fully readed, False otherwise. The
    reader finishes when all fields are readed.
    """
    fields: t.List[str] = None

    def __init__(self) -> None:
        super().__init__()
        self._index = 0

    @property
    def finished(self):
        return self._index >= len(self.fields)

    @classmethod
    async def from_stream(cls, buffer: StreamBuffer, stream: asyncio.StreamReader, **kwargs) -> _T:
        reader = cls(**kwargs)
        while True:
            reader.read(buffer)
            if reader.finished:
                buffer.discard_readed()
                return reader.get_message()
            data = await stream.read(1024)
            if len(data) == 0:
                raise ConnectionError('stream connection closed')
            buffer.append(data)

    def get_message(self) -> _T:
        raise NotImplementedError

    def read(self, buffer: StreamBuffer(bytearray(0))):
        while not self.finished and getattr(self, self.fields[self._index])(buffer):
            self._index += 1


@dataclass(frozen=True)
class SOCKSAuthNegotiationRequest:
    ver: int
    methods: t.List[SOCKSAuthMethod]

    def encode(self) -> bytes:
        return struct.pack(f'!BB{len(self.methods)}B', self.ver, len(self.methods), *self.methods)


@dataclass(frozen=True)
class SOCKSAuthNegotiationResponse:
    ver: int
    method: int

class SOCKSAuthNegResponseReader(StreamMessageReader[SOCKSAuthNegotiationResponse]):
    fields = ('read_ver', 'read_method')

    def read_ver(self, buffer: StreamBuffer):
        if buffer.unread >= 1:
            self._ver = buffer.read(1)[0]
            return True
        return False

    def read_method(self, buffer: StreamBuffer):
        if buffer.unread >= 1:
            self._method = buffer.read(1)[0]
            return True
        return False

    def get_message(self):
        return SOCKSAuthNegotiationResponse(self._ver, self._method)


@dataclass(frozen=True)
class SOCKSUsernameAuthRequest:
    ver: int
    username: str
    password: str

    def encode(self) -> bytes:
        return struct.pack(
            f'!BB{len(self.username)}sB{len(self.password)}s',
            self.ver,
            len(self.username),
            self.username.encode(),
            len(self.password),
            self.password.encode()
        )


@dataclass(frozen=True)
class SOCKSUsernameAuthResponse:
    ver: int
    status: int

class SOCKSUsernameAuthRespReader(StreamMessageReader[SOCKSUsernameAuthResponse]):
    fields = ('read_ver', 'read_status')

    def read_ver(self, buffer: StreamBuffer):
        if buffer.unread >= 1:
            self._ver = buffer.read(1)[0]
            return True
        return False

    def read_method(self, buffer: StreamBuffer):
        if buffer.unread >= 1:
            self._status = buffer.read(1)[0]
            return True
        return False

    def get_message(self):
        return SOCKSUsernameAuthResponse(self._ver, self._status)


@dataclass(frozen=True)
class SOCKSRequest:
    ver: int
    cmd: int
    rsv: int
    atyp: int
    dstaddr: str
    dstport: int

    def encode(self) -> bytes:
        if self.atyp == SOCKSAddressType.DOMAIN:
            return struct.pack(
                f'!BBBBB{len(self.dstaddr)}sH',
                self.ver,
                self.cmd,
                self.rsv,
                self.atyp,
                len(self.dstaddr),
                self.dstaddr.encode(),
                self.dstport
            )
        elif self.atyp == SOCKSAddressType.IPV4:
            return struct.pack(
                '!BBBB4sH',
                self.ver,
                self.cmd,
                self.rsv,
                self.atyp,
                ipaddress.IPv4Address(self.dstaddr).packed,
                self.dstport
            )
        elif self.atyp == SOCKSAddressType.IPV6:
            return struct.pack(
                f'!BBBB16sH',
                self.ver,
                self.cmd,
                self.rsv,
                self.atyp,
                ipaddress.IPv6Address(self.dstaddr).packed,
                self.dstport
            )
        else:
            raise ValueError(f'unknown address type {self.atyp}')


@dataclass(frozen=True)
class SOCKSResponse:
    ver: int
    rep: int
    rsv: int
    atyp: int
    bndaddr: str
    bndport: int

class SOCKSResponseReader(StreamMessageReader[SOCKSResponse]):
    fields = ('read_ver', 'read_rep', 'read_rsv', 'read_atyp', 'read_bndaddr', 'read_bndport')

    def read_ver(self, buffer: StreamBuffer):
        if buffer.unread >= 1:
            self._ver = buffer.read(1)[0]
            return True
        return False

    def read_rep(self, buffer: StreamBuffer):
        if buffer.unread >= 1:
            self._rep = buffer.read(1)[0]
            return True
        return False

    def read_rsv(self, buffer: StreamBuffer):
        if buffer.unread >= 1:
            self._rsv = buffer.read(1)[0]
            return True
        return False

    def read_atyp(self, buffer: StreamBuffer):
        if buffer.unread >= 1:
            self._atyp = buffer.read(1)[0]
            return True
        return False

    def read_bndaddr(self, buffer: StreamBuffer):
        if self._atyp == SOCKSAddressType.DOMAIN:
            if buffer.can_read_string():
                self._bndaddr = buffer.read_string()
                return True
        elif self._atyp == SOCKSAddressType.IPV4:
            if buffer.unread >= 4:
                self._bndaddr = '.'.join(str(bt) for bt in buffer.read(4))
                return True
        elif self._atyp == SOCKSAddressType.IPV6:
            if buffer.unread >= 16:
                self._bndaddr = buffer.read(16).hex(':', 2)
                return True
        else:
            self._bndaddr = ''
            return True
        return False

    def read_bndport(self, buffer: StreamBuffer):
        if buffer.unread >= 2:
            self._bndport = struct.unpack('!H', buffer.read(2))[0]
            return True
        return False

    def get_message(self):
        return SOCKSResponse(
            self._ver,
            self._rep,
            self._rsv,
            self._atyp,
            self._bndaddr,
            self._bndport
        )


async def open_socks_connection(socks_url: URL, host: str, port: int, ssl: t.Union[bool, SSLContext]=False):
    """Opens a TCP connection to target host proxied through given SOCKS5 server. Returns a raw
    Transport for the connection."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=2**64, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport, _ = await loop.create_connection(lambda: protocol, socks_url.host, socks_url.port, family=socket.AF_INET)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    buffer = StreamBuffer(bytearray(0))
    # authenticate
    if socks_url.user is not None:
        writer.write(SOCKSAuthNegotiationRequest(
            SOCKS_VER,
            [SOCKSAuthMethod.NO_AUTH, SOCKSAuthMethod.USERNAME]
        ).encode())
        await writer.drain()
        resp = await SOCKSAuthNegResponseReader.from_stream(buffer, reader)
        if resp.method == SOCKSAuthMethod.USERNAME:
            writer.write(SOCKSUsernameAuthRequest(
                SOCKS_VER,
                socks_url.user,
                socks_url.password
            ).encode())
            await writer.drain()
            resp = await SOCKSUsernameAuthRespReader.from_stream(buffer, reader)
            if resp.status != 0:
                writer.close()
                raise SOCKSAuthError(f'SOCKS server rejected username authentication: Status {resp.status}')
        elif resp.method != SOCKSAuthMethod.NO_AUTH:
            writer.close()
            raise SOCKSServerError(f'SOCKS server replied auth negotiation with unexpected method (expected NO_AUTH or USERNAME): {resp.method}')
    else:
        writer.write(SOCKSAuthNegotiationRequest(SOCKS_VER, [SOCKSAuthMethod.NO_AUTH]).encode())
        await writer.drain()
        resp = await SOCKSAuthNegResponseReader.from_stream(buffer, reader)
        if resp.method != SOCKSAuthMethod.NO_AUTH:
            writer.close()
            raise SOCKSServerError(f'SOCKS server replied auth negotiation with unexpected method (expected NO_AUTH): {resp.method}')
    # create socks tunnel
    try:
        ipaddress.IPv4Address(host)
        atyp = SOCKSAddressType.IPV4
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(host)
            atyp = SOCKSAddressType.IPV6
        except ipaddress.AddressValueError:
            atyp = SOCKSAddressType.DOMAIN
    writer.write(SOCKSRequest(
        ver=SOCKS_VER,
        cmd=SOCKSCommand.CONNECT,
        rsv=0,
        atyp=atyp,
        dstaddr=host,
        dstport=port
    ).encode())
    await writer.drain()
    resp = await SOCKSResponseReader.from_stream(buffer, reader)
    if resp.rep != SOCKSResponseCode.SUCCESS:
        writer.close()
        raise SOCKSServerError(f'CONNECT request failed: SOCKS {resp.rep} {SOCKSResponseCode(resp.rep).name}')
    # perform TLS handshake if needed
    if ssl:
        transport = await loop.start_tls(
            transport,
            protocol,
            sslcontext=create_default_context(Purpose.SERVER_AUTH) if isinstance(ssl, bool) else ssl,
            server_side=False,
            server_hostname=host
        )
    return transport
