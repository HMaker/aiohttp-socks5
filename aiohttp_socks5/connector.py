from aiohttp.connector import TCPConnector
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_exceptions import ClientConnectionError
from aiohttp.client_reqrep import ClientRequest
from aiohttp_socks5.socks import SOCKSServerError, open_socks_connection


class SOCKSConnector(TCPConnector):
    """SOCKS proxies for aiohttp. This connector is compatible with both HTTP and SOCKS5 proxies."""

    async def _create_proxy_connection(self, req: "ClientRequest", traces, timeout):
        if req.proxy is None:
            raise RuntimeError('empty proxy URL')
        if req.proxy.scheme == 'socks5':
            try:
                if req.port is not None:
                    transport = await open_socks_connection(req.proxy, req.host, req.port)
                elif req.url.scheme == 'http':
                    transport = await open_socks_connection(req.proxy, req.host, 80)
                elif req.url.scheme == 'https':
                    transport = await open_socks_connection(req.proxy, req.host, 443)
                else:
                    raise RuntimeError(f'unexpected URL scheme: {req.url.scheme}')
            except (SOCKSServerError, ConnectionError) as e:
                raise ClientConnectionError('SOCKS connection failed') from e
            if req.is_ssl():
                return await self._start_tls_connection(transport, req=req, timeout=timeout)
            proto = ResponseHandler(self._loop)
            proto.connection_made(transport)
            return transport, proto
        else:
            return await super()._create_proxy_connection(req, traces, timeout)
