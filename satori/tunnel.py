import eventlet
eventlet.monkey_patch()

import logging
import os
import socket
import select
import sys
import threading

from eventlet import greenthread
from eventlet.green import SocketServer
import paramiko
from satori import ssh

LOG = logging.getLogger(__name__)
LOG.addHandler(logging.StreamHandler(sys.stdout))
[h.setLevel(logging.DEBUG) for h in LOG.handlers]
LOG.setLevel(logging.DEBUG)

class TunnelServer(SocketServer.ThreadingTCPServer):

    daemon_threads = True
    allow_reuse_address = True


class TunnelHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        try:
            chan = self.ssh_transport.open_channel('direct-tcpip',
                                                   self.target_address,
                                                   self.request.getpeername())
        except Exception as exc:
            LOG.error('Incoming request to %s:%s failed',
                      self.target_address[0],
                      self.target_address[1],
                      exc_info=exc)
            return
        if chan is None:
            LOG.error('Incoming request to %s:%s was rejected '
                      'by the SSH server.',
                      self.target_address[0],
                      self.target_address[1])
            return

        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)

        try:
            peername = "Unknown"
            peername = self.request.getpeername()
        except socket.error as exc:
            LOG.error("ERROR: Couldn't fetch peername, tunnel "
                      "has been closed. %s", str(exc))
        chan.close()
        self.request.close()
        print 'Tunnel closed from', peername


class Tunnel(object):

    def __init__(self, target_host, target_port,
                 sshclient, tunnel_host='localhost',
                 tunnel_port=0):

        if not isinstance(sshclient, paramiko.SSHClient):
            raise TypeError("'sshclient' must be an instance of "
                            "paramiko.SSHClient.")

        self.target_host = target_host
        self.target_port = target_port
        self.target_address = (target_host, target_port)
        self.address = (tunnel_host, tunnel_port)

        self._tunnel = None
        self._tunnel_greenthread = None
        self.sshclient = sshclient
        self._ssh_transport = self.get_sshclient_transport(
            self.sshclient)

        TunnelHandler.target_address = self.target_address
        TunnelHandler.ssh_transport = self._ssh_transport

        self._tunnel = TunnelServer(self.address, TunnelHandler)
        # reset attribute to the port it has actually ben set to
        self.address = self._tunnel.server_address
        tunnel_host, self.tunnel_port = self.address

    def get_sshclient_transport(self, sshclient):
        sshclient.connect()
        return sshclient.get_transport()

    def serve_forever(self, async=True):
        if not async:
            self._tunnel.serve_forever()
        #self._tunnel_greenthread = greenthread.spawn_n(
        #    self._tunnel.serve_forever)
        #eventlet.sleep(1)
        self._tunnel_thread = threading.Thread(
            target=self._tunnel.serve_forever)
        self._tunnel_thread.start()

    def shutdown(self):

        self._tunnel.shutdown()
        self._tunnel.socket.close()


HELP = """\
Set up a forward tunnel across an SSH server, using paramiko. A local port
(given with -p) is forwarded across an SSH session to an address:port from
the SSH server. This is similar to the openssh -L option.
"""


def connect(targethost, targetport, sshclient):

    return Tunnel(targethost, targetport, sshclient)


def get_sshclient(*args, **kwargs):

    kwargs.setdefault('options', {})
    kwargs['options'].update({'StrictHostKeyChecking': False})
    kwargs['timeout'] = None
    return ssh.connect(*args, **kwargs)

