import eventlet
eventlet.monkey_patch()

import ast
import tempfile
import os
import socket
import subprocess
import shlex
#import time
#import signal
import base64
import re

from satori.ssh import SSH
from satori import tunnel


def connect(*args, **kwargs):
    """Connect to a remote device using psexec.py"""
    try:
        return PSE.get_client(*args, **kwargs)
    except:
        print "failed"

class SubprocessError(Exception):
    """custom Exception that will be raised when the subprocess running psexec.py has exited"""
    pass


class PSE(object):

    """Connects to devices over SMB/psexec to execute commands."""

    _prompt_pattern = re.compile(r'^[a-zA-Z]:\\.*>$', re.MULTILINE)

    def __init__(self, host, password=None, username="Administrator", port=445, timeout=10, gateway=None):
        """Create an instance of the PSE class

        :param str host:        The ip address or host name of the server
                                to connect to
        :param str password:    A password to use for authentication
        :param str username:    The username to authenticate as (defaults to Administrator)
        :param int port:        tcp/ip port to use (defaults to 445)
        :param float timeout:   an optional timeout (in seconds) for the
                                TCP connection
        :param gateway:         instance of satori.ssh.SSH to be used to set up an 
                                SSH tunnel (equivalent to ssh -L)
        """
        self.password = password
        self.host = host
        self.port = port
        self.username = username
        self.timeout = timeout
        self._connected = False
        self._platform_info = None

        #creating temp file to talk to _process with
        self._file_write = tempfile.NamedTemporaryFile()
        self._file_read = open(self._file_write.name, 'r')
        
        self._command = "nice python %s/psexec.py -port %s %s:%s@%s 'c:\\Windows\\sysnative\\cmd'"
        self._output = ''
        self.gateway = gateway

        if gateway:
            if not isinstance(self.gateway, SSH):
                raise TypeError("'gateway' must be a satori.ssh.SSH instance. "
                                "( instances of this type are returned by"
                                "satori.ssh.connect() )")


    def __del__(self):
        """Destructor of the PSE class.
        This method will be called when an instance of this class is about to being
        destroyed. It will try to close the connection (which will clean up on the
        remote server) and catch the exception that is raised when the connection
        has already been closed.
        """
        try:
            self.close()
        except ValueError:
            pass

    @classmethod
    def get_client(cls, *args, **kwargs):
        """Return a pse client object from this module"""
        return cls(*args, **kwargs)

    @property
    def platform_info(self):
        """Returns Windows edition, version ann architecture
        requires Powershell version 3"""
        if not self._platform_info:
            stdout = self.remote_execute('Get-WmiObject Win32_OperatingSystem | ' \
                                         'select @{n="dist";e={$_.Caption.Trim()}},' \
                                         '@{n="version";e={$_.Version}},@{n="arch";e={$_.OSArchitecture}} | ' \
                                         ' ConvertTo-Json -Compress', retry = 3)
            self._platform_info = ast.literal_eval(stdout)

        return self._platform_info
    
    def create_tunnel(self):
        """Creates an ssh tunnel via gateway to tunnel a local ephemeral port to the host's port.
        This will preserve the original host and port
        """
        self.ssh_tunnel = tunnel.connect(self.host, self.port, self.gateway)
        self._orig_host = self.host
        self._orig_port = self.port
        self.host, self.port = self.ssh_tunnel.address
        self.ssh_tunnel.serve_forever(async=True)

    def shutdown_tunnel(self):
        """Terminates the ssh tunnel. Restores original host and port"""
        self.ssh_tunnel.shutdown()
        self.host = self._orig_host
        self.port = self._orig_port

    def test_connection(self):
        """Connect to a Windows server and disconnect again.
        Make sure the returncode is 0, otherwise return False
        """
        self.connect()
        self.close()
        self._get_output()
        if self._output.find('ErrorCode: 0, ReturnCode: 0') > -1:
            return True
        else:
            return False

    def connect(self):
        """Attempt a connection using psexec.py.
        This will create a subprocess.Popen() instance and communicate with it via _file_read/_file_write
        and _process.stdin
        """
        if self._connected and self._process:
            if self._process.poll() is None:
                return
            else:
                self._process.wait()
                if self.gateway:    
                    self.shutdown_tunnel()
        if self.gateway:
            self.create_tunnel()
        self._substituted_command = self._command % (os.path.dirname(__file__), 
                                                     self.port, 
                                                     self.username, 
                                                     self.password, 
                                                     self.host)
        self._process = subprocess.Popen(shlex.split(self._substituted_command), stdout=self._file_write, 
                                         stderr=subprocess.STDOUT, 
                                         stdin=subprocess.PIPE,
                                         close_fds=True,
                                         bufsize=0)
        output = ''
        while not self._prompt_pattern.findall(output):
            output += self._get_output()
        self._connected = True
        
    def close(self):
        """Close the psexec connection by sending 'exit' to the subprocess.
        This will cleanly exit psexec (i.e. stop and uninstall the service and delete the files)
        """
        stdout,stderr = self._process.communicate('exit')
        if self.gateway:
            self.shutdown_tunnel()

    def remote_execute(self, command, powershell=True, retry=0):
        """Execute a command on a remote host

        :param command:     Command to be executed
        :param powershell:  If True, command will be interpreted as Powershell command
                            and therefore converted to base64 and prepended with 'powershell -EncodedCommand
        :param int retry:   Number of retries when SubprocessError is thrown by _get_output before giving up
        """
        self.connect()
        if powershell:
            command = 'powershell -EncodedCommand %s' % self._posh_encode(command)
        self._process.stdin.write('%s\n' % command)
        try:
            output =  self._get_output()
            output = "\n".join(output.splitlines()[:-1]).strip()  
            return output
        except SubprocessError as exc:
            if not retry:
                raise
            else:
                return self.remote_execute(command, powershell=powershell, retry=retry - 1)

    def _get_output(self, prompt_expected=True, wait=200):
        """Retrieve output from _process. This method will wait until output is started to be received
        and then wait until no further output is received within a defined period
        :param prompt_expected:     only return when regular expression defined in _prompt_pattern
                                    is matched
        :param wait:                Time in milliseconds to wait in eacht of the two loops that wait for
                                    (more) output.
        """
        tmp_out = ''
        while tmp_out == '':
            self._file_read.seek(0,1)
            tmp_out += self._file_read.read()
            # leave loop if underlying process has a return code
            # obviously meaning that it has terminated
            if not self._process.poll() is None:
                raise SubprocessError("subprocess with pid: %s has terminated unexpectedly with return code: %s"
                                % (self._process.pid, self._process.poll()))
            eventlet.sleep(wait/1000)
        stdout = tmp_out
        #print stdout
        while not tmp_out == '' or \
             (not self._prompt_pattern.findall(stdout) and\
              prompt_expected):
            self._file_read.seek(0,1)
            tmp_out = self._file_read.read()
            stdout += tmp_out
            # leave loop if underlying process has a return code
            # obviously meaning that it has terminated
            if not self._process.poll() is None:
                raise SubprocessError("subprocess with pid: %s has terminated unexpectedly with return code: %s"
                                % (self._process.pid, self._process.poll()))
            eventlet.sleep(wait/1000)
            #print tmp_out
        self._output += stdout
        stdout = stdout.replace('\r', '').replace('\x08','')
        return stdout
        
    def _posh_encode(self, command):
        """Encodes a powershell command to base64 using utf-16 encoding and disregarding the first two bytes
        :param  command:    command to encode
        """
        return base64.b64encode(command.encode('utf-16')[2:])