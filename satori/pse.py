import eventlet
eventlet.monkey_patch()

import tempfile
import os
import socket
import subprocess
import shlex
import time
import signal
import base64
import re

from satori.ssh import SSH
import tunnel

class PSE(object):

    _prompt_pattern = re.compile(r'^[a-zA-Z]:\\.*>$', re.MULTILINE)

    def __init__(self, host=None, password=None, username="Administrator", port=445, timeout=10, gateway=None):
        self.password = password
        self.host = host
        self.port = port
        self.username = username
        self.timeout = timeout

        #creating temp file to talk to _process with
        self._file_write = tempfile.NamedTemporaryFile()
        self._file_read = open(self._file_write.name, 'r')
        
        self._command = "nice python psexec.py -port %s %s:%s@%s 'c:\\Windows\\sysnative\\cmd'"
        self._output = ''
        self.gateway = gateway

        if gateway:
            if not isinstance(self.gateway, SSH):
                raise TypeError("'gateway' must be a satori.ssh.SSH instance. "
                                "( instances of this tupe are returned by"
                                "satori.ssh.connect() )")


    def __del__(self):
        try:
            self.close()
        except ValueError:
            pass

    def create_tunnel(self):
        self.ssh_tunnel = tunnel.connect(self.host, self.port, self.gateway)
        self._orig_host = self.host
        self._orig_port = self.port
        self.host, self.port = self.ssh_tunnel.address
        self.ssh_tunnel.serve_forever(async=True)

    def shutdown_tunnel(self):
        self.ssh_tunnel.shutdown()
        self.host = self._orig_host
        self.port = self._orig_port

    def test_connection(self):
        self.connect()
        self.close()
        self._get_output()
        if self._output.find('ErrorCode: 0, ReturnCode: 0') > -1:
            return True
        else:
            return False

    def connect(self):
        if self.gateway:
            self.create_tunnel()
        self._substituted_command = self._command % (self.port, self.username, self.password, self.host)
        self._process = subprocess.Popen(shlex.split(self._substituted_command), stdout=self._file_write, 
                                         stderr=subprocess.STDOUT, 
                                         stdin=subprocess.PIPE,
                                         close_fds=True,
                                         bufsize=0)
        while not self._prompt_pattern.findall(self._output):
            self._get_output()
        print self._prompt_pattern.findall(self._output)
        
    def close(self):
        stdout,stderr = self._process.communicate('exit')
        if self.gateway:
            self.shutdown_tunnel()

    def remote_execute(self, command, powershell=True):
        if powershell:
            command = 'powershell -EncodedCommand %s' % self._posh_encode(command)
        self._process.stdin.write('%s\n' % command)
        return "\n".join(self._get_output().splitlines()[:-1]).strip()

    def _get_output(self):
        tmp_out = ''
        while tmp_out == '':
            eventlet.sleep(0.1)
            self._file_read.seek(0,1)
            tmp_out += self._file_read.read()
        stdout = tmp_out
        while not tmp_out == '' and not self._prompt_pattern.findall(stdout):
            eventlet.sleep(0.1)
            self._file_read.seek(0,1)
            tmp_out = self._file_read.read()
            stdout += tmp_out
        self._output += stdout
        stdout = stdout.replace('\r', '').replace('\x08','')
        return stdout
        
    def _posh_encode(self, command):
        return base64.b64encode(command.encode('utf-16')[2:])

    def install_ohai_solo(self):
        powershell_command = '[scriptblock]::Create((New-Object -TypeName System.Net.WebClient)'\
                             '.DownloadString("http://12d9673e1fdcef86bf0a-162ee3689e7f81d29099'\
                             '4e20942dc617.r59.cf3.rackcdn.com/deploy.ps1")).Invoke()'
        out = self.execute('powershell -EncodedCommand %s' % self._posh_encode(powershell_command))
        while not self._prompt_pattern.findall(out):
            out += "\n"+self._get_output()
        out = "\n".join(out.splitlines()[:-1]).strip()
        return out

    def remove_ohai_solo(self):
        powershell_command = 'Remove-Item -Path (Join-Path -Path $($env:PSModulePath.Split(";") '\
                             '| Where-Object { $_.StartsWith($env:SystemRoot)}) -ChildPath "PoSh-Ohai") '\
                             '-Recurse -Force -ErrorAction SilentlyContinue'
        out = self.execute('powershell -EncodedCommand %s' % self._posh_encode(powershell_command))
        return out
