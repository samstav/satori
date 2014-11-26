#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#
# pylint: disable=W0622
"""PoSh-Ohai Data Plane Discovery Module."""

import json
import logging
import time

import ipaddress as ipaddress_module
import six

from satori import bash
from satori import errors
from satori import smb
from satori import utils

LOG = logging.getLogger(__name__)


def get_systeminfo(ipaddress, config, interactive=False):
    """Run data plane discovery using this module against a host.

    :param ipaddress: address to the host to discover.
    :param config: arguments and configuration suppplied to satori.
    :keyword interactive: whether to prompt the user for information.
    """
    if (ipaddress in utils.get_local_ips() or
            ipaddress_module.ip_address(six.text_type(ipaddress)).is_loopback):

        client = bash.LocalShell()
        client.host = "localhost"
        client.port = 0
        perform_install(client)
        return system_info(client)

    else:
        with bash.RemoteShell(
                ipaddress, username=config['host_username'],
                private_key=config['host_key'],
                interactive=interactive) as client:
            perform_install(client)
            return system_info(client)


def system_info(client, with_install=False):
    """Run Posh-Ohai on a remote system and gather the output.

    :param client: :class:`smb.SMB` instance
    :returns: dict -- system information from PoSh-Ohai
    :raises: SystemInfoCommandMissing, SystemInfoCommandOld, SystemInfoNotJson
             SystemInfoMissingJson

        SystemInfoCommandMissing if `posh-ohai` is not installed.
        SystemInfoCommandOld if `posh-ohai` is not the latest.
        SystemInfoNotJson if `posh-ohai` does not return valid JSON.
        SystemInfoMissingJson if `posh-ohai` does not return any JSON.
    """
    if with_install:
        perform_install(client)

    if client.is_windows():
        powershell_command = 'Get-ComputerConfiguration'
        # 'wait' is in ms, wait 2 seconds
        # (output is large and takes some time to
        #  begin streaming back through psexec)
        output = client.execute(powershell_command, wait=3000)
        unicode_output = "%s" % output
        try:
            results = json.loads(unicode_output)
        except ValueError:
            try:
                clean_output = get_json(unicode_output)
                results = json.loads(clean_output)
            except ValueError as err:
                raise errors.SystemInfoNotJson(err)
            except errors.OutputMissingJson:
                raise errors.SystemInfoMissingJson(
                    "System info command returned and does not appear to "
                    "contain any json-encoded data.")
        return results
    else:
        raise errors.UnsupportedPlatform(
            "PoSh-Ohai is a Windows-only sytem info provider. "
            "Target platform was %s", client.platform_info['dist'])


def perform_install(client):
    """Install PoSh-Ohai on remote system."""
    LOG.info("Installing (or updating) PoSh-Ohai on device %s at %s:%d",
             client.host, client.host, client.port)

    # Check is it is a windows box, but fail safely to Linux
    is_windows = False
    try:
        is_windows = client.is_windows()
    except Exception:
        pass
    if is_windows:
        url = 'http://readonly.configdiscovery.rackspace.com/deploy.ps1'
        path = r'c:\windows\temp\deploy.ps1'
        # first download the file
        powershell_command = (r'(New-Object -TypeName '
                              'System.Net.WebClient).DownloadFile('
                              '"%s","%s")' % (url, path))
        # check output to ensure that installation was successful
        # if not, raise SystemInfoCommandInstallFailed
        output = client.execute(powershell_command, wait=10000)
        time.sleep(3)
        # replace with encoded command
        run_script = (r'powershell -ExecutionPolicy Bypass %s' % path)
        output = client.execute(run_script, powershell=False, wait=5000)
        unicode_output = "%s" % output
        breakup = [k.split() for k in unicode_output.splitlines()]
        try:
            breakup = breakup[breakup.index(['Name', 'Value']):]
        except ValueError as err:
            raise errors.PowerShellVersionDetectionException(
                "Failed to detect PowerShell version from output: %s. | %s"
                % (unicode_output, "ValueError: {err}".format(err=str(err))))
        supported, message = None, None
        for line in breakup:
            if line[0] == 'Supported' and len(line) == 2:
                supported = line[1].lower() == 'true'
            if line[0] == 'PsMessage':
                message = " ".join(line[1:])
        if supported is None or message is None:
            raise errors.PowerShellVersionDetectionException(
                "Failed to detect PowerShell version from output: %s."
                % unicode_output)
        if not supported:
            raise errors.PowerShellVersionNotSupported(message)
        else:
            LOG.info("PoSh-Ohai Installed: %s", message)
        return unicode_output
    else:
        raise errors.UnsupportedPlatform(
            "PoSh-Ohai is a Windows-only sytem info provider. "
            "Target platform was %s", client.platform_info['dist'])


def remove_remote(client):
    """Remove PoSh-Ohai from specifc remote system.

    Currently supports:
        - ubuntu [10.x, 12.x]
        - debian [6.x, 7.x]
        - redhat [5.x, 6.x]
        - centos [5.x, 6.x]
    """
    if client.is_windows():
        powershell_command = ('Remove-Item -Path (Join-Path -Path '
                              '$($env:PSModulePath.Split(";") '
                              '| Where-Object { $_.StartsWith('
                              '$env:SystemRoot)}) -ChildPath '
                              '"PoSh-Ohai") -Recurse -Force -ErrorAction '
                              'SilentlyContinue')
        output = client.execute(powershell_command)
        return output
    else:
        raise errors.UnsupportedPlatform(
            "PoSh-Ohai is a Windows-only sytem info provider. "
            "Target platform was %s", client.platform_info['dist'])


def get_json(data):
    """Find the JSON string in data and return a string.

    :param data: :string:
    :returns: string -- JSON string stripped of non-JSON data
    :raises: SystemInfoMissingJson

        SystemInfoMissingJson if no JSON is returned.
    """
    try:
        first = data.index('{')
        last = data.rindex('}')
        return data[first:last + 1]
    except ValueError as exc:
        context = {"ValueError": "%s" % exc}
        raise errors.OutputMissingJson(context)
