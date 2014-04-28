import threading
import re
from tempest import config
from tempest.openstack.common import log

LOG = log.getLogger(__name__)

CONF = config.CONF

class iperf(threading.Thread):
    def __init__(self, **kwargs):
        threading.Thread.__init__(self)
        if kwargs['status']=='Client':
            self.ip_address = kwargs['ip_address']
            self.client_ssh = kwargs['client_ssh']
            self.is_client = True
            self.bandwidth = None
        else:
            self.is_client = False
            self.server_ssh = kwargs['server_ssh']

    def run(self):
        if self.is_client:

            self._install_iperf(self.client_ssh)
            self._client_mode()
        else:

            self._install_iperf(self.server_ssh)
            self._server_mode(self.server_ssh)

    def result(self):
        return self.bandwidth

    def _client_mode(self):
        isSecond = False
        self.bandwidth = -1
        p = self.client_ssh.exec_command("iperf -c " + self.ip_address + " -i2")
        for line in p.splitlines():
            # Command outputs 0.0- twice, 2nd one contains the overall average
            if re.search("0.0-",line) and not isSecond:
                isSecond = True
            elif re.search("0.0-",line) and isSecond:
                # Found the second one, get the Mbits/sec and work backwards for the value
                idx = line.index("bits/sec")
                self.bandwidth = line[idx-5:idx+9]

    def _server_mode(self, server):
        server.exec_command("iperf -s -P 1",)

    def _install_iperf(self, linux_client):
        try:
            #linux_client = self.get_remote_client(ip_address, ssh_login, private_key)
            linux_client.put_file(CONF.compute.iperf_file, "~")
            linux_client.exec_command("sudo -S chmod +x " + CONF.compute.iperf_file +"; sudo -S mv ~/" + CONF.compute.iperf_file + " /usr/bin/iperf")
        except Exception:
            LOG.exception('Iperf installation on server failed')
            raise
        return linux_client

