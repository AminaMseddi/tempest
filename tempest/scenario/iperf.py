import threading
import re
from tempest import config
from tempest.openstack.common import log

LOG = log.getLogger(__name__)

CONF = config.CONF


class Iperf(threading.Thread):
    def __init__(self, **kwargs):
        threading.Thread.__init__(self)
        self.client_ssh = kwargs['client_ssh']
        self.is_client = False
        if kwargs['status'] == 'Client':
            self.ip_address = kwargs['ip_address']
            self.is_client = True
            self.bandwidth = None

    def run(self):
        if self.is_client:
            self._client_mode()
        else:
            self._server_mode()

    def _client_mode(self):
        is_second = False
        self.bandwidth = -1
        p = self.client_ssh.exec_command("iperf -c " + self.ip_address + " -i2")
        for line in p.splitlines():
            # Command outputs 0.0- twice, 2nd one contains the overall average
            if re.search("0.0-",line) and not is_second:
                is_second = True
            elif re.search("0.0-",line) and is_second:
                # Found the second one, get the Mbits/sec and work backwards for the value
                idx = line.index("bits/sec")
                self.bandwidth = line[idx-5:idx+9]

    def result(self):
        return self.bandwidth

    def _server_mode(self):
        self.client_ssh.exec_command("iperf -s -P 1",)

    def _install_iperf(self):
        try:
            self.client_ssh.put_file(CONF.compute.iperf_file, "~")
            self.client_ssh.exec_command("sudo -S chmod +x " + CONF.compute.iperf_file +"; sudo -S mv ~/" + CONF.compute.iperf_file + " /usr/bin/iperf")
        except Exception:
            LOG.exception('Iperf installation on server failed')
            raise
