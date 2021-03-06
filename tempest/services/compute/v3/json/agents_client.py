# Copyright 2014 NEC Corporation.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json
import urllib

from tempest.api_schema.compute.v3 import agents as schema
from tempest.common import rest_client
from tempest import config

CONF = config.CONF


class AgentsV3ClientJSON(rest_client.RestClient):

    def __init__(self, auth_provider):
        super(AgentsV3ClientJSON, self).__init__(auth_provider)
        self.service = CONF.compute.catalog_v3_type

    def list_agents(self, params=None):
        """List all agent builds."""
        url = 'os-agents'
        if params:
            url += '?%s' % urllib.urlencode(params)
        resp, body = self.get(url)
        return resp, self._parse_resp(body)

    def create_agent(self, **kwargs):
        """Create an agent build."""
        post_body = json.dumps({'agent': kwargs})
        resp, body = self.post('os-agents', post_body)
        return resp, self._parse_resp(body)

    def delete_agent(self, agent_id):
        """Delete an existing agent build."""
        resp, body = self.delete("os-agents/%s" % str(agent_id))
        self.validate_response(schema.delete_agent, resp, body)
        return resp, body

    def update_agent(self, agent_id, **kwargs):
        """Update an agent build."""
        put_body = json.dumps({'agent': kwargs})
        resp, body = self.put('os-agents/%s' % str(agent_id), put_body)
        return resp, self._parse_resp(body)
