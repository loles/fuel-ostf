#    Copyright 2013 Mirantis, Inc.
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

import requests
import json
import pprint


def make_requests(claster_id, test_set):
    body = [{'id': claster_id, 'status': 'stopped'}]
    headers = {'Content-Type': 'application/json'}

    update = requests.put(
        'http://localhost:8989/v1/testruns',
        data=json.dumps(body),
        headers=headers
    )

    data = update.json()
    pprint.pprint(data)


if __name__ == '__main__':
    make_requests(378, 'plugin_stopped')
