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

import unittest2
from mock import patch, Mock
from sqlalchemy.orm import sessionmaker

from fuel_plugin.ostf_adapter.nose_plugin import nose_discovery
from fuel_plugin.ostf_adapter.storage import models
from fuel_plugin.ostf_adapter.storage import engine


#stopped__profile__ = {
#    "id": "stopped_test",
#    "driver": "nose",
#    "test_path": "fuel_plugin/tests/functional/dummy_tests/stopped_test.py",
#    "description": "Long running 25 secs fake tests",
#    "deployment tags": ["multinode", "ubuntu"]
#}
general__profile__ = {
    "id": "general_test",
    "driver": "nose",
    "test_path": "fuel_plugin/tests/functional/dummy_tests/general_test.py",
    "description": "General fake tests",
    "deployment_tags": ["ha"]
}


class TestNoseDiscovery(unittest2.TestCase):
    '''
    All test writing to database is wrapped in
    non-ORM transaction which is created in
    test_case setUp method and rollbacked in
    tearDown, so that keep prodaction base clean
    '''

    @classmethod
    def setUpClass(cls):
        cls._mocked_pecan_conf = Mock()
        cls._mocked_pecan_conf.dbpath = \
            'postgresql+psycopg2://ostf:ostf@localhost/ostf'

        cls.Session = sessionmaker()

        with patch(
            'fuel_plugin.ostf_adapter.storage.engine.conf',
            cls._mocked_pecan_conf
        ):
            cls.engine = engine.get_engine()

    def setUp(self):
        #database transaction wrapping
        connection = self.engine.connect()
        self.trans = connection.begin()

        self.Session.configure(bind=connection)
        self.session = self.Session(bind=connection)

        #test_case level patching
        self.mocked_get_session = lambda *args: self.session

        self.session_patcher = patch(
            'fuel_plugin.ostf_adapter.nose_plugin.nose_discovery.engine.get_session',
            self.mocked_get_session
        )
        self.session_patcher.start()

        self.fixtures = [
            {
                'cluster_id': 1,
                'deployment_tags': {
                    'ha',
                    'rhel'
                }
            },
            {
                'cluster_id': 2,
                'deployment_tags': {
                    'multinode',
                    'ubuntu'
                }
            },

        ]

    def tearDown(self):
        #end patching
        self.session_patcher.stop()

        #unwrapping
        self.trans.rollback()
        self.session.close()

    def test_discovery_testsets(self):
        expected = {
            'id': 'general_test',
            'cluster_id': 1,
            'deployment_tags': ['ha']
        }

        nose_discovery.discovery(
            path='fuel_plugin.tests.functional.dummy_tests.general_test',
            deployment_info=self.fixtures[0]
        )

        test_set = self.session.query(models.TestSet)\
            .filter_by(id=expected['id'])\
            .filter_by(cluster_id=expected['cluster_id'])\
            .one()

        self.assertEqual(
            test_set.deployment_tags,
            expected['deployment_tags']
        )

    def test_discovery_tests(self):
        expected = {
            'test_set_id': 'general_test',
            'cluster_id': 1,
            'results_count': 2,
            'results_data': [
                {
                    'id': 'fuel_plugin.tests.functional.dummy_tests.general_test.Dummy_test.test_fast_pass',
                    'deployment_tags': ['ha', 'rhel']
                },
                {
                    'id': 'fuel_plugin.tests.functional.dummy_tests.general_test.Dummy_test.test_fail_with_step',
                    'deployment_tags': []
                }
            ]
        }

        nose_discovery.discovery(
            path='fuel_plugin.tests.functional.dummy_tests.general_test',
            deployment_info=self.fixtures[0]
        )

        tests = self.session.query(models.Test)\
            .filter_by(test_set_id=expected['test_set_id'])\
            .filter_by(cluster_id=expected['cluster_id'])\
            .all()

        #self.assertTrue(len(tests) == expected['results_count'])

        #for test in tests:
        #    assertEqual(test.id == expected['results_count'][''])

    def test_get_proper_description(self, engine):
        '''
        Checks whether retrived docsctrings from tests
        are correct (in this occasion -- full).

        Magic that is used here is based on using
        data that is stored deeply in passed to test
        method mock object.
        '''
        #etalon data is list of docstrings of tests
        #of particular test set
        expected = {
            'title': 'fast pass test',
            'name':
                'fuel_plugin.tests.functional.dummy_tests.general_test.Dummy_test.test_fast_pass',
            'duration': '1sec',
            'description':
                '        This is a simple always pass test\n        '
        }

        #mocking behaviour of afterImport hook from DiscoveryPlugin
        #so that another hook -- addSuccess could process data properly
        engine.get_session().merge = lambda arg: arg

        #following code provide mocking logic for
        #addSuccess hook from DiscoveryPlugin that
        #(mentioned logic) in turn allows us to
        #capture data about test object that are processed
        engine.get_session()\
              .query()\
              .filter_by()\
              .update\
              .return_value = None

        nose_discovery.discovery(
            path='fuel_plugin/tests/functional/dummy_tests'
        )

        #now we can refer to captured test objects (not test_sets) in order to
        #make test comparison against etalon
        test_obj_to_compare = [
            call[0][0] for call in engine.get_session().add.call_args_list
            if (
                isinstance(call[0][0], models.Test)
                and
                call[0][0].name.rsplit('.')[-1] == 'test_fast_pass'
            )
        ][0]

        self.assertTrue(
            all(
                [
                    expected[key] == test_obj_to_compare.__dict__[key]
                    for key in expected.keys()
                ]
            )
        )
