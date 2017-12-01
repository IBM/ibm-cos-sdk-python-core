# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
from tests import unittest, create_session

import mock
from nose.tools import assert_equals, assert_raises

from ibm_botocore import regions
from ibm_botocore.client import ClientEndpointBridge
from ibm_botocore.exceptions import NoRegionError


# NOTE: sqs endpoint updated to be the CN in the SSL cert because
# a bug in python2.6 prevents subjectAltNames from being parsed
# and subsequently being used in cert validation.
# Same thing is needed for rds.
KNOWN_REGIONS = {
    'ap-northeast-1': {
        's3': 's3-ap-northeast-1.amazonaws.com',
    },
    'ap-southeast-1': {
        's3': 's3-ap-southeast-1.amazonaws.com',
    },
    'ap-southeast-2': {
        's3': 's3-ap-southeast-2.amazonaws.com',
    },
    'cn-north-1': {
        's3': 's3.cn-north-1.amazonaws.com.cn',
    },
    'eu-central-1': {
        's3': 's3.eu-central-1.amazonaws.com',
    },
    'eu-west-1': {
        's3': 's3-eu-west-1.amazonaws.com',
    },
    'fips-us-gov-west-1': {
        's3': 's3-fips-us-gov-west-1.amazonaws.com'
    },
    's3-external-1': {
        's3': 's3-external-1.amazonaws.com'
    },
    'sa-east-1': {
        's3': 's3-sa-east-1.amazonaws.com',
    },
    'us-east-1': {
        's3': 's3.amazonaws.com',
    },
    'us-gov-west-1': {
        's3': 's3-us-gov-west-1.amazonaws.com',
    },
    'us-west-1': {
        's3': 's3-us-west-1.amazonaws.com',
    },
    'us-west-2': {
        's3': 's3-us-west-2.amazonaws.com',
    }
}


# Lists the services in the aws partition that do not require a region
# when resolving an endpoint because these services have partitionWide
# endpoints.
KNOWN_AWS_PARTITION_WIDE = {
    's3': 'https://s3.amazonaws.com',
}


def _get_patched_session():
    with mock.patch('os.environ') as environ:
        environ['AWS_ACCESS_KEY_ID'] = 'access_key'
        environ['AWS_SECRET_ACCESS_KEY'] = 'secret_key'
        environ['AWS_CONFIG_FILE'] = 'no-exist-foo'
        session = create_session()
    return session


def test_known_endpoints():
    # Verify the actual values from the partition files.  While
    # TestEndpointHeuristics verified the generic functionality given any
    # endpoints file, this test actually verifies the partition data against a
    # fixed list of known endpoints.  This list doesn't need to be kept 100% up
    # to date, but serves as a basis for regressions as the endpoint data
    # logic evolves.
    resolver = _get_patched_session().get_component('endpoint_resolver')
    for region_name, service_dict in KNOWN_REGIONS.items():
        for service_name, endpoint in service_dict.items():
            yield (_test_single_service_region, service_name,
                   region_name, endpoint, resolver)


def _test_single_service_region(service_name, region_name,
                                expected_endpoint, resolver):
    bridge = ClientEndpointBridge(resolver, None, None)
    result = bridge.resolve(service_name, region_name)
    expected = 'https://%s' % expected_endpoint
    assert_equals(result['endpoint_url'], expected)


# Ensure that all S3 regions use s3v4 instead of v4
def test_all_s3_endpoints_have_s3v4():
    session = _get_patched_session()
    partitions = session.get_available_partitions()
    resolver = session.get_component('endpoint_resolver')
    for partition_name in partitions:
        for endpoint in session.get_available_regions('s3', partition_name):
            resolved = resolver.construct_endpoint('s3', endpoint)
            assert 's3v4' in resolved['signatureVersions']
            assert 'v4' not in resolved['signatureVersions']


def test_known_endpoints():
    resolver = _get_patched_session().get_component('endpoint_resolver')
    for service_name, endpoint in KNOWN_AWS_PARTITION_WIDE.items():
        yield (_test_single_service_partition_endpoint, service_name,
               endpoint, resolver)


def _test_single_service_partition_endpoint(service_name, expected_endpoint,
                                            resolver):
    bridge = ClientEndpointBridge(resolver)
    result = bridge.resolve(service_name)
    assert_equals(result['endpoint_url'], expected_endpoint)


def test_non_partition_endpoint_requires_region():
    resolver = _get_patched_session().get_component('endpoint_resolver')
    assert_raises(NoRegionError, resolver.construct_endpoint, 'ec2')
