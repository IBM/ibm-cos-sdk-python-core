# Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
from nose.tools import assert_equals

import ibm_botocore.session


REGION = 'us-east-1'

SERVICE_TO_CLASS_NAME = {
    's3': 'S3',
}


def test_client_has_correct_class_name():
    session = ibm_botocore.session.get_session()
    for service_name in SERVICE_TO_CLASS_NAME:
        client = session.create_client(service_name, REGION)
        yield (_assert_class_name_matches_ref_class_name, client,
               SERVICE_TO_CLASS_NAME[service_name])


def _assert_class_name_matches_ref_class_name(client, ref_class_name):
    assert_equals(client.__class__.__name__, ref_class_name)
