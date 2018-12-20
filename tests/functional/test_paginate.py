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
from __future__ import division
from math import ceil
from datetime import datetime

from nose.tools import assert_equal

from tests import random_chars
from tests import BaseSessionTest
from ibm_botocore.stub import Stubber, StubAssertionError
from ibm_botocore.paginate import TokenDecoder, TokenEncoder
from ibm_botocore.compat import six


def test_token_encoding():
    cases = [
        {'foo': 'bar'},
        {'foo': b'bar'},
        {'foo': {'bar': b'baz'}},
        {'foo': ['bar', b'baz']},
        {'foo': b'\xff'},
        {'foo': {'bar': b'baz', 'bin': [b'bam']}},
    ]

    for token_dict in cases:
        yield assert_token_encodes_and_decodes, token_dict


def assert_token_encodes_and_decodes(token_dict):
    encoded = TokenEncoder().encode(token_dict)
    assert isinstance(encoded, six.string_types)
    decoded = TokenDecoder().decode(encoded)
    assert_equal(decoded, token_dict)
