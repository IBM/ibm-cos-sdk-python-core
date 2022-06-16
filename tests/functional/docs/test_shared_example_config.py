# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import pytest

import ibm_botocore.session
from ibm_botocore.model import OperationNotFoundError
from ibm_botocore.utils import parse_timestamp


def _shared_example_configs():
    session = ibm_botocore.session.Session()
    loader = session.get_component('data_loader')
    services = loader.list_available_services('examples-1')
    for service in services:
        service_model = session.get_service_model(service)
        example_config = loader.load_service_model(
            service, 'examples-1', service_model.api_version
        )
        examples = example_config.get("examples", {})
        for operation, operation_examples in examples.items():
            for example in operation_examples:
                yield operation, example, service_model


@pytest.mark.parametrize(
    "operation_name, example_config, service_model",
    _shared_example_configs()
)
def test_lint_shared_example_configs(operation_name, example_config, service_model):
    # The operation should actually exist
    assert_operation_exists(service_model, operation_name)
    operation_model = service_model.operation_model(operation_name)
    assert_valid_values(service_model.service_name, operation_model,
                        example_config)


def assert_valid_values(service_name, operation_model, example_config):
    example_input = example_config.get('input')
    input_shape = operation_model.input_shape
    example_id = example_config['id']

    if input_shape is None and example_input:
        raise AssertionError(
            "Input found in example for %s from %s with id %s, but no input "
            "shape is defined." % (
                operation_model.name, service_name, example_id
            ))

    example_output = example_config.get('output')
    output_shape = operation_model.output_shape

    if output_shape is None and example_output:
        raise AssertionError(
            "Output found in example for %s from %s with id %s, but no output "
            "shape is defined." % (
                operation_model.name, service_name, example_id
            ))

    try:
        if example_input is not None and input_shape is not None:
            _assert_valid_values(
                input_shape, example_input, [input_shape.name])

        if example_output is not None and output_shape is not None:
            _assert_valid_values(
                output_shape, example_output, [output_shape.name])
    except AssertionError as e:
        raise AssertionError(
            "Invalid value in example for %s from %s with id %s: %s" % (
                operation_model.name, service_name, example_id, e
            ))


def _assert_valid_values(shape, example_value, path):
    if shape.type_name == 'timestamp':
        _assert_valid_timestamp(example_value, path)
    elif shape.type_name == 'structure':
        _assert_valid_structure_values(shape, example_value, path)
    elif shape.type_name == 'list':
        _assert_valid_list_values(shape, example_value, path)
    elif shape.type_name == 'map':
        _assert_valid_map_values(shape, example_value, path)


def _assert_valid_structure_values(shape, example_dict, path):
    invalid_members = [k for k in example_dict.keys()
                       if k not in shape.members]
    if invalid_members:
        dotted_path = '.'.join(path)
        raise AssertionError(
            "Invalid members found for %s: %s" % (dotted_path, invalid_members)
        )

    for member_name, example_value in example_dict.items():
        member = shape.members[member_name]
        _assert_valid_values(member, example_value, path + [member_name])


def _assert_valid_list_values(shape, example_values, path):
    member = shape.member
    for i, value in enumerate(example_values):
        name = "%s[%s]" % (path[-1], i)
        _assert_valid_values(member, value, path[:-1] + [name])


def _assert_valid_map_values(shape, example_value, path):
    for key, value in example_value.items():
        name = '%s["%s"]' % (path[-1], key)
        _assert_valid_values(shape.value, value, path[:-1] + [name])


def _assert_valid_timestamp(timestamp, path):
    try:
        parse_timestamp(timestamp).timetuple()
    except Exception as e:
        dotted_path = '.'.join(path)
        raise AssertionError('Failed to parse timestamp %s for %s: %s' % (
            timestamp, dotted_path, e))


def assert_operation_exists(service_model, operation_name):
    try:
        service_model.operation_model(operation_name)
    except OperationNotFoundError:
        raise AssertionError(
            "Examples found in %s for operation %s that does not exist." % (
                service_model.service_name, operation_name))
