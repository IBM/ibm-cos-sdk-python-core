"""Smoke tests to verify basic communication to all AWS services.

If you want to control what services/regions are used you can
also provide two separate env vars:

    * AWS_SMOKE_TEST_REGION - The region used to create clients.
    * AWS_SMOKE_TEST_SERVICES - A CSV list of service names to test.

Otherwise, the ``REGION`` variable specifies the default region
to use and all the services in SMOKE_TESTS/ERROR_TESTS will be tested.

"""
import os
import mock
from pprint import pformat
import warnings
from nose.tools import assert_equals, assert_true

from ibm_botocore import xform_name
import ibm_botocore.session
from ibm_botocore.client import ClientError
from ibm_botocore.vendored.requests import adapters
from ibm_botocore.vendored.requests.exceptions import ConnectionError


# Mapping of service -> api calls to try.
# Each api call is a dict of OperationName->params.
# Empty params means that the operation will be called with no params.  This is
# used as a quick verification that we can successfully make calls to services.
SMOKE_TESTS = {
 's3': {'ListBuckets': {}},
}

# Same thing as the SMOKE_TESTS hash above, except these verify
# that we get an error response back from the server because
# we've sent invalid params.
ERROR_TESTS = {
    's3': {'ListObjects': {'Bucket': 'thisbucketdoesnotexistasdf'}},
}

REGION = 'us-east-1'
REGION_OVERRIDES = {
    'devicefarm': 'us-west-2',
    'efs': 'us-west-2',
    'inspector': 'us-west-2',
}


def _get_client(session, service):
    if os.environ.get('AWS_SMOKE_TEST_REGION', ''):
        region_name = os.environ['AWS_SMOKE_TEST_REGION']
    else:
        region_name = REGION_OVERRIDES.get(service, REGION)
    return session.create_client(service, region_name=region_name)


def _list_services(dict_entries):
    # List all services in the provided dict_entry.
    # If the AWS_SMOKE_TEST_SERVICES is provided,
    # it's a comma separated list of services you can provide
    # if you only want to run the smoke tests for certain services.
    if 'AWS_SMOKE_TEST_SERVICES' not in os.environ:
        return dict_entries.keys()
    else:
        wanted_services = os.environ.get(
            'AWS_SMOKE_TEST_SERVICES', '').split(',')
        return [key for key in dict_entries if key in wanted_services]


def test_can_make_request_with_client():
    # Same as test_can_make_request, but with Client objects
    # instead of service/operations.
    session = ibm_botocore.session.get_session()
    for service_name in _list_services(SMOKE_TESTS):
        client = _get_client(session, service_name)
        for operation_name in SMOKE_TESTS[service_name]:
            kwargs = SMOKE_TESTS[service_name][operation_name]
            method_name = xform_name(operation_name)
            yield _make_client_call, client, method_name, kwargs


def _make_client_call(client, operation_name, kwargs):
    method = getattr(client, operation_name)
    with warnings.catch_warnings(record=True) as caught_warnings:
        response = method(**kwargs)
        assert_equals(len(caught_warnings), 0,
                      "Warnings were emitted during smoke test: %s"
                      % caught_warnings)
        assert_true('Errors' not in response)


def test_can_make_request_and_understand_errors_with_client():
    session = ibm_botocore.session.get_session()
    for service_name in _list_services(ERROR_TESTS):
        client = _get_client(session, service_name)
        for operation_name in ERROR_TESTS[service_name]:
            kwargs = ERROR_TESTS[service_name][operation_name]
            method_name = xform_name(operation_name)
            yield _make_error_client_call, client, method_name, kwargs


def _make_error_client_call(client, operation_name, kwargs):
    method = getattr(client, operation_name)
    try:
        response = method(**kwargs)
    except ClientError as e:
        pass
    else:
        raise AssertionError("Expected client error was not raised "
                             "for %s.%s" % (client, operation_name))


def test_client_can_retry_request_properly():
    session = ibm_botocore.session.get_session()
    for service_name in _list_services(SMOKE_TESTS):
        client = _get_client(session, service_name)
        for operation_name in SMOKE_TESTS[service_name]:
            kwargs = SMOKE_TESTS[service_name][operation_name]
            yield (_make_client_call_with_errors, client,
                   operation_name, kwargs)


def _make_client_call_with_errors(client, operation_name, kwargs):
    operation = getattr(client, xform_name(operation_name))
    original_send = adapters.HTTPAdapter.send
    def mock_http_adapter_send(self, *args, **kwargs):
        if not getattr(self, '_integ_test_error_raised', False):
            self._integ_test_error_raised = True
            raise ConnectionError("Simulated ConnectionError raised.")
        else:
            return original_send(self, *args, **kwargs)
    with mock.patch('ibm_botocore.vendored.requests.adapters.HTTPAdapter.send',
                    mock_http_adapter_send):
        try:
            response = operation(**kwargs)
        except ClientError as e:
            assert False, ('Request was not retried properly, '
                           'received error:\n%s' % pformat(e))
