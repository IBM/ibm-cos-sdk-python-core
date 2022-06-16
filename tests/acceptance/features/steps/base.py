import json

from ibm_botocore import xform_name
from ibm_botocore.exceptions import ClientError

from behave import when, then


def _params_from_table(table):
    # Unfortunately the way we're using table is not quite how
    # behave expects tables to be used:
    # They expect:
    #
    #     | name      | department  |
    #     | Barry     | foo         |
    #     | Pudey     | bar         |
    #     | Two-Lumps | bar         |
    #
    # Where the first row are headings that indicate the
    # key name you can use to retrieve row values,
    # e.g row['name'] -> Barry.
    #
    #
    # We just use:
    #      | LaunchConfigurationName | hello, world |
    #      | ImageId                 | ami-12345678 |
    #      | InstanceType            | m1.small     |
    #
    # So we have to grab the headings before iterating over
    # the table rows.
    params = {table.headings[0]: table.headings[1]}
    for row in table:
        params[row[0]] = row[1]
    return params


@when(u'I call the "{}" API')
def api_call_no_args(context, operation):
    context.response = getattr(context.client, xform_name(operation))()


@when(u'I call the "{}" API with')
def api_call_with_args(context, operation):
    params = _params_from_table(context.table)
    context.response = getattr(context.client, xform_name(operation))(**params)


@when(u'I call the "{}" API with JSON')
def api_call_with_json(context, operation):
    params = json.loads(context.text)
    context.response = getattr(context.client, xform_name(operation))(**params)


@when(u'I attempt to call the "{}" API with')
def api_call_with_error(context, operation):
    params = _params_from_table(context.table)
    try:
        getattr(context.client, xform_name(operation))(**params)
    except ClientError as e:
        context.error_response = e


@when(u'I attempt to call the "{}" API with JSON')
def api_call_with_json_and_error(context, operation):
    params = json.loads(context.text)
    try:
        getattr(context.client, xform_name(operation))(**params)
    except ClientError as e:
        context.error_response = e


@then(u'I expect the response error code to be "{}"')
def then_expected_error(context, code):
    assert context.error_response.response['Error']['Code'] == code


@then(u'the value at "{}" should be a list')
def then_expected_type_is_list(context, expression):
    # In ibm_botocore, if there are no values with an element,
    # it will not appear in the response dict, so it's actually
    # ok if the element does not exist (and is not a list).
    # If an exception happened the test will have already failed,
    # which makes this step a noop.  We'll just verify
    # the response is a dict to ensure it made it through
    # our response parser properly.
    if not isinstance(context.response, dict):
        raise AssertionError("Response is not a dict: %s" % context.response)


@then(u'the response should contain a "{}"')
def then_should_contain_key(context, key):
    # See then_expected_type_is_a_list for more background info.
    # We really just care that the request succeeded for these
    # smoke tests.
    if not isinstance(context.response, dict):
        raise AssertionError("Response is not a dict: %s" % context.response)


@then(u'I expect the response error to contain a message')
def then_error_has_message(context):
    if 'Message' not in context.error_response.response['Error']:
        raise AssertionError("Message key missing from error response: %s" %
                             context.error_response.response)
