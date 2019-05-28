# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Unit tests for the binary event stream decoder. """

from mock import Mock
from nose.tools import assert_equal, raises

from ibm_botocore.parsers import EventStreamXMLParser
from ibm_botocore.eventstream import (
    EventStreamMessage, MessagePrelude, EventStreamBuffer,
    ChecksumMismatch, InvalidPayloadLength, InvalidHeadersLength,
    DuplicateHeader, EventStreamHeaderParser, DecodeUtils, EventStream,
    NoInitialResponseError
)
from ibm_botocore.exceptions import EventStreamError

EMPTY_MESSAGE = (
    b'\x00\x00\x00\x10\x00\x00\x00\x00\x05\xc2H\xeb}\x98\xc8\xff',
    EventStreamMessage(
        prelude=MessagePrelude(
            total_length=0x10,
            headers_length=0,
            crc=0x05c248eb,
        ),
        headers={},
        payload=b'',
        crc=0x7d98c8ff,
    )
)

INT32_HEADER = (
    (b"\x00\x00\x00+\x00\x00\x00\x0e4\x8b\xec{\x08event-id\x04\x00\x00\xa0\x0c"
     b"{'foo':'bar'}\xd3\x89\x02\x85"),
    EventStreamMessage(
        prelude=MessagePrelude(
            total_length=0x2b,
            headers_length=0x0e,
            crc=0x348bec7b,
        ),
        headers={'event-id': 0x0000a00c},
        payload=b"{'foo':'bar'}",
        crc=0xd3890285,
    )
)

PAYLOAD_NO_HEADERS = (
    b"\x00\x00\x00\x1d\x00\x00\x00\x00\xfdR\x8cZ{'foo':'bar'}\xc3e96",
    EventStreamMessage(
        prelude=MessagePrelude(
            total_length=0x1d,
            headers_length=0,
            crc=0xfd528c5a,
        ),
        headers={},
        payload=b"{'foo':'bar'}",
        crc=0xc3653936,
    )
)

PAYLOAD_ONE_STR_HEADER = (
    (b"\x00\x00\x00=\x00\x00\x00 \x07\xfd\x83\x96\x0ccontent-type\x07\x00\x10"
     b"application/json{'foo':'bar'}\x8d\x9c\x08\xb1"),
    EventStreamMessage(
        prelude=MessagePrelude(
            total_length=0x3d,
            headers_length=0x20,
            crc=0x07fd8396,
        ),
        headers={'content-type': 'application/json'},
        payload=b"{'foo':'bar'}",
        crc=0x8d9c08b1,
    )
)

ALL_HEADERS_TYPES = (
    (b"\x00\x00\x00\x62\x00\x00\x00\x52\x03\xb5\xcb\x9c"
     b"\x010\x00\x011\x01\x012\x02\x02\x013\x03\x00\x03"
     b"\x014\x04\x00\x00\x00\x04\x015\x05\x00\x00\x00\x00\x00\x00\x00\x05"
     b"\x016\x06\x00\x05bytes\x017\x07\x00\x04utf8"
     b"\x018\x08\x00\x00\x00\x00\x00\x00\x00\x08\x019\x090123456789abcdef"
     b"\x63\x35\x36\x71"),
    EventStreamMessage(
        prelude=MessagePrelude(
            total_length=0x62,
            headers_length=0x52,
            crc=0x03b5cb9c,
        ),
        headers={
            '0': True,
            '1': False,
            '2': 0x02,
            '3': 0x03,
            '4': 0x04,
            '5': 0x05,
            '6': b'bytes',
            '7': u'utf8',
            '8': 0x08,
            '9': b'0123456789abcdef',
        },
        payload=b"",
        crc=0x63353671,
    )
)

ERROR_EVENT_MESSAGE = (
    (b"\x00\x00\x00\x52\x00\x00\x00\x42\xbf\x23\x63\x7e"
     b"\x0d:message-type\x07\x00\x05error"
     b"\x0b:error-code\x07\x00\x04code"
     b"\x0e:error-message\x07\x00\x07message"
     b"\x6b\x6c\xea\x3d"),
    EventStreamMessage(
        prelude=MessagePrelude(
            total_length=0x52,
            headers_length=0x42,
            crc=0xbf23637e,
        ),
        headers={
            ':message-type': 'error',
            ':error-code': 'code',
            ':error-message': 'message',
        },
        payload=b'',
        crc=0x6b6cea3d,
    )
)

# Tuples of encoded messages and their expected decoded output
POSITIVE_CASES = [
    EMPTY_MESSAGE,
    INT32_HEADER,
    PAYLOAD_NO_HEADERS,
    PAYLOAD_ONE_STR_HEADER,
    ALL_HEADERS_TYPES,
    ERROR_EVENT_MESSAGE,
]

CORRUPTED_HEADER_LENGTH = (
    (b"\x00\x00\x00=\xFF\x00\x01\x02\x07\xfd\x83\x96\x0ccontent-type\x07\x00"
     b"\x10application/json{'foo':'bar'}\x8d\x9c\x08\xb1"),
    InvalidHeadersLength
)

CORRUPTED_HEADERS = (
    (b"\x00\x00\x00=\x00\x00\x00 \x07\xfd\x83\x96\x0ccontent+type\x07\x00\x10"
     b"application/json{'foo':'bar'}\x8d\x9c\x08\xb1"),
    ChecksumMismatch
)

CORRUPTED_LENGTH = (
    b"\x01\x00\x00\x1d\x00\x00\x00\x00\xfdR\x8cZ{'foo':'bar'}\xc3e96",
    InvalidPayloadLength
)

CORRUPTED_PAYLOAD = (
    b"\x00\x00\x00\x1d\x00\x00\x00\x00\xfdR\x8cZ{'foo':'bar'\x8d\xc3e96",
    ChecksumMismatch
)

DUPLICATE_HEADER = (
    (b"\x00\x00\x00\x24\x00\x00\x00\x14\x4b\xb9\x82\xd0"
     b"\x04test\x04asdf\x04test\x04asdf\xf3\xf4\x75\x63"),
    DuplicateHeader
)

# Tuples of encoded messages and their expected exception
NEGATIVE_CASES = [
    CORRUPTED_LENGTH,
    CORRUPTED_PAYLOAD,
    CORRUPTED_HEADERS,
    CORRUPTED_HEADER_LENGTH,
    DUPLICATE_HEADER,
]


def assert_message_equal(message_a, message_b):
    """Asserts all fields for two messages are equal. """
    assert_equal(
        message_a.prelude.total_length,
        message_b.prelude.total_length
    )
    assert_equal(
        message_a.prelude.headers_length,
        message_b.prelude.headers_length
    )
    assert_equal(message_a.prelude.crc, message_b.prelude.crc)
    assert_equal(message_a.headers, message_b.headers)
    assert_equal(message_a.payload, message_b.payload)
    assert_equal(message_a.crc, message_b.crc)


def test_partial_message():
    """ Ensure that we can receive partial payloads. """
    data = EMPTY_MESSAGE[0]
    event_buffer = EventStreamBuffer()
    # This mid point is an arbitrary break in the middle of the headers
    mid_point = 15
    event_buffer.add_data(data[:mid_point])
    messages = list(event_buffer)
    assert_equal(messages, [])
    event_buffer.add_data(data[mid_point:len(data)])
    for message in event_buffer:
        assert_message_equal(message, EMPTY_MESSAGE[1])


def check_message_decodes(encoded, decoded):
    """ Ensure the message decodes to what we expect. """
    event_buffer = EventStreamBuffer()
    event_buffer.add_data(encoded)
    messages = list(event_buffer)
    assert len(messages) == 1
    assert_message_equal(messages[0], decoded)


def test_positive_cases():
    """Test that all positive cases decode how we expect. """
    for (encoded, decoded) in POSITIVE_CASES:
        yield check_message_decodes, encoded, decoded


def test_all_positive_cases():
    """Test all positive cases can be decoded on the same buffer. """
    event_buffer = EventStreamBuffer()
    # add all positive test cases to the same buffer
    for (encoded, _) in POSITIVE_CASES:
        event_buffer.add_data(encoded)
    # collect all of the expected messages
    expected_messages = [decoded for (_, decoded) in POSITIVE_CASES]
    # collect all of the decoded messages
    decoded_messages = list(event_buffer)
    # assert all messages match what we expect
    for (expected, decoded) in zip(expected_messages, decoded_messages):
        assert_message_equal(expected, decoded)


def test_negative_cases():
    """Test that all negative cases raise the expected exception. """
    for (encoded, exception) in NEGATIVE_CASES:
        test_function = raises(exception)(check_message_decodes)
        yield test_function, encoded, None


def test_header_parser():
    """Test that the header parser supports all header types. """
    headers_data = (
     b"\x010\x00\x011\x01\x012\x02\x02\x013\x03\x00\x03"
     b"\x014\x04\x00\x00\x00\x04\x015\x05\x00\x00\x00\x00\x00\x00\x00\x05"
     b"\x016\x06\x00\x05bytes\x017\x07\x00\x04utf8"
     b"\x018\x08\x00\x00\x00\x00\x00\x00\x00\x08\x019\x090123456789abcdef"
    )

    expected_headers = {
        '0': True,
        '1': False,
        '2': 0x02,
        '3': 0x03,
        '4': 0x04,
        '5': 0x05,
        '6': b'bytes',
        '7': u'utf8',
        '8': 0x08,
        '9': b'0123456789abcdef',
    }

    parser = EventStreamHeaderParser()
    headers = parser.parse(headers_data)
    assert_equal(headers, expected_headers)


def test_message_prelude_properties():
    """Test that calculated properties from the payload are correct. """
    # Total length: 40, Headers Length: 15, random crc
    prelude = MessagePrelude(40, 15, 0x00000000)
    assert_equal(prelude.payload_length, 9)
    assert_equal(prelude.headers_end, 27)
    assert_equal(prelude.payload_end, 36)


def test_message_to_response_dict():
    response_dict = INT32_HEADER[1].to_response_dict()
    assert_equal(response_dict['status_code'], 200)
    assert_equal(response_dict['headers'], {'event-id': 0x0000a00c})
    assert_equal(response_dict['body'], b"{'foo':'bar'}")


def test_message_to_response_dict_error():
    response_dict = ERROR_EVENT_MESSAGE[1].to_response_dict()
    assert_equal(response_dict['status_code'], 400)
    headers = {
        ':message-type': 'error',
        ':error-code': 'code',
        ':error-message': 'message',
    }
    assert_equal(response_dict['headers'], headers)
    assert_equal(response_dict['body'], b'')


def test_unpack_uint8():
    (value, bytes_consumed) = DecodeUtils.unpack_uint8(b'\xDE')
    assert_equal(bytes_consumed, 1)
    assert_equal(value, 0xDE)


def test_unpack_uint32():
    (value, bytes_consumed) = DecodeUtils.unpack_uint32(b'\xDE\xAD\xBE\xEF')
    assert_equal(bytes_consumed, 4)
    assert_equal(value, 0xDEADBEEF)


def test_unpack_int16():
    (value, bytes_consumed) = DecodeUtils.unpack_int16(b'\xFF\xFE')
    assert_equal(bytes_consumed, 2)
    assert_equal(value, -2)


def test_unpack_int32():
    (value, bytes_consumed) = DecodeUtils.unpack_int32(b'\xFF\xFF\xFF\xFE')
    assert_equal(bytes_consumed, 4)
    assert_equal(value, -2)


def test_unpack_int64():
    test_bytes = b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE'
    (value, bytes_consumed) = DecodeUtils.unpack_int64(test_bytes)
    assert_equal(bytes_consumed, 8)
    assert_equal(value, -2)


def test_unpack_array_short():
    test_bytes = b'\x00\x10application/json'
    (value, bytes_consumed) = DecodeUtils.unpack_byte_array(test_bytes)
    assert_equal(bytes_consumed, 18)
    assert_equal(value, b'application/json')


def test_unpack_byte_array_int():
    (value, array_bytes_consumed) = DecodeUtils.unpack_byte_array(
        b'\x00\x00\x00\x10application/json', length_byte_size=4)
    assert_equal(array_bytes_consumed, 20)
    assert_equal(value, b'application/json')


def test_unpack_utf8_string():
    length = b'\x00\x09'
    utf8_string = b'\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e'
    encoded = length + utf8_string
    (value, bytes_consumed) = DecodeUtils.unpack_utf8_string(encoded)
    assert_equal(bytes_consumed, 11)
    assert_equal(value, utf8_string.decode('utf-8'))


def test_unpack_prelude():
    data = b'\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03'
    prelude = DecodeUtils.unpack_prelude(data)
    assert_equal(prelude, ((1, 2, 3), 12))


def create_mock_raw_stream(*data):
    raw_stream = Mock()
    def generator():
        for chunk in data:
            yield chunk
    raw_stream.stream = generator
    return raw_stream


def test_event_stream_wrapper_iteration():
    raw_stream = create_mock_raw_stream(
        b"\x00\x00\x00+\x00\x00\x00\x0e4\x8b\xec{\x08event-id\x04\x00",
        b"\x00\xa0\x0c{'foo':'bar'}\xd3\x89\x02\x85",
    )
    parser = Mock(spec=EventStreamXMLParser)
    output_shape = Mock()
    event_stream = EventStream(raw_stream, output_shape, parser, '')
    events = list(event_stream)
    assert_equal(len(events), 1)

    response_dict = {
        'headers': {'event-id': 0x0000a00c},
        'body': b"{'foo':'bar'}",
        'status_code': 200,
    }
    parser.parse.assert_called_with(response_dict, output_shape)


@raises(EventStreamError)
def test_eventstream_wrapper_iteration_error():
    raw_stream = create_mock_raw_stream(ERROR_EVENT_MESSAGE[0])
    parser = Mock(spec=EventStreamXMLParser)
    parser.parse.return_value = {}
    output_shape = Mock()
    event_stream = EventStream(raw_stream, output_shape, parser, '')
    list(event_stream)


def test_event_stream_wrapper_close():
    raw_stream = Mock()
    event_stream = EventStream(raw_stream, None, None, '')
    event_stream.close()
    raw_stream.close.assert_called_once_with()


def test_event_stream_initial_response():
    raw_stream = create_mock_raw_stream(
        b'\x00\x00\x00~\x00\x00\x00O\xc5\xa3\xdd\xc6\r:message-type\x07\x00',
        b'\x05event\x0b:event-type\x07\x00\x10initial-response\r:content-type',
        b'\x07\x00\ttext/json{"InitialResponse": "sometext"}\xf6\x98$\x83'
    )
    parser = Mock(spec=EventStreamXMLParser)
    output_shape = Mock()
    event_stream = EventStream(raw_stream, output_shape, parser, '')
    event = event_stream.get_initial_response()
    headers = {
        ':message-type': 'event',
        ':event-type': 'initial-response',
        ':content-type': 'text/json',
    }
    payload = b'{"InitialResponse": "sometext"}'
    assert event.headers == headers
    assert event.payload == payload


@raises(NoInitialResponseError)
def test_event_stream_initial_response_wrong_type():
    raw_stream = create_mock_raw_stream(
        b"\x00\x00\x00+\x00\x00\x00\x0e4\x8b\xec{\x08event-id\x04\x00",
        b"\x00\xa0\x0c{'foo':'bar'}\xd3\x89\x02\x85",
    )
    parser = Mock(spec=EventStreamXMLParser)
    output_shape = Mock()
    event_stream = EventStream(raw_stream, output_shape, parser, '')
    event_stream.get_initial_response()


@raises(NoInitialResponseError)
def test_event_stream_initial_response_no_event():
    raw_stream = create_mock_raw_stream(b'')
    parser = Mock(spec=EventStreamXMLParser)
    output_shape = Mock()
    event_stream = EventStream(raw_stream, output_shape, parser, '')
    event_stream.get_initial_response()
