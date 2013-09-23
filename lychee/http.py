# -*- coding: utf-8 -*-
"""A very basic library for parsing HTTP Request/Responses
"""

LINE_BREAK = '\r\n'


def strip_headers(data):
    """Puts the headers into a dictionary and returns that along with the body"""

    headers_raw, body = data.split(LINE_BREAK * 2, 1)

    headers = dict(split_headers(headers_raw.split(LINE_BREAK)))

    return headers, body


def split_headers(data):
    """Takes an interable of "Key: Value" and returns an interable of key, value

    This will ignore any rows that can not be split by a ':'

    """
    kv_gen = (h.split(':', 1) for h in data if ':' in h)
    return ((k.lower().strip(), v.strip()) for k, v in kv_gen)


def has_complete_headers(data):
    return LINE_BREAK * 2 in data


def parse_request(data):
    first_line, data = data.split(LINE_BREAK, 1)

    method, path, http_version = first_line.split(' ')

    headers, body = strip_headers(data)

    return dict(method=method,
                host=headers.pop('host', None),
                path=path,
                http_version=http_version,
                headers=headers,
                body=body
                )


def parse_response(data):
    headers, body = strip_headers(data)

    return dict(headers=headers,
                body=body
                )
