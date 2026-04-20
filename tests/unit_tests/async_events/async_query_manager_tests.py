# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import time
from unittest import mock
from unittest.mock import ANY, Mock

from flask import g
from jwt import encode
from pytest import fixture, mark, raises  # noqa: PT013

from superset import security_manager
from superset.async_events.async_query_manager import (
    AsyncQueryManager,
    AsyncQueryTokenException,
)
from superset.async_events.cache_backend import (
    RedisCacheBackend,
    RedisSentinelCacheBackend,
)

JWT_TOKEN_SECRET = "some_secret"  # noqa: S105
JWT_TOKEN_COOKIE_NAME = "superset_async_jwt"  # noqa: S105
JWT_TOKEN_AUDIENCE = "superset"  # noqa: S105


@fixture
def async_query_manager():
    query_manager = AsyncQueryManager()
    query_manager._jwt_secret = JWT_TOKEN_SECRET
    query_manager._jwt_cookie_name = JWT_TOKEN_COOKIE_NAME
    query_manager._jwt_audience_config = JWT_TOKEN_AUDIENCE
    query_manager._jwt_exp_seconds = 300
    query_manager._jwt_leeway = 5
    query_manager._jwt_strict = True
    return query_manager


@fixture
def async_query_manager_compat(async_query_manager):
    async_query_manager._jwt_strict = False
    return async_query_manager


def set_current_as_guest_user():
    g.user = security_manager.get_guest_user_from_token(
        {"user": {}, "resources": [{"type": "dashboard", "id": "some-uuid"}]}
    )


def _encode(payload, secret=JWT_TOKEN_SECRET):
    return encode(payload, secret, algorithm="HS256")


def test_parse_channel_id_from_request(async_query_manager):
    now = int(time.time())
    encoded_token = _encode(
        {
            "channel": "test_channel_id",
            "sub": "1",
            "iat": now,
            "exp": now + 300,
            "aud": JWT_TOKEN_AUDIENCE,
        }
    )

    request = Mock()
    request.cookies = {"superset_async_jwt": encoded_token}

    assert (
        async_query_manager.parse_channel_id_from_request(request) == "test_channel_id"
    )


def test_parse_channel_id_from_request_no_cookie(async_query_manager):
    request = Mock()
    request.cookies = {}

    with raises(AsyncQueryTokenException):
        async_query_manager.parse_channel_id_from_request(request)


def test_parse_channel_id_from_request_bad_jwt(async_query_manager):
    request = Mock()
    request.cookies = {"superset_async_jwt": "bad_jwt"}

    with raises(AsyncQueryTokenException):
        async_query_manager.parse_channel_id_from_request(request)


def test_parse_channel_id_from_request_rejects_expired(async_query_manager):
    now = int(time.time())
    expired_token = _encode(
        {
            "channel": "test_channel_id",
            "sub": "1",
            "iat": now - 1000,
            "exp": now - 600,
            "aud": JWT_TOKEN_AUDIENCE,
        }
    )
    request = Mock()
    request.cookies = {"superset_async_jwt": expired_token}

    with raises(AsyncQueryTokenException):
        async_query_manager.parse_channel_id_from_request(request)


def test_parse_channel_id_from_request_rejects_wrong_audience(async_query_manager):
    now = int(time.time())
    token = _encode(
        {
            "channel": "test_channel_id",
            "sub": "1",
            "iat": now,
            "exp": now + 300,
            "aud": "someone-else",
        }
    )
    request = Mock()
    request.cookies = {"superset_async_jwt": token}

    with raises(AsyncQueryTokenException):
        async_query_manager.parse_channel_id_from_request(request)


def test_parse_channel_id_from_request_rejects_missing_claims_strict(
    async_query_manager,
):
    token = _encode({"channel": "test_channel_id"})
    request = Mock()
    request.cookies = {"superset_async_jwt": token}

    with raises(AsyncQueryTokenException):
        async_query_manager.parse_channel_id_from_request(request)


def test_parse_channel_id_from_request_accepts_missing_claims_compat(
    async_query_manager_compat,
):
    token = _encode({"channel": "test_channel_id"})
    request = Mock()
    request.cookies = {"superset_async_jwt": token}

    assert (
        async_query_manager_compat.parse_channel_id_from_request(request)
        == "test_channel_id"
    )


def test_parse_channel_id_from_request_rejects_missing_channel(async_query_manager):
    now = int(time.time())
    token = _encode(
        {
            "sub": "1",
            "iat": now,
            "exp": now + 300,
            "aud": JWT_TOKEN_AUDIENCE,
        }
    )
    request = Mock()
    request.cookies = {"superset_async_jwt": token}

    with raises(AsyncQueryTokenException):
        async_query_manager.parse_channel_id_from_request(request)


def test_parse_channel_id_from_request_respects_leeway(async_query_manager):
    now = int(time.time())
    token = _encode(
        {
            "channel": "test_channel_id",
            "sub": "1",
            "iat": now,
            # Expired 2 seconds ago; within default 5-second leeway.
            "exp": now - 2,
            "aud": JWT_TOKEN_AUDIENCE,
        }
    )
    request = Mock()
    request.cookies = {"superset_async_jwt": token}

    assert (
        async_query_manager.parse_channel_id_from_request(request) == "test_channel_id"
    )


def test_encode_jwt_includes_standard_claims(async_query_manager):
    token, exp = async_query_manager._encode_jwt("ch-123", user_id=42)
    # round-trip decode using the manager's own validator
    claims = async_query_manager._decode_jwt(token)
    assert claims["channel"] == "ch-123"
    assert claims["sub"] == "42"
    assert claims["aud"] == JWT_TOKEN_AUDIENCE
    assert claims["exp"] == int(exp)
    assert "iat" in claims


@mark.parametrize(
    "cache_type, cache_backend",
    [
        ("RedisCacheBackend", mock.Mock(spec=RedisCacheBackend)),
        ("RedisSentinelCacheBackend", mock.Mock(spec=RedisSentinelCacheBackend)),
    ],
)
@mock.patch("superset.is_feature_enabled")
def test_submit_chart_data_job_as_guest_user(
    is_feature_enabled_mock, async_query_manager, cache_type, cache_backend
):
    is_feature_enabled_mock.return_value = True
    set_current_as_guest_user()

    # Mock the get_cache_backend method to return the current cache backend
    async_query_manager.get_cache_backend = mock.Mock(return_value=cache_backend)

    job_mock = Mock()
    async_query_manager._load_chart_data_into_cache_job = job_mock
    job_meta = async_query_manager.submit_chart_data_job(
        channel_id="test_channel_id",
        form_data={},
    )

    job_mock.delay.assert_called_once_with(
        {
            "channel_id": "test_channel_id",
            "errors": [],
            "guest_token": {
                "resources": [{"id": "some-uuid", "type": "dashboard"}],
                "user": {},
            },
            "job_id": ANY,
            "result_url": None,
            "status": "pending",
            "user_id": None,
        },
        {},
    )

    assert "guest_token" not in job_meta
    job_mock.reset_mock()  # Reset the mock for the next iteration


@mark.parametrize(
    "cache_type, cache_backend",
    [
        ("RedisCacheBackend", mock.Mock(spec=RedisCacheBackend)),
        ("RedisSentinelCacheBackend", mock.Mock(spec=RedisSentinelCacheBackend)),
    ],
)
@mock.patch("superset.is_feature_enabled")
def test_submit_explore_json_job_as_guest_user(
    is_feature_enabled_mock, async_query_manager, cache_type, cache_backend
):
    is_feature_enabled_mock.return_value = True
    set_current_as_guest_user()

    # Mock the get_cache_backend method to return the current cache backend
    async_query_manager.get_cache_backend = mock.Mock(return_value=cache_backend)

    job_mock = Mock()
    async_query_manager._load_explore_json_into_cache_job = job_mock
    job_meta = async_query_manager.submit_explore_json_job(
        channel_id="test_channel_id",
        form_data={},
        response_type="json",
    )

    job_mock.delay.assert_called_once_with(
        {
            "channel_id": "test_channel_id",
            "errors": [],
            "guest_token": {
                "resources": [{"id": "some-uuid", "type": "dashboard"}],
                "user": {},
            },
            "job_id": ANY,
            "result_url": None,
            "status": "pending",
            "user_id": None,
        },
        {},
        "json",
        False,
    )

    assert "guest_token" not in job_meta
