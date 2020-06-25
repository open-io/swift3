# Copyright (c) 2017 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import importlib
from six import string_types
from swift.common.utils import config_true_value

try:
    from oio.common.redis_conn import RedisConnection
except ImportError:
    # TODO(adu): Delete when it will no longer be used
    class RedisConnection(object):

        # Imported from redis-py, for compatibility with pre 2.10.6 versions.
        URL_QUERY_ARGUMENT_PARSERS = {
            'socket_timeout': float,
            'socket_connect_timeout': float,
            'socket_keepalive': config_true_value,
            'retry_on_timeout': config_true_value,
            'max_connections': int,
            'health_check_interval': int,
        }

        def __init__(self, host=None, sentinel_hosts=None,
                     sentinel_name=None, **kwargs):
            self.__redis_mod = importlib.import_module('redis')
            self.__redis_sentinel_mod = importlib.import_module(
                'redis.sentinel')

            self._conn = None
            self._host = None
            self._port = None
            self._sentinel = None
            self._sentinel_hosts = None
            self._sentinel_name = None
            self._conn_kwargs = self._filter_conn_kwargs(kwargs)

            if host:
                self._host, self._port = host.rsplit(':', 1)
                self._port = int(self._port)
                return

            if not sentinel_name:
                raise ValueError("missing parameter 'sentinel_name'")

            if isinstance(sentinel_hosts, string_types):
                sentinel_hosts = sentinel_hosts.split(',')
            self._sentinel_hosts = [(h, int(p)) for h, p, in (hp.rsplit(':', 1)
                                    for hp in sentinel_hosts)]
            self._sentinel_name = sentinel_name
            self._sentinel_conn_kwargs = self._filter_sentinel_conn_kwargs(
                kwargs)
            self._sentinel = self.__redis_sentinel_mod.Sentinel(
                self._sentinel_hosts,
                sentinel_kwargs=self._sentinel_conn_kwargs,
                **self._conn_kwargs)

        def _filter_conn_kwargs(self, conn_kwargs):
            """
            Keep only keyword arguments known by Redis classes, cast them to
            the appropriate type.
            """
            if conn_kwargs is None:
                return None
            if hasattr(self.__redis_mod.connection,
                       'URL_QUERY_ARGUMENT_PARSERS'):
                parsers = \
                    self.__redis_mod.connection.URL_QUERY_ARGUMENT_PARSERS
            else:
                parsers = self.URL_QUERY_ARGUMENT_PARSERS
            return {k: parsers[k](v)
                    for k, v in conn_kwargs.items()
                    if k in parsers}

        def _filter_sentinel_conn_kwargs(self, sentinel_conn_kwargs):
            if sentinel_conn_kwargs is None:
                return None
            return self._filter_conn_kwargs(
                {k[9:]: v for k, v in sentinel_conn_kwargs.items()
                 if k.startswith('sentinel_')})

        @property
        def conn(self):
            """Retrieve Redis connection (normal or sentinel)"""
            if self._sentinel:
                return self._sentinel.master_for(self._sentinel_name)
            if not self._conn:
                self._conn = self.__redis_mod.StrictRedis(
                    host=self._host, port=self._port,
                    **self._conn_kwargs)
            return self._conn

        @property
        def conn_slave(self):
            """Retrieve Redis connection (normal or sentinel)"""
            if self._sentinel:
                return self._sentinel.slave_for(self._sentinel_name)
            return self.conn


class DummyBucketDb(object):
    """
    Keep a list of buckets with their associated account.
    Dummy in-memory implementation.
    """

    def __init__(self, *args, **kwargs):
        self._bucket_db = dict()

    def get_owner(self, bucket):
        """
        Get the owner of a bucket.
        """
        owner, deadline = self._bucket_db.get(bucket, (None, None))
        if deadline is not None and deadline < time.time():
            del self._bucket_db[bucket]
            return None
        return owner

    def reserve(self, bucket, owner, timeout=30):
        """
        Reserve a bucket. The bucket entry must not already
        exist in the database.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :param timeout: a timeout in seconds, for the reservation to expire.
        :returns: True if the bucket has been reserved, False otherwise
        """
        if self.get_owner(bucket):
            return False
        deadline = time.time() + timeout
        self._bucket_db[bucket] = (owner, deadline)
        return True

    def set_owner(self, bucket, owner):
        """
        Set the owner of a bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :returns: True if the ownership has been set
        """
        self._bucket_db[bucket] = (owner, None)
        return True

    def release(self, bucket):
        """
        Remove the bucket from the database.
        """
        self._bucket_db.pop(bucket, None)


class RedisBucketDb(RedisConnection):
    """
    Keep a list of buckets with their associated account.
    """

    def __init__(self, host=None, sentinel_hosts=None, sentinel_name=None,
                 prefix="s3bucket:", **kwargs):
        super(RedisBucketDb, self).__init__(
            host=host, sentinel_hosts=sentinel_hosts,
            sentinel_name=sentinel_name, **kwargs)
        self._prefix = prefix

    def _key(self, bucket):
        return self._prefix + bucket

    def get_owner(self, bucket):
        """
        Get the owner of a bucket.

        :returns: the name of the account owning the bucket or None
        """
        owner = self.conn_slave.get(self._key(bucket))
        return owner

    def set_owner(self, bucket, owner):
        """
        Set the owner of a bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :returns: True if the ownership has been set
        """
        res = self.conn.set(self._key(bucket), owner)
        return res is True

    def reserve(self, bucket, owner, timeout=30):
        """
        Reserve a bucket. The bucket entry must not already
        exist in the database.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :param timeout: a timeout in seconds, for the reservation to expire.
        :returns: True if the bucket has been reserved, False otherwise
        """
        res = self.conn.set(self._key(bucket), owner,
                            ex=int(timeout), nx=True)
        return res is True

    def release(self, bucket):
        """
        Remove the bucket from the database.
        """
        self.conn.delete(self._key(bucket))


class BucketDbWrapper(object):
    """
    Memoizer for bucket DB. It is intended to have the same life cycle
    as an S3 request.
    """

    def __init__(self, bucket_db):
        self.bucket_db = bucket_db
        self.cache = dict()

    def get_owner(self, bucket, **kwargs):
        cached = self.cache.get(bucket)
        if cached:
            return cached
        owner = self.bucket_db.get_owner(bucket=bucket, **kwargs)
        self.cache[bucket] = owner
        return owner

    def set_owner(self, bucket, owner, **kwargs):
        res = self.bucket_db.set_owner(bucket=bucket, owner=owner, **kwargs)
        if res:
            self.cache[bucket] = owner
        return res

    def release(self, bucket, **kwargs):
        self.cache.pop(bucket, None)
        return self.bucket_db.release(bucket=bucket, **kwargs)

    def reserve(self, bucket, owner, **kwargs):
        res = self.bucket_db.reserve(bucket=bucket, owner=owner, **kwargs)
        if res:
            self.cache[bucket] = owner
        return res


def get_bucket_db(conf):
    """
    If `bucket_db_enabled` is set in `conf`, get the bucket database,
    otherwise return `None`.

    If `bucket_db_host` or `bucket_db_sentinel_hosts` are also set in `conf`,
    return an instance of `RedisBucketDb`, otherwise return an instance of
    `DummyBucketDb`.
    """
    db_kwargs = {k[10:]: v for k, v in conf.items()
                 if k.startswith('bucket_db_')}
    if config_true_value(db_kwargs.get('enabled', 'false')):
        if 'host' in db_kwargs or 'sentinel_hosts' in db_kwargs:
            if db_kwargs.get('sentinel_name') is None:
                # TODO(adu): Delete when it will no longer be used
                db_kwargs['sentinel_name'] = db_kwargs.pop('master_name', None)
            return RedisBucketDb(**db_kwargs)
        else:
            return DummyBucketDb(**db_kwargs)

    return None
