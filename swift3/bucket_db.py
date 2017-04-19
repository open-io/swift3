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


class BucketDb(object):
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

    def set_owner(self, bucket, owner, timeout=None):
        """
        Set the owner of a bucket.

        :param bucket: name of the bucket
        :param owner: name of the account owning the bucket
        :param timeout: a timeout in seconds, for the ownership to expire.
                        `None` means no timeout.
        """
        if timeout is not None:
            deadline = time.time() + timeout
        else:
            deadline = None
        self._bucket_db[bucket] = (owner, deadline)

    def release(self, bucket):
        """
        Remove the bucket from the database.
        """
        self._bucket_db.pop(bucket, None)
