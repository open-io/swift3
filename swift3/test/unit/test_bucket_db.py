from swift.common import swob
from swift.common.swob import Request
from swift.common.utils import json
from swift3.cfg import CONF
from swift3.etree import fromstring
from swift3.test.unit import Swift3TestCase


class TestSwift3BucketDb(Swift3TestCase):

    def __init__(self, name):
        super(TestSwift3BucketDb, self).__init__(name)

    def setUp(self):
        # Trick to load dummy bucket DB
        CONF.bucket_db_enabled = True

        super(TestSwift3BucketDb, self).setUp()
        self.swift.register('PUT', '/v1/AUTH_test2/bucket',
                            swob.HTTPCreated, {}, None)
        self.swift.register('PUT', '/v1/AUTH_test/bucket-server-error',
                            swob.HTTPServerError, {}, None)
        self.swift.register(
            'HEAD', '/v1/AUTH_test/bucket', swob.HTTPNoContent,
            {'X-Container-Object-Count': 0}, None)
        self.swift.register(
            'GET', '/v1/AUTH_test/bucket+segments?format=json&marker=',
            swob.HTTPNotFound, {}, None)

    @property
    def db(self):
        return self.swift3.bucket_db

    def _bucket_op(self, op, bucket='bucket', account='test'):
        req = Request.blank(
            '/%s' % bucket,
            environ={'REQUEST_METHOD': op},
            headers={'Authorization': 'AWS %s:tester:hmac' % account,
                     'Date': self.get_date_header()})
        return self.call_swift3(req)

    def _bucket_put(self, *args, **kwargs):
        return self._bucket_op('PUT', *args, **kwargs)

    def _bucket_get(self, *args, **kwargs):
        return self._bucket_op('GET', *args, **kwargs)

    def _bucket_delete(self, *args, **kwargs):
        return self._bucket_op('DELETE', *args, **kwargs)

    def test_bucket_PUT(self):
        self.assertEqual(self.db.get_owner('bucket'), None)
        status, headers, body = self._bucket_put()
        self.assertEqual(body, '')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(headers['Location'], '/bucket')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

    def test_bucket_PUT_twice(self):
        self.assertEqual(self.db.get_owner('bucket'), None)
        status, headers, body = self._bucket_put()
        self.assertEqual(body, '')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(headers['Location'], '/bucket')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        status, headers, body = self._bucket_put()
        self.assertEqual(status.split()[0], '409')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

    def test_bucket_PUT_other_account(self):
        self.assertEqual(self.db.get_owner('bucket'), None)
        status, headers, body = self._bucket_put()
        self.assertEqual(body, '')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(headers['Location'], '/bucket')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        status, headers, body = self._bucket_put(account='test2')
        self.assertEqual(status.split()[0], '409')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

    def test_bucket_PUT_fail(self):
        self.assertEqual(self.db.get_owner('bucket-server-error'), None)
        status, _, _ = self._bucket_put('bucket-server-error')
        self.assertEqual(status.split()[0], '500')
        self.assertEqual(self.db.get_owner('bucket-server-error'), None)

    def test_bucket_DELETE(self):
        self.assertEqual(self.db.get_owner('bucket'), None)
        status, _, _ = self._bucket_put()
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        status, _, _ = self._bucket_delete()
        self.assertEqual(status.split()[0], '204')
        self.assertEqual(self.db.get_owner('bucket'), None)

    def test_bucket_DELETE_fail(self):
        self.assertEqual(self.db.get_owner('bucket'), None)
        status, _, _ = self._bucket_put()
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        self.swift.register('DELETE', '/v1/AUTH_test/bucket',
                            swob.HTTPServerError, {}, None)
        status, _, _ = self._bucket_delete()
        self.assertEqual(status.split()[0], '500')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

    def test_bucket_PUT_after_DELETE(self):
        self.assertEqual(self.db.get_owner('bucket'), None)
        status, _, _ = self._bucket_put()
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        status, _, _ = self._bucket_delete()
        self.assertEqual(status.split()[0], '204')
        self.assertEqual(self.db.get_owner('bucket'), None)

        status, _, _ = self._bucket_put(account='test2')
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test2')

    def test_bucket_GET_other_account(self):
        self.assertEqual(self.db.get_owner('bucket'), None)
        status, _, _ = self._bucket_put()
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(self.db.get_owner('bucket'), 'AUTH_test')

        # Register request with account 'test'.
        expected_body = json.dumps(
            [{"name": "expected",
              "last_modified": "2017-04-21T16:30:34.133034",
              "hash": "0000",
              "bytes": 0}])
        self.swift.register('GET',
                            '/v1/AUTH_test/bucket?format=json&limit=1001',
                            swob.HTTPOk, {}, expected_body)
        # Then do a call with 'test2' account, that should be changed
        # to 'test' by the middleware (because the bucket 'bucket' belongs
        # to account 'test').
        status, _, body = self._bucket_get('bucket', account='test2')
        elem = fromstring(body, "ListBucketResult")
        self.assertEqual(status.split()[0], '200')
        self.assertEqual(elem.find('Contents').find('Key').text, "expected")
