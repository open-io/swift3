# Copyright (c) 2020 OpenStack Foundation.
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

import json
from unittest import TestCase
from mock import MagicMock

from swift3.iam import IamResource, IamRulesMatcher, \
    EXPLICIT_DENY, EXPLICIT_ALLOW
from swift3.exception import IAMException


class TestSwift3Iam(TestCase):

    def test_invalid_action_for_resource_type(self):
        rsc = IamResource("customer")  # Bucket resource
        self.assertRaises(IAMException,
                          IamRulesMatcher({}), rsc, "s3:GetObject")

    def test_action_wildcard(self):
        rules = json.loads("""{
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:Get*",
                        "s3:List*"
                    ],
                    "Resource": ["*"],
                    "Sid": "ReadOnly"
                }
            ],
            "Version": "2012-10-17"
        }
        """)
        check = IamRulesMatcher(rules)
        bucket_res = IamResource("customer")
        object_res = IamResource("customer/somefile")
        self.assertEqual((EXPLICIT_ALLOW, 'ReadOnly'),
                         check(object_res, "s3:GetObject"))
        self.assertEqual((EXPLICIT_ALLOW, 'ReadOnly'),
                         check(bucket_res, "s3:GetBucketLocation"))
        self.assertEqual((EXPLICIT_ALLOW, 'ReadOnly'),
                         check(bucket_res, "s3:ListBucket"))
        self.assertEqual((None, None),
                         check(bucket_res, "s3:CreateBucket"))
        self.assertEqual((None, None),
                         check(object_res, "s3:PutObject"))

    def test_explicit_allow(self):
        rules = json.loads("""{
            "Statement": [
                {
                    "Action": ["s3:GetObject"],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::customer/dede"
                    ],
                    "Sid": "AllowGetSpecificObject"
                }
            ],
            "Version": "2012-10-17"
        }
        """)
        rsc = IamResource("customer/dede")
        check = IamRulesMatcher(rules)
        self.assertEqual((EXPLICIT_ALLOW, 'AllowGetSpecificObject'),
                         check(rsc, "s3:GetObject"))
        forbidden = IamResource("customer/somefile")
        self.assertEqual((None, None),
                         check(forbidden, "s3:GetObject"))

    def test_explicit_deny(self):
        rules = json.loads("""{
            "Statement": [
                {
                    "Action": ["s3:*"],
                    "Effect": "Allow",
                    "Resource": ["*"],
                    "Sid": "DefaultFullAccess"
                },
                {
                    "Action": ["s3:*"],
                    "Effect": "Deny",
                    "Resource": [
                        "arn:aws:s3:::customer",
                        "arn:aws:s3:::customer/*"
                    ],
                    "Sid": "DenyCustomerBucketAndObjects"
                }
            ],
            "Version": "2012-10-17"
        }
        """)
        rsc = IamResource("customer/dede")
        check = IamRulesMatcher(rules)
        self.assertEqual((EXPLICIT_DENY, 'DenyCustomerBucketAndObjects'),
                         check(rsc, "s3:GetObject"))

        rsc = IamResource("customer")
        check = IamRulesMatcher(rules)
        self.assertEqual((EXPLICIT_DENY, 'DenyCustomerBucketAndObjects'),
                         check(rsc, "s3:ListBucketMultipartUploads"))

    def test_explicit_wildcard_bucket_path(self):
        rules = json.loads("""
        {
            "Statement": [
                {
                    "Action": ["s3:GetObject"],
                    "Effect": "Allow",
                    "Resource": ["arn:aws:s3:::*/*"],
                    "Sid": "AllowWildcard-2"
                }
            ],
            "Version": "2012-10-17"
        }
        """)
        rsc = IamResource("bucket/dede")
        check = IamRulesMatcher(rules)
        self.assertEqual((EXPLICIT_ALLOW, 'AllowWildcard-2'),
                         check(rsc, "s3:GetObject"))

    def test_explicit_wildcard_path(self):
        rules = json.loads("""
        {
            "Statement": [
                {
                    "Action": ["s3:GetObject"],
                    "Effect": "Allow",
                    "Resource": ["arn:aws:s3:::bucket/*"],
                    "Sid": "AllowWildcard-3"
                }
            ],
            "Version": "2012-10-17"
        }
        """)
        rsc = IamResource("bucket/dede")
        check = IamRulesMatcher(rules)
        self.assertEqual((EXPLICIT_ALLOW, 'AllowWildcard-3'),
                         check(rsc, "s3:GetObject"))

    def test_bucket_and_object_wildcards(self):
        rules = json.loads("""
        {
            "Statement": [
                {
                    "Action": [
                        "s3:*"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::s3rt*"
                    ],
                    "Sid": "S3RoundtripBucket"
                },
                {
                    "Action": [
                        "s3:*"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::s3rt*/*"
                    ],
                    "Sid": "S3RoundtripObjects"
                }
            ]
        }
        """)
        check = IamRulesMatcher(rules)
        bkt_res = IamResource("s3rt-test")
        self.assertEqual((EXPLICIT_ALLOW, 'S3RoundtripBucket'),
                         check(bkt_res, "s3:CreateBucket"))
        obj_res = IamResource("s3rt-test/hosts")
        self.assertEqual((EXPLICIT_ALLOW, 'S3RoundtripObjects'),
                         check(obj_res, "s3:PutObject"))

        obj_res2 = IamResource("s3ru-test/hosts")
        self.assertEqual((None, None),
                         check(obj_res2, "s3:PutObject"))

    def test_statement_condition_stringequals(self):
        rules = json.loads("""{
            "Statement": [
                {
                    "Sid": "AllowRootAndHomeListingOfCompanyBucket",
                    "Action": ["s3:ListBucket"],
                    "Effect": "Allow",
                    "Resource": ["arn:aws:s3:::my-company"],
                    "Condition": {
                        "StringEquals": {
                            "s3:prefix": ["", "home/", "home/David"],
                            "s3:delimiter": ["/"]
                        }
                    }
                }
            ],
            "Version": "2012-10-17"
        }
        """)
        check = IamRulesMatcher(rules)
        bucket_res = IamResource("my-company")
        self.assertEqual((None, None),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={})))
        self.assertEqual((None, None),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={'prefix': ''})))
        self.assertEqual((None, None),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={'prefix': 'home/Michael',
                                                 'delimiter': '/'})))
        self.assertEqual((None, None),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={'prefix': 'home/David',
                                                 'delimiter': ':'})))
        self.assertEqual(('ALLOW', 'AllowRootAndHomeListingOfCompanyBucket'),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={'prefix': 'home/David',
                                                 'delimiter': '/'})))

    def test_statement_condition_stringlike(self):
        rules = json.loads("""{
            "Statement": [
                {
                    "Sid": "AllowListingOfUserFolder",
                    "Action": ["s3:ListBucket"],
                    "Effect": "Allow",
                    "Resource": ["arn:aws:s3:::my-company"],
                    "Condition": {
                        "StringLike": {"s3:prefix": ["home/David/*"]}
                    }
                }
            ],
            "Version": "2012-10-17"
        }
        """)
        check = IamRulesMatcher(rules)
        bucket_res = IamResource("my-company")
        self.assertEqual((None, None),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={})))
        self.assertEqual((None, None),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={'prefix': ''})))
        self.assertEqual((None, None),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={'prefix': 'home/Michael/'})))
        self.assertEqual((None, None),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={'prefix': 'home/David',
                                                 'delimiter': ':'})))
        self.assertEqual(('ALLOW', 'AllowListingOfUserFolder'),
                         check(bucket_res, "s3:ListBucket",
                               MagicMock(params={'prefix': 'home/David/'})))
        self.assertEqual(
            ('ALLOW', 'AllowListingOfUserFolder'),
            check(bucket_res, "s3:ListBucket",
                  MagicMock(params={'prefix': 'home/David/foo/'})))
