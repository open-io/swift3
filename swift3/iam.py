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

from functools import wraps

from swift.common.utils import get_logger

from swift3.exception import IAMException
from swift3.response import AccessDenied
from swift3.utils import LOGGER


ARN_S3_PREFIX = "arn:aws:s3:::"

# Match every bucket or object
ARN_WILDCARD_EVERYTHING = "arn:aws:s3:::*"
# Match every object (but not buckets)
ARN_WILDCARD_OBJECTS = "arn:aws:s3:::*/*"

ACTION_WILDCARD = "s3:*"
EXPLICIT_ALLOW = "ALLOW"
EXPLICIT_DENY = "DENY"
RESOURCE_VERSION = "2012-10-17"

# Rule effect: allow
RE_ALLOW = "Allow"
# Rule effect: deny
RE_DENY = "Deny"

# Resource type: object
RT_OBJECT = "Object"
# Resource type: bucket
RT_BUCKET = "Bucket"

SUPPORTED_ACTIONS = {
    "s3:AbortMultipartUpload": RT_OBJECT,
    "s3:CreateBucket": RT_BUCKET,
    "s3:DeleteBucket": RT_BUCKET,
    "s3:DeleteObject": RT_OBJECT,
    "s3:ListBucket": RT_BUCKET,
    "s3:ListMultipartUploadParts": RT_OBJECT,
    "s3:ListBucketMultipartUploads": RT_BUCKET,
    "s3:PutObject": RT_OBJECT,
    "s3:GetObject": RT_OBJECT
}

IAM_RULES_CALLBACK = 'swift.callback.fetch_iam_rules'


class IamResource(object):
    """
    Represents a resource in the sense intended in the IAM specification.
    """

    def __init__(self, name):
        if name.startswith(ARN_S3_PREFIX):
            self._resource_name = name
        else:
            self._resource_name = ARN_S3_PREFIX + name

    @property
    def arn(self):
        return self._resource_name

    def is_bucket(self):
        return '/' not in self._resource_name

    def is_object(self):
        return '/' in self._resource_name

    @property
    def type(self):
        return RT_BUCKET if self.is_bucket() else RT_OBJECT


class IamRulesMatcher(object):
    """
    Matches an action and a resource against a set of IAM rules.

    Only S3 actions are supported at the moment.
    """

    def __init__(self, rules, logger=None):
        self._rules = rules
        self.logger = logger or LOGGER

    def __call__(self, resource, action):
        """
        Match the specified action and resource against the set of IAM rules.

        :param action: the S3 action to match.
        :type action: `str`
        :param resource: the resource to match.
        :type resource: `Resource`
        """
        if action not in SUPPORTED_ACTIONS:
            raise IAMException("Unsupported action: %s" % action)

        if resource.type != SUPPORTED_ACTIONS[action]:
            raise IAMException(
                "Action %s does not apply on %s resources" %
                (action, resource.type))

        # Start by matching explicit denies, because they take precedence
        # over explicit allows.
        matched, rule_name = self.match_explicit_deny(action, resource)
        if matched:
            return EXPLICIT_DENY, rule_name
        # Then match explicit allows.
        matched, rule_name = self.match_explicit_allow(action, resource)
        if matched:
            return EXPLICIT_ALLOW, rule_name
        # Nothing matched, the request will be denied :(
        return None, None

    def do_explicit_check(self, effect, action, req_res):
        """
        Lookup for an explicit deny or an explicit allow in the set of rules.

        :param effect: one of RE_ALLOW or RE_DENY
        :param req_res: the resource specified by the request
        :returns: a tuple with a boolean telling of the rule has been matched
            and the ID of the statement that matched.
        """
        for num, statement in enumerate(self._rules['Statement']):
            # Statement ID is optional
            sid = statement.get('Sid', 'statement-id-%d' % num)
            self.logger.info("===> Checking statement %s (%s)",
                             sid, statement['Effect'])
            if statement['Effect'] != effect:
                continue

            # Check Action
            if (ACTION_WILDCARD not in statement['Action'] and
                    action not in statement['Action']):
                self.logger.info('Skipping %s, action %s is not in the list',
                                 sid, action)
                continue

            for resource_str in statement['Resource']:
                rule_res = IamResource(resource_str)

                # check WildCard before everything else
                if rule_res.arn == ARN_WILDCARD_EVERYTHING:
                    self.logger.info('%s: matches everything', sid)
                    return True, sid

                if (req_res.type == RT_OBJECT and
                        rule_res.arn == ARN_WILDCARD_OBJECTS):
                    self.logger.info('%s: matches every object', sid)
                    return True, sid

                if rule_res.type != req_res.type:
                    self.logger.info('%s: skip, resource types do not match',
                                     sid)
                    continue

                if rule_res.arn == req_res.arn:
                    self.logger.info('%s: found exact match', sid)
                    return True, sid
                if rule_res.arn.endswith('*'):
                    root_path = rule_res.arn[:-1]
                    if req_res.arn.startswith(root_path):
                        self.logger.info('%s: found object match (wildcard)',
                                         sid)
                        return True, sid
        self.logger.info('No %s match found', effect)
        return False, None

    def match_explicit_deny(self, action, resource):
        return self.do_explicit_check(RE_DENY, action, resource)

    def match_explicit_allow(self, action, resource):
        return self.do_explicit_check(RE_ALLOW, action, resource)


def check_iam_access(action):
    """
    Check the specified action is allowed for the current user
    on the resource defined by the request.
    """

    def real_check_iam_access(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            req = args[1]

            # If there is no callback, IAM is disabled,
            # thus we let everything pass through.
            rules_cb = req.environ.get(IAM_RULES_CALLBACK)
            if rules_cb is None:
                return func(*args, **kwargs)

            # If there is no rule for this user,
            # don't let anything pass through.
            # FIXME(IAM): refine the callback parameters
            matcher = rules_cb(req)
            if not matcher:
                raise AccessDenied()

            # FIXME(IAM): a * must be used as object name,
            # not as wildcard in Resource below
            if req.object_name:
                rsc = IamResource(req.container_name + '/' + req.object_name)
            elif req.container_name:
                rsc = IamResource(req.container_name)
            else:
                rsc = None

            effect, _sid = matcher(rsc, action)
            # TODO(IAM): log sid, the ID of the rule statement which matched
            if effect != EXPLICIT_ALLOW:
                raise AccessDenied()

            return func(*args, **kwargs)
        return wrapper
    return real_check_iam_access


class StaticIamMiddleware(object):
    """
    Middleware loading IAM rules from a file.

    This middleware must be placed before swift3 in the pipeline.
    The file must contain a JSON object, with one IAM policy document
    per user ID.
    """

    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf)
        self.rules_file = conf.get('rules_file')
        if not self.rules_file:
            self.logger.info('No IAM rules files')
            self.rules = dict()
        else:
            import json
            self.logger.info('Loading IAM rules from %s',
                             self.rules_file)
            with open(self.rules_file, 'r') as rules_fd:
                self.rules = json.load(rules_fd)

    def rules_callback(self, s3req):
        rules = self.rules.get(s3req.user_id)
        if rules:
            self.logger.debug("Loading IAM rules for account=%s user_id=%s",
                              s3req.account, s3req.user_id)
            # TODO(IAM): save IamRulesMatcher instances in a cache
            # or build them all in __init__.
            matcher = IamRulesMatcher(rules, logger=self.logger)
            return matcher
        else:
            self.logger.debug("No IAM rule for account=%s user_id=%s",
                              s3req.account, s3req.user_id)
            return None

    def __call__(self, env, start_response):
        env[IAM_RULES_CALLBACK] = self.rules_callback
        return self.app(env, start_response)


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    def factory(app):
        return StaticIamMiddleware(app, conf)
    return factory
