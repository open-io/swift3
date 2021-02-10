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

from fnmatch import fnmatchcase
from functools import wraps

from swift.common.utils import config_auto_int_value, get_logger, LRUCache

from swift3.exception import IAMException
from swift3.response import AccessDenied
from swift3.utils import LOGGER


ARN_AWS_PREFIX = "arn:aws:"
ARN_S3_PREFIX = ARN_AWS_PREFIX + "s3:::"

# Match every bucket
ARN_WILDCARD_BUCKET = ARN_S3_PREFIX + "*"

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
    "s3:GetBucketLocation": RT_BUCKET,
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
        if name.startswith(ARN_AWS_PREFIX):
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


def string_equals(actual, expected):
    """
    Check if `actual` is equal to one of the strings in the `expected` list.

    :type expected: list
    :type actual: str
    :rtype: bool
    :returns: True if actual is in the list of expected strings
    """
    return actual in expected


def string_like(actual, expected):
    """
    Try to match `actual` to one of the patterns in `expected`.

    :returns: True if `actual` matches one of the patterns in `expected`
    """
    if actual is None:
        return False
    for pattern in expected:
        if fnmatchcase(actual, pattern):
            return True
    return False


# See iam-ug.pdf document, page 569.
IamConditionOp = {
    "StringEquals": string_equals,
    "StringNotEquals": lambda a, e: not string_equals(a, e),
    "StringLike": string_like,
    "StringNotLike": lambda a, e: not string_like(a, e),
    # TODO(IAM): implement the following functions
    "IpAddress": None,
    "NotIpAddress": None,
    "StringEqualsIgnoreCase": None,
    "StringNotEqualsIgnoreCase": None,
}


# See iam-ug.pdf document, page 629.
IamConditionKey = {
    "s3:delimiter": lambda req: req.params.get('delimiter'),
    "s3:max-keys": lambda req: req.params.get('max-keys'),
    "s3:prefix": lambda req: req.params.get('prefix'),
    # TODO(IAM): implement the following keys
    "aws:CurrentTime": None,
    "aws:EpochTime": None,
    "aws:SourceIp": None,
    "aws:UserAgent": None,
    "aws:userid": None,
    "s3:VersionId": None,
    "s3:x-amz-acl": None,
    "s3:x-amz-copy-source": None,
    "s3:x-amz-metadata-directive": None,
    # referer (bucket policy)
    # custom header with specific value
}


# TODO(IAM): merge this class into StaticIamMiddleware
# so we can make subrequests to load resource-based policies.
class IamRulesMatcher(object):
    """
    Matches an action and a resource against a set of IAM rules.

    Only S3 actions are supported at the moment.
    """

    def __init__(self, rules, logger=None):
        self._rules = rules
        self.logger = logger or LOGGER

    def __call__(self, resource, action, req=None):
        """
        Match the specified action and resource against the set of IAM rules.

        :param action: the S3 action to match.
        :type action: `str`
        :param resource: the resource to match.
        :type resource: `Resource`
        :param req: the S3 request object
        """
        if action not in SUPPORTED_ACTIONS:
            raise IAMException("Unsupported action: %s" % action)

        if resource.type != SUPPORTED_ACTIONS[action]:
            raise IAMException(
                "Action %s does not apply on %s resources" %
                (action, resource.type))

        # Start by matching explicit denies, because they take precedence
        # over explicit allows.
        matched, rule_name = self.match_explicit_deny(action, resource, req)
        if matched:
            return EXPLICIT_DENY, rule_name
        # Then match explicit allows.
        matched, rule_name = self.match_explicit_allow(action, resource, req)
        if matched:
            return EXPLICIT_ALLOW, rule_name
        # Nothing matched, the request will be denied :(
        return None, None

    def resolve_cond_key(self, key, req):
        """
        Load the condition value from the request or environment.
        See iam-ug.pdf document, page 1401.
        """
        return IamConditionKey[key](req)

    def check_condition(self, statement, req):
        """
        Check the conditions from the statement are satisfied.

        To be consistent with the "default deny" rule, for unverifiable
        conditions, deny the request.

        :param statement: the statement dict using the condition
        :param req: the current request
        """
        cond = statement.get('Condition', {})
        effect = statement['Effect']
        for opname, operands in cond.items():
            if IamConditionOp.get(opname, None) is None:
                if effect == RE_ALLOW:
                    self.logger.info(
                        "IAM: condition operator %s not implemented. Since "
                        "it is used in an 'allow' statement, consider the "
                        "condition is not satisfied.", opname)
                    return False
                else:
                    self.logger.info(
                        "IAM: condition operator %s not implemented. Since "
                        "it is used in a 'deny' statement, consider the "
                        "condition is satisfied.", opname)
                    continue
            operator = IamConditionOp[opname]
            for cond_key, values in operands.items():
                if IamConditionKey.get(cond_key, None) is None:
                    if effect == RE_ALLOW:
                        self.logger.info(
                            "IAM: condition %s not implemented. Since it is "
                            "in an 'allow' statement, consider it is not "
                            "satisfied.", cond_key)
                        return False
                    else:
                        self.logger.info(
                            "IAM: condition %s not implemented. Since it is "
                            "in a 'deny' statement, consider it is satisfied.",
                            cond_key)
                        continue
                cond_val = self.resolve_cond_key(cond_key, req)
                if not operator(cond_val, values):
                    # One of the conditions is not satisfied
                    return False
        # All conditions are satisfied
        return True

    def do_explicit_check(self, effect, action, req_res, req):
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
            self.logger.debug("===> Checking statement %s (%s)",
                              sid, statement['Effect'])
            if statement['Effect'] != effect:
                continue

            # Check Action
            for rule_action in statement['Action']:
                if rule_action == action:
                    # Found an exact match
                    break
                elif rule_action.endswith('*'):
                    action_prefix = rule_action[:-1]
                    if action.startswith(action_prefix):
                        # Found a wildcard match
                        break
            else:
                self.logger.debug('Skipping %s, action %s is not in the list',
                                  sid, action)
                continue

            for resource_str in statement['Resource']:
                rule_res = IamResource(resource_str)

                # check wildcards before everything else
                if (rule_res.arn == ARN_WILDCARD_BUCKET and
                        self.check_condition(statement, req)):
                    self.logger.debug('%s: matches everything', sid)
                    return True, sid

                # Ensure the requested and the current resource are of the
                # same type. The specification says that a wildcard in the
                # bucket name should not match objects (stop at first slash).
                if rule_res.type != req_res.type:
                    self.logger.debug('%s: skip, resource types do not match',
                                      sid)
                    continue

                # Do a case-sensitive match between the requested resource
                # and the resource of the current rule.
                if (fnmatchcase(req_res.arn, rule_res.arn) and
                        self.check_condition(statement, req)):
                    self.logger.debug('%s: wildcard or exact match', sid)
                    return True, sid

        self.logger.debug('No %s match found', effect)
        return False, None

    def match_explicit_deny(self, action, resource, req):
        return self.do_explicit_check(RE_DENY, action, resource, req)

    def match_explicit_allow(self, action, resource, req):
        return self.do_explicit_check(RE_ALLOW, action, resource, req)


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

            effect, sid = matcher(rsc, action, req)
            if effect != EXPLICIT_ALLOW:
                matcher.logger.info("Request denied by IAM (sid=%s)", sid)
                raise AccessDenied()

            return func(*args, **kwargs)
        return wrapper
    return real_check_iam_access


class IamMiddleware(object):
    """
    Base class for IAM implementations.

    Subclasses must implement load_rules_for_user.
    """

    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf)
        self.connection = conf.get('connection')
        maxsize = config_auto_int_value(conf.get('cache_size'), 1000)
        maxtime = config_auto_int_value(conf.get('cache_ttl'), 30)
        self._load_rules_matcher = LRUCache(maxsize=maxsize, maxtime=maxtime)(
            self._build_rules_matcher)

    def __call__(self, env, start_response):
        # Put the rules callback in the request environment so middlewares
        # further in the pipeline can call it when needed.
        env[IAM_RULES_CALLBACK] = self.rules_callback
        return self.app(env, start_response)

    def load_rules_for_user(self, account, user_id):
        """
        Load rules for the authenticated user who did the request:
        - from its own user policy,
        - from its optional group policy,
        - from its role policy.

        Subclasses must implement this method.

        :rtype: dict
        :returns: a dictionary with at least a 'Statement' key, containing
            a list of IAM statements.
        """
        raise NotImplementedError

    def _build_rules_matcher(self, account, user_id):
        """
        Load IAM rules for the specified user, then build an IamRulesMatcher
        instance.
        """
        rules = self.load_rules_for_user(account, user_id)
        if rules:
            self.logger.debug("Loading IAM rules for account=%s user_id=%s",
                              account, user_id)
            matcher = IamRulesMatcher(rules, logger=self.logger)
            return matcher
        else:
            self.logger.debug("No IAM rule for account=%s user_id=%s",
                              account, user_id)
            return None

    def rules_callback(self, s3req):
        matcher = self._load_rules_matcher(s3req.account, s3req.user_id)
        return matcher


class StaticIamMiddleware(IamMiddleware):
    """
    Middleware loading IAM rules from a file.

    This middleware must be placed before swift3 in the pipeline.
    The file must contain a JSON object, with one IAM policy document
    per user ID.
    """

    def __init__(self, app, conf):
        super(StaticIamMiddleware, self).__init__(app, conf)
        if not self.connection:
            self.logger.info('No IAM rules file')
            self.rules = dict()
        else:
            import json
            from urlparse import urlparse
            parsed = urlparse(self.connection)
            if parsed.scheme and parsed.scheme != 'file':
                raise ValueError("IAM: 'connection' must point to a JSON file")
            self.logger.info('Loading IAM rules from %s', parsed.path)
            with open(parsed.path, 'r') as rules_fd:
                self.rules = json.load(rules_fd)

    def load_rules_for_user(self, account, user_id):
        rules = self.rules.get(user_id)
        return rules


def filter_factory(global_conf, **local_config):
    conf = global_conf.copy()
    conf.update(local_config)

    def factory(app):
        return StaticIamMiddleware(app, conf)
    return factory
