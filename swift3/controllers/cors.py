# Copyright (c) 2018 OpenStack Foundation.
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

import sys

from swift.common.utils import public

from swift3.controllers.base import Controller, bucket_operation
from swift3.etree import fromstring, DocumentInvalid, XMLSyntaxError
from swift3.response import HTTPOk, MalformedXML, NoSuchCORSConfiguration
from swift3.utils import LOGGER, sysmeta_header

MAX_CORS_BODY_SIZE = 10240

BUCKET_CORS_HEADER = sysmeta_header('bucket', 'cors')


def get_cors(app, req, method, origin):
    resp = req._get_response(app, 'HEAD',
                             req.container_name, "")
    body = resp.sysmeta_headers.get(BUCKET_CORS_HEADER)
    if not body:
        return None
    data = fromstring(body, "CorsConfiguration")

    # we have to iterate over each to find matching origin
    # whe have to manage wildcard in domain
    rules = data.findall('CORSRule')
    for rule in rules:
        item = rule.find('AllowedOrigin')
        if item.text == origin or item.text == '*':
            # check AllowedMethod
            methods = rule.findall('AllowedMethod')
            for m in methods:
                if m.text == method:
                    hdrs = req.headers.get('Access-Control-Request-Headers')
                    if hdrs:
                        allowed = [x.text.lower()
                                   for x in rule.findall('AllowedHeader')]

                        # manage * as well for headers
                        hdrs = [x.lower().strip() for x in hdrs.split(',')]
                        if '*' not in allowed \
                                and not all([hdr in allowed for hdr in hdrs]):
                            # some requested headers are not found
                            continue
                    return rule
    return None


def cors_fill_headers(req, resp, rule):
    def set_header_if_item(hdr, tag):
        x = rule.find(tag)
        if x is not None:
            resp.headers[hdr] = x.text

    def set_header_if_items(hdr, tag):
        vals = [m.text for m in rule.findall(tag)]
        if len(vals):
            resp.headers[hdr] = ', '.join(vals)

    set_header_if_item('Access-Control-Allow-Origin', 'AllowedOrigin')
    set_header_if_item('Access-Control-Max-Age', 'MaxAgeSeconds')
    set_header_if_items('Access-Control-Allow-Methods', 'AllowedMethod')
    set_header_if_items('Access-Control-Expose-Headers', 'ExposeHeader')
    set_header_if_items('Access-Control-', 'AllowedHeaders')
    resp.headers['Access-Control-Allow-Credentials'] = 'true'

    return resp


class CorsController(Controller):
    """
    Handles the following APIs:

     - GET Bucket CORS
     - PUT Bucket CORS
     - DELETE Bucket CORS

    """
    @public
    @bucket_operation
    def GET(self, req):  # pylint: disable=invalid-name
        """
        Handles GET Bucket CORS.
        """
        resp = req._get_response(self.app, 'HEAD',
                                 req.container_name, None)
        body = resp.sysmeta_headers.get(BUCKET_CORS_HEADER)
        if not body:
            raise NoSuchCORSConfiguration
        return HTTPOk(body=body, content_type='application/xml')

    @public
    @bucket_operation
    def PUT(self, req):  # pylint: disable=invalid-name
        """
        Handles PUT Bucket CORs.
        """
        xml = req.xml(MAX_CORS_BODY_SIZE)
        try:
            fromstring(xml, "CorsConfiguration")
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            LOGGER.error(e)
            raise exc_type, exc_value, exc_traceback

        req.headers[BUCKET_CORS_HEADER] = xml
        resp = req._get_response(self.app, 'POST',
                                 req.container_name, None)
        return resp

    @public
    @bucket_operation
    def DELETE(self, req):  # pylint: disable=invalid-name
        """
        Handles DELETE Bucket CORs.
        """
        req.headers[BUCKET_CORS_HEADER] = ''
        return req._get_response(self.app, 'POST',
                                 req.container_name, None)
