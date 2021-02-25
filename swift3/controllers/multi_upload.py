# Copyright (c) 2010-2014,2018 OpenStack Foundation.
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

"""
Implementation of S3 Multipart Upload.

This module implements S3 Multipart Upload APIs with the Swift SLO feature.
The following explains how swift3 uses swift container and objects to store S3
upload information:

 - [bucket]+segments

   A container to store upload information.  [bucket] is the original bucket
   where multipart upload is initiated.

 - [bucket]+segments/[upload_id]

   A object of the ongoing upload id.  The object is empty and used for
   checking the target upload status.  If the object exists, it means that the
   upload is initiated but not either completed or aborted.


 - [bucket]+segments/[upload_id]/1
   [bucket]+segments/[upload_id]/2
   [bucket]+segments/[upload_id]/3
     .
     .

   Uploaded part objects.  Those objects are directly used as segments of Swift
   Static Large Object.
"""

import binascii
import os
import re

from hashlib import md5

from swift.common.request_helpers import update_etag_is_at_header
from swift.common.swob import Range
from swift.common.utils import json, public, close_if_possible, list_from_csv
from swift.common.db import utf8encode

from six.moves.urllib.parse import urlparse  # pylint: disable=F0401

from swift3.controllers.base import Controller, bucket_operation, \
    object_operation, check_container_existence
from swift3.iam import check_iam_access
from swift3.response import InvalidArgument, ErrorResponse, MalformedXML, \
    InvalidPart, EntityTooSmall, InvalidPartOrder, \
    InvalidRequest, HTTPOk, HTTPNoContent, NoSuchKey, NoSuchUpload, \
    NoSuchBucket, InvalidRange, BadDigest
from swift3.utils import LOGGER, unique_id, MULTIUPLOAD_SUFFIX, S3Timestamp, \
    log_s3api_command, sysmeta_header
from swift3.etree import Element, SubElement, fromstring, tostring, \
    XMLSyntaxError, DocumentInvalid
from swift3.controllers.tagging import OBJECT_TAGGING_HEADER, \
    HTTP_HEADER_TAGGING_KEY, convert_urlquery_to_xml
from swift3.cfg import CONF

DEFAULT_MAX_PARTS_LISTING = 1000
DEFAULT_MAX_UPLOADS = 1000

MAX_COMPLETE_UPLOAD_BODY_SIZE = 2048 * 1024


def _get_upload_info(req, app, upload_id):
    container = req.container_name + MULTIUPLOAD_SUFFIX
    obj = '%s/%s' % (req.object_name, upload_id)
    req.environ['oio.ephemeral_object'] = True
    try:
        res = req.get_response(app, 'HEAD', container=container, obj=obj)
        return res
    except NoSuchKey:
        raise NoSuchUpload(upload_id=upload_id)
    finally:
        req.environ['oio.ephemeral_object'] = False


def _check_upload_info(req, app, upload_id):

    _get_upload_info(req, app, upload_id)


class PartController(Controller):
    """
    Handles the following APIs:

     - Upload Part
     - Upload Part - Copy

    Those APIs are logged as PART operations in the S3 server log.
    """

    def parse_part_number(self, req):
        """
        Parse the part number from query string.
        Raise InvalidArgument if missing or invalid.
        """
        try:
            part_number = int(req.params['partNumber'])
            if part_number < 1 or CONF.max_upload_part_num < part_number:
                raise Exception()
        except Exception:
            err_msg = 'Part number must be an integer between 1 and %d,' \
                      ' inclusive' % CONF.max_upload_part_num
            raise InvalidArgument('partNumber', req.params['partNumber'],
                                  err_msg)
        return part_number

    @public
    @object_operation
    @check_container_existence
    @check_iam_access('s3:PutObject')
    def PUT(self, req):
        """
        Handles Upload Part and Upload Part Copy.
        """

        if 'uploadId' not in req.params:
            raise InvalidArgument('ResourceType', 'partNumber',
                                  'Unexpected query string parameter')

        part_number = self.parse_part_number(req)

        upload_id = req.params['uploadId']
        _check_upload_info(req, self.app, upload_id)

        req.container_name += MULTIUPLOAD_SUFFIX
        req.object_name = '%s/%s/%d' % (req.object_name, upload_id,
                                        part_number)

        req_timestamp = S3Timestamp.now()
        req.headers['X-Timestamp'] = req_timestamp.internal
        source_resp = req.check_copy_source(self.app)
        method = 'upload-part'
        if 'X-Amz-Copy-Source' in req.headers and \
                'X-Amz-Copy-Source-Range' in req.headers:
            rng = req.headers['X-Amz-Copy-Source-Range']
            method = 'upload-part-copy'
            header_valid = True
            try:
                rng_obj = Range(rng)
                if len(rng_obj.ranges) != 1:
                    header_valid = False
            except ValueError:
                header_valid = False
            if not header_valid:
                err_msg = ('The x-amz-copy-source-range value must be of the '
                           'form bytes=first-last where first and last are '
                           'the zero-based offsets of the first and last '
                           'bytes to copy')
                raise InvalidArgument('x-amz-source-range', rng, err_msg)

            source_size = int(source_resp.headers['Content-Length'])
            if not rng_obj.ranges_for_length(source_size):
                err_msg = ('Range specified is not valid for source object '
                           'of size: %s' % source_size)
                raise InvalidArgument('x-amz-source-range', rng, err_msg)

            req.headers['Range'] = rng
            del req.headers['X-Amz-Copy-Source-Range']
        if 'X-Amz-Copy-Source' in req.headers:
            # Clear some problematic headers that might be on the source
            req.headers.update({
                sysmeta_header('object', 'etag'): '',
                'X-Object-Sysmeta-Swift3-Etag': '',  # for legacy data
                'X-Object-Sysmeta-Slo-Etag': '',
                'X-Object-Sysmeta-Slo-Size': '',
                'X-Object-Sysmeta-Container-Update-Override-Etag': '',
            })
        log_s3api_command(req, method)
        resp = req.get_response(self.app)

        if 'X-Amz-Copy-Source' in req.headers:
            resp.append_copy_resp_body(req.controller_name,
                                       req_timestamp.s3xmlformat)

        resp.status = 200
        return resp

    @public
    @object_operation
    @check_container_existence
    def GET(self, req):
        """
        Handles Get Part (regular Get but with ?part-number=N).
        """
        log_s3api_command(req, 'get-object-part')
        return self.GETorHEAD(req)

    @public
    @object_operation
    @check_container_existence
    def HEAD(self, req):
        """
        Handles Head Part (regular HEAD but with ?part-number=N).
        """
        log_s3api_command(req, 'head-object-part')
        return self.GETorHEAD(req)

    def GETorHEAD(self, req):
        """
        Handled GET or HEAD request on a part of a multipart object.
        """
        part_number = self.parse_part_number(req)

        had_match = False
        for match_header in ('if-match', 'if-none-match'):
            if match_header not in req.headers:
                continue
            had_match = True
            for value in list_from_csv(req.headers[match_header]):
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                if value.endswith('-N'):
                    # Deal with fake S3-like etags for SLOs uploaded via Swift
                    req.headers[match_header] += ', ' + value[:-2]

        if had_match:
            # Update where to look
            update_etag_is_at_header(req, sysmeta_header('object', 'etag'))

        # Get the list of parts. Must be raw to get all response headers.
        slo_resp = req.get_response(
            self.app, 'GET', req.container_name, req.object_name,
            query={'multipart-manifest': 'get', 'format': 'raw'})

        # Check if the object is really a SLO. If not, and user asked
        # for the first part, do a regular request.
        if 'X-Static-Large-Object' not in slo_resp.sw_headers:
            if part_number == 1:
                if slo_resp.is_success and req.method == 'HEAD':
                    # Clear body
                    slo_resp.body = ''
                return slo_resp
            else:
                close_if_possible(slo_resp.app_iter)
                raise InvalidRange()

        # Locate the part
        slo = json.loads(slo_resp.body)
        try:
            part = slo[part_number - 1]
        except IndexError:
            raise InvalidRange()

        # Redirect the request on the part
        _, req.container_name, req.object_name = part['path'].split('/', 2)
        # XXX enforce container_name and object_name to be <str>
        # or it will rise issues in swift3/requests when merging both
        req.container_name = req.container_name.encode('utf-8')
        req.object_name = req.object_name.encode('utf8')
        # The etag check was performed with the manifest
        if had_match:
            for match_header in ('if-match', 'if-none-match'):
                req.headers.pop(match_header, None)
        resp = req.get_response(self.app)

        # Replace status
        slo_resp.status = resp.status
        # Replace body
        slo_resp.app_iter = resp.app_iter
        # Update with the size of the part
        slo_resp.headers['Content-Length'] = \
            resp.headers.get('Content-Length', 0)
        slo_resp.sw_headers['Content-Length'] = \
            slo_resp.headers['Content-Length']
        # Add the number of parts in this object
        slo_resp.headers['X-Amz-Mp-Parts-Count'] = len(slo)
        return slo_resp


class UploadsController(Controller):
    """
    Handles the following APIs:

     - List Multipart Uploads
     - Initiate Multipart Upload

    Those APIs are logged as UPLOADS operations in the S3 server log.
    """
    @public
    @bucket_operation(err_resp=InvalidRequest,
                      err_msg="Key is not expected for the GET method "
                              "?uploads subresource")
    @check_container_existence
    @check_iam_access('s3:ListBucketMultipartUploads')
    def GET(self, req):
        """
        Handles List Multipart Uploads
        """

        log_s3api_command(req, 'list-multipart-uploads')

        def separate_uploads(uploads, prefix, delimiter):
            """
            separate_uploads will separate uploads into non_delimited_uploads
            (a subset of uploads) and common_prefixes according to the
            specified delimiter. non_delimited_uploads is a list of uploads
            which exclude the delimiter. common_prefixes is a set of prefixes
            prior to the specified delimiter. Note that the prefix in the
            common_prefixes includes the delimiter itself.

            i.e. if '/' delimiter specified and then the uploads is consists of
            ['foo', 'foo/bar'], this function will return (['foo'], ['foo/']).

            :param uploads: A list of uploads dictionary
            :param prefix: A string of prefix reserved on the upload path.
                           (i.e. the delimiter must be searched behind the
                            prefix)
            :param delimiter: A string of delimiter to split the path in each
                              upload

            :return (non_delimited_uploads, common_prefixes)
            """
            (prefix, delimiter) = \
                utf8encode(prefix, delimiter)
            non_delimited_uploads = []
            common_prefixes = set()
            for upload in uploads:
                key = upload['key']
                end = key.find(delimiter, len(prefix))
                if end >= 0:
                    common_prefix = key[:end + len(delimiter)]
                    common_prefixes.add(common_prefix)
                else:
                    non_delimited_uploads.append(upload)
            return non_delimited_uploads, sorted(common_prefixes)

        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        keymarker = req.params.get('key-marker', '')
        uploadid = req.params.get('upload-id-marker', '')
        maxuploads = req.get_validated_param(
            'max-uploads', DEFAULT_MAX_UPLOADS, DEFAULT_MAX_UPLOADS)

        query = {
            'format': 'json',
            'limit': maxuploads + 1,
        }

        if uploadid and keymarker:
            query.update({'marker': '%s/%s' % (keymarker, uploadid)})
        elif keymarker:
            query.update({'marker': '%s/~' % (keymarker)})
        if 'prefix' in req.params:
            query.update({'prefix': req.params['prefix']})

        container = req.container_name + MULTIUPLOAD_SUFFIX
        try:
            req.environ['oio.list_mpu'] = True
            resp = req.get_response(self.app, container=container, query=query)
            objects = json.loads(resp.body)
        except NoSuchBucket:
            # Assume NoSuchBucket as no uploads
            objects = []

        def object_to_upload(object_info):
            obj, upid = object_info['name'].rsplit('/', 1)
            obj_dict = {'key': obj,
                        'upload_id': upid,
                        'last_modified': object_info['last_modified']}
            return obj_dict

        # uploads is a list consists of dict, {key, upload_id, last_modified}
        # Note that pattern matcher will drop whole segments objects like as
        # object_name/upload_id/1.
        pattern = re.compile('/[0-9]+$')
        uploads = [object_to_upload(obj) for obj in objects if
                   pattern.search(obj.get('name', '')) is None]

        prefixes = []
        if 'delimiter' in req.params:
            prefix = req.params.get('prefix', '')
            delimiter = req.params['delimiter']
            uploads, prefixes = \
                separate_uploads(uploads, prefix, delimiter)

        if len(uploads) > maxuploads:
            uploads = uploads[:maxuploads]
            truncated = True
        else:
            truncated = False

        nextkeymarker = ''
        nextuploadmarker = ''
        if len(uploads) > 1:
            nextuploadmarker = uploads[-1]['upload_id']
            nextkeymarker = uploads[-1]['key']

        result_elem = Element('ListMultipartUploadsResult')
        if encoding_type is not None:
            result_elem.encoding_type = encoding_type
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'KeyMarker').text = keymarker
        SubElement(result_elem, 'UploadIdMarker').text = uploadid
        SubElement(result_elem, 'NextKeyMarker').text = nextkeymarker
        SubElement(result_elem, 'NextUploadIdMarker').text = nextuploadmarker
        if 'delimiter' in req.params:
            SubElement(result_elem, 'Delimiter').text = \
                req.params['delimiter']
        if 'prefix' in req.params:
            SubElement(result_elem, 'Prefix').text = req.params['prefix']
        SubElement(result_elem, 'MaxUploads').text = str(maxuploads)
        if encoding_type is not None:
            SubElement(result_elem, 'EncodingType').text = encoding_type
        SubElement(result_elem, 'IsTruncated').text = \
            'true' if truncated else 'false'

        # TODO: don't show uploads which are initiated before this bucket is
        # created.
        for u in uploads:
            upload_elem = SubElement(result_elem, 'Upload')
            SubElement(upload_elem, 'Key').text = u['key']
            SubElement(upload_elem, 'UploadId').text = u['upload_id']
            initiator_elem = SubElement(upload_elem, 'Initiator')
            SubElement(initiator_elem, 'ID').text = req.user_id
            SubElement(initiator_elem, 'DisplayName').text = req.user_id
            owner_elem = SubElement(upload_elem, 'Owner')
            SubElement(owner_elem, 'ID').text = req.user_id
            SubElement(owner_elem, 'DisplayName').text = req.user_id
            SubElement(upload_elem, 'StorageClass').text = 'STANDARD'
            SubElement(upload_elem, 'Initiated').text = \
                u['last_modified'][:-3] + 'Z'

        for p in prefixes:
            elem = SubElement(result_elem, 'CommonPrefixes')
            SubElement(elem, 'Prefix').text = p

        body = tostring(result_elem, encoding_type=encoding_type)

        return HTTPOk(body=body, content_type='application/xml')

    @public
    @object_operation
    @check_container_existence
    @check_iam_access('s3:PutObject')
    def POST(self, req):
        """
        Handles Initiate Multipart Upload.
        """

        log_s3api_command(req, 'create-multipart-upload')
        # Create a unique S3 upload id from UUID to avoid duplicates.
        upload_id = unique_id()

        container = req.container_name + MULTIUPLOAD_SUFFIX

        obj = '%s/%s' % (req.object_name, upload_id)

        if HTTP_HEADER_TAGGING_KEY in req.headers:
            tagging = convert_urlquery_to_xml(
                req.headers.get(HTTP_HEADER_TAGGING_KEY))
            req.headers[OBJECT_TAGGING_HEADER] = tagging

        req.headers.pop('Etag', None)
        req.headers.pop('Content-Md5', None)
        req.environ['oio.ephemeral_object'] = True

        req.get_response(self.app, 'PUT', container, obj, body='')

        result_elem = Element('InitiateMultipartUploadResult')
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = req.object_name
        SubElement(result_elem, 'UploadId').text = upload_id

        body = tostring(result_elem)

        return HTTPOk(body=body, content_type='application/xml')


class UploadController(Controller):
    """
    Handles the following APIs:

     - List Parts
     - Abort Multipart Upload
     - Complete Multipart Upload

    Those APIs are logged as UPLOAD operations in the S3 server log.
    """
    @public
    @object_operation
    @check_container_existence
    @check_iam_access('s3:ListMultipartUploadParts')
    def GET(self, req):
        """
        Handles List Parts.
        """
        log_s3api_command(req, 'list-parts')

        def filter_part_num_marker(o):
            try:
                num = int(os.path.basename(o['name']))
                return num > part_num_marker
            except ValueError:
                return False

        encoding_type = req.params.get('encoding-type')
        if encoding_type is not None and encoding_type != 'url':
            err_msg = 'Invalid Encoding Method specified in Request'
            raise InvalidArgument('encoding-type', encoding_type, err_msg)

        upload_id = req.params['uploadId']
        _check_upload_info(req, self.app, upload_id)

        maxparts = req.get_validated_param(
            'max-parts', DEFAULT_MAX_PARTS_LISTING, CONF.max_parts_listing)
        part_num_marker = req.get_validated_param(
            'part-number-marker', 0)

        query = {
            'format': 'json',
            'limit': maxparts + 1,
            'prefix': '%s/%s/' % (req.object_name, upload_id),
            'delimiter': '/'
        }

        container = req.container_name + MULTIUPLOAD_SUFFIX
        resp = req.get_response(self.app, container=container, obj='',
                                query=query)
        objects = json.loads(resp.body)

        last_part = 0

        # If the caller requested a list starting at a specific part number,
        # construct a sub-set of the object list.
        objList = filter(filter_part_num_marker, objects)

        # pylint: disable-msg=E1103
        objList.sort(key=lambda o: int(o['name'].split('/')[-1]))

        if len(objList) > maxparts:
            objList = objList[:maxparts]
            truncated = True
        else:
            truncated = False
        # TODO: We have to retrieve object list again when truncated is True
        # and some objects filtered by invalid name because there could be no
        # enough objects for limit defined by maxparts.

        if objList:
            o = objList[-1]
            last_part = os.path.basename(o['name'])

        result_elem = Element('ListPartsResult')
        if encoding_type is not None:
            result_elem.encoding_type = encoding_type
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = req.object_name
        SubElement(result_elem, 'UploadId').text = upload_id

        initiator_elem = SubElement(result_elem, 'Initiator')
        SubElement(initiator_elem, 'ID').text = req.user_id
        SubElement(initiator_elem, 'DisplayName').text = req.user_id
        owner_elem = SubElement(result_elem, 'Owner')
        SubElement(owner_elem, 'ID').text = req.user_id
        SubElement(owner_elem, 'DisplayName').text = req.user_id

        SubElement(result_elem, 'StorageClass').text = 'STANDARD'
        SubElement(result_elem, 'PartNumberMarker').text = str(part_num_marker)
        SubElement(result_elem, 'NextPartNumberMarker').text = str(last_part)
        SubElement(result_elem, 'MaxParts').text = str(maxparts)
        if 'encoding-type' in req.params:
            SubElement(result_elem, 'EncodingType').text = \
                req.params['encoding-type']
        SubElement(result_elem, 'IsTruncated').text = \
            'true' if truncated else 'false'

        for i in objList:
            part_elem = SubElement(result_elem, 'Part')
            SubElement(part_elem, 'PartNumber').text = i['name'].split('/')[-1]
            SubElement(part_elem, 'LastModified').text = \
                i['last_modified'][:-3] + 'Z'
            SubElement(part_elem, 'ETag').text = '"%s"' % i['hash']
            SubElement(part_elem, 'Size').text = str(i['bytes'])

        body = tostring(result_elem, encoding_type=encoding_type)

        return HTTPOk(body=body, content_type='application/xml')

    @public
    @object_operation
    @check_container_existence
    @check_iam_access('s3:AbortMultipartUpload')
    def DELETE(self, req):
        """
        Handles Abort Multipart Upload.
        """
        log_s3api_command(req, 'abort-multipart-upload')
        upload_id = req.params['uploadId']
        _check_upload_info(req, self.app, upload_id)

        container = req.container_name + MULTIUPLOAD_SUFFIX
        # First check to see if this multi-part upload was already
        # completed.  Look in the primary container, if the object exists,
        # then it was completed and we return an error here.
        obj = '%s/%s' % (req.object_name, upload_id)
        req.environ['oio.ephemeral_object'] = True
        try:
            req.get_response(self.app, container=container, obj=obj)
        finally:
            req.environ['oio.ephemeral_object'] = False

        # The completed object was not found so this
        # must be a multipart upload abort.
        # We must delete any uploaded segments for this UploadID and then
        # delete the object in the main container as well
        query = {
            'format': 'json',
            'prefix': '%s/%s/' % (req.object_name, upload_id),
            'delimiter': '/',
        }

        # Force the master to be sure to fetch all uploaded parts
        req.environ.setdefault('oio.query', {})
        req.environ['oio.query']['force_master'] = True

        resp = req.get_response(self.app, 'GET', container, '', query=query)

        #  Iterate over the segment objects and delete them individually
        objects = json.loads(resp.body)
        for o in objects:
            container = req.container_name + MULTIUPLOAD_SUFFIX
            obj = o['name'].encode('utf-8')
            req.get_response(self.app, container=container, obj=obj)

        return HTTPNoContent()

    @public
    @object_operation
    @check_container_existence
    @check_iam_access('s3:PutObject')
    def POST(self, req):
        """
        Handles Complete Multipart Upload.
        """
        log_s3api_command(req, 'complete-multipart-upload')
        upload_id = req.params['uploadId']
        resp = _get_upload_info(req, self.app, upload_id)
        headers = {}
        for key, val in resp.headers.iteritems():
            _key = key.lower()
            if _key.startswith('x-amz-meta-'):
                headers['x-object-meta-' + _key[11:]] = val
            elif _key == 'content-type':
                headers['Content-Type'] = val
        for key, val in resp.sysmeta_headers.items():
            _key = key.lower()
            if _key == OBJECT_TAGGING_HEADER.lower():
                headers[key] = val

        # Query for the objects in the segments area to make sure it completed
        query = {
            'format': 'json',
            'prefix': '%s/%s/' % (req.object_name, upload_id),
            'delimiter': '/'
        }

        # Force the master to be sure to fetch all uploaded parts
        req.environ.setdefault('oio.query', {})
        req.environ['oio.query']['force_master'] = True

        container = req.container_name + MULTIUPLOAD_SUFFIX
        resp = req.get_response(self.app, 'GET', container, '', query=query)
        objinfo = json.loads(resp.body)

        # pylint: disable-msg=no-member
        objinfo.sort(key=lambda o: int(o['name'].split('/')[-1]))

        objtable = dict((o['name'].encode('utf-8'),
                         {'path': '/'.join(['', container, o['name']]),
                          'etag': o['hash'],
                          'size_bytes': o['bytes']}) for o in objinfo)

        s3_etag_hasher = md5()
        manifest = []
        previous_number = 0
        try:
            xml = req.xml(MAX_COMPLETE_UPLOAD_BODY_SIZE)
            if not xml:
                raise InvalidRequest(msg='You must specify at least one part')
            if 'content-md5' in req.headers:
                # If an MD5 was provided, we need to verify it.
                # Note that S3Request already took care of translating to ETag
                if req.headers['etag'] != md5(xml).hexdigest():
                    raise BadDigest(content_md5=req.headers['content-md5'])
                # We're only interested in the body here, in the
                # multipart-upload controller -- *don't* let it get
                # plumbed down to the object-server
                del req.headers['etag']

            complete_elem = fromstring(xml, 'CompleteMultipartUpload')
            for part_elem in complete_elem.iterchildren('Part'):
                part_number = int(part_elem.find('./PartNumber').text)

                if part_number <= previous_number:
                    raise InvalidPartOrder(upload_id=upload_id)
                previous_number = part_number

                etag = part_elem.find('./ETag').text
                if len(etag) >= 2 and etag[0] == '"' and etag[-1] == '"':
                    # strip double quotes
                    etag = etag[1:-1]

                info = objtable.get("%s/%s/%s" % (req.object_name, upload_id,
                                                  part_number))
                if info is None or info['etag'] != etag:
                    raise InvalidPart(upload_id=upload_id,
                                      part_number=part_number)

                s3_etag_hasher.update(binascii.a2b_hex(etag))
                info['size_bytes'] = int(info['size_bytes'])
                manifest.append(info)
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except ErrorResponse:
            raise
        except Exception as e:
            LOGGER.error(e)
            raise

        s3_etag = '%s-%d' % (s3_etag_hasher.hexdigest(), len(manifest))
        headers[sysmeta_header('object', 'etag')] = s3_etag
        # Leave base header value blank; SLO will populate
        c_etag = '; s3_etag=%s' % s3_etag
        headers['X-Object-Sysmeta-Container-Update-Override-Etag'] = c_etag

        # Following swift commit 7f636a5, zero-byte segments aren't allowed,
        # even as the final segment
        empty_seg = None
        if manifest[-1]['size_bytes'] == 0:
            empty_seg = manifest.pop()

            # We'll check the sizes of all except the last segment below, but
            # since we just popped off a zero-byte segment, we should check
            # that last segment, too.
            if manifest and manifest[-1]['size_bytes'] < CONF.min_segment_size:
                raise EntityTooSmall()

        # Check the size of each segment except the last and make sure they are
        # all more than the minimum upload chunk size
        for info in manifest[:-1]:
            if info['size_bytes'] < CONF.min_segment_size:
                raise EntityTooSmall()

        try:
            # TODO: add support for versioning
            if manifest:
                resp = req.get_response(self.app, 'PUT',
                                        body=json.dumps(manifest),
                                        query={'multipart-manifest': 'put'},
                                        headers=headers)
            else:
                # the upload must have consisted of a single zero-length part
                # just write it directly
                resp = req.get_response(self.app, 'PUT', body='',
                                        headers=headers)
        except ErrorResponse as e:
            msg = str(e._msg)
            expected_msg = 'too small; each segment must be at least 1 byte'
            if expected_msg in msg:
                # FIXME: AWS S3 allows a smaller object than 5 MB if there is
                # only one part.  Use a COPY request to copy the part object
                # from the segments container instead.
                raise EntityTooSmall(msg)
            else:
                raise

        if empty_seg:
            # clean up the zero-byte segment
            _, empty_seg_cont, empty_seg_name = empty_seg['path'].split('/', 2)
            req.get_response(self.app, 'DELETE',
                             container=empty_seg_cont, obj=empty_seg_name)

        # clean up the multipart-upload record
        obj = '%s/%s' % (req.object_name, upload_id)
        req.environ['oio.ephemeral_object'] = True
        req.get_response(self.app, 'DELETE', container, obj)

        result_elem = Element('CompleteMultipartUploadResult')

        # NOTE: boto with sig v4 appends port to HTTP_HOST value at the
        # request header when the port is non default value and it makes
        # req.host_url like as http://localhost:8080:8080/path
        # that obviously invalid. Probably it should be resolved at
        # swift.common.swob though, tentatively we are parsing and
        # reconstructing the correct host_url info here.
        # in detail, https://github.com/boto/boto/pull/3513
        parsed_url = urlparse(req.host_url)
        host_url = '%s://%s' % (parsed_url.scheme, parsed_url.hostname)
        if parsed_url.port:
            host_url += ':%s' % parsed_url.port

        SubElement(result_elem, 'Location').text = host_url + req.path
        SubElement(result_elem, 'Bucket').text = req.container_name
        SubElement(result_elem, 'Key').text = req.object_name
        SubElement(result_elem, 'ETag').text = '"%s"' % s3_etag
        del resp.headers['ETag']

        resp.body = tostring(result_elem)
        resp.status = 200
        resp.content_type = "application/xml"

        return resp
