import io
import json
import logging
import logging.config
import sys
from urllib.parse import parse_qsl

import pkg_resources

from .base import SATOSABase
from .context import Context

### rZone Code Start ###
''' org
from .response import ServiceError, NotFound
'''
from .response import ServiceError, NotFound, Response
from pyop.storage import MongoWrapper
### rZone Code End ###

from .routing import SATOSANoBoundEndpointError
from saml2.s_utils import UnknownSystemEntity

logger = logging.getLogger(__name__)

def unpack_get(environ):
    """
    Unpacks a redirect request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    if "QUERY_STRING" in environ:
        return dict(parse_qsl(environ["QUERY_STRING"]))

    return None


def unpack_post(environ, content_length):
    """
    Unpacks a post request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    post_body = environ['wsgi.input'].read(content_length).decode("utf-8")
    data = None
    if "application/x-www-form-urlencoded" in environ["CONTENT_TYPE"]:
        data = dict(parse_qsl(post_body))
        logger.info("In x-www-form-urlencoded")
    elif "application/json" in environ["CONTENT_TYPE"]:
        data = json.loads(post_body)
        logger.info("In application/jason")

    logger.debug("unpack_post:: %s", data)
    return data


def unpack_request(environ, content_length=0):
    """
    Unpacks a get or post request query string.
    :param environ: whiskey application environment.
    :return: A dictionary with parameters.
    """
    data = None
    if environ["REQUEST_METHOD"] == "GET":
        data = unpack_get(environ)
    elif environ["REQUEST_METHOD"] == "POST":
        data = unpack_post(environ, content_length)

    logger.debug("read request data: %s", data)
    return data


class ToBytesMiddleware(object):
    """Converts a message to bytes to be sent by WSGI server."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        data = self.app(environ, start_response)

        if isinstance(data, list):
            encoded_data = []
            for d in data:
                if isinstance(d, bytes):
                    encoded_data.append(d)
                else:
                    encoded_data.append(d.encode("utf-8"))
            return encoded_data

        if isinstance(data, str):
            return data.encode("utf-8")

        return data


class WsgiApplication(SATOSABase):
    def __init__(self, config):
        super().__init__(config)
        self.config = config

    def __call__(self, environ, start_response, debug=False):
        path = environ.get('PATH_INFO', '').lstrip('/')
        if ".." in path or path == "":
            resp = NotFound("Couldn't find the page you asked for!")
            return resp(environ, start_response)

        context = Context()
        context.path = path

        # copy wsgi.input stream to allow it to be re-read later by satosa plugins
        # see: http://stackoverflow.com/questions/1783383/how-do-i-copy-wsgi-input-if-i-want-to-process-post-data-more-than-once
        content_length = int(environ.get('CONTENT_LENGTH', '0') or '0')
        body = io.BytesIO(environ['wsgi.input'].read(content_length))
        environ['wsgi.input'] = body
        context.request = unpack_request(environ, content_length)
        environ['wsgi.input'].seek(0)

        ### rZone Code Start ###
        access_ip = environ['HTTP_X_FORWARDED_FOR']
        if context.path == 'rz-api/client-info':
            try:
                resp_data = {}
                resp_data['status'] = 401

                allow_ip = self.config['config']['rz_api']['allow_ip']
                if access_ip not in allow_ip:
                    resp = Response(message=json.dumps(resp_data))
                    return resp(environ, start_response)

                relay_state = context.request['relay_state']
                db_uri = self.config['config']['db_uri']
                client_db = MongoWrapper(db_uri, "satosa", "clients") 
                consent_db = MongoWrapper(db_uri, "satosa", "consents") 

                if relay_state not in consent_db:
                    resp_data['status'] = 404
                    resp = Response(message=json.dumps(resp_data))
                    return resp(environ, start_response)

                resp_data['status'] = 201 

                consent_info = consent_db[relay_state]
                if consent_info["requester"] in client_db:
                    consent_info['client_info'] = client_db[consent_info["requester"]]
                    resp_data['status'] = 200 

                resp_data['data'] = consent_info

                resp = Response(message=json.dumps(resp_data))
                return resp(environ, start_response)
            except:
                e = sys.exc_info()[0]
                resp = Response(message='{"status": 500}')
                return resp(environ, start_response)

        ### rZone Code End ###
        context.cookie = environ.get("HTTP_COOKIE", "")
        context.request_authorization = environ.get("HTTP_AUTHORIZATION", "")

        try:
            resp = self.run(context)
            if isinstance(resp, Exception):
                raise resp
            return resp(environ, start_response)
        except SATOSANoBoundEndpointError:
            resp = NotFound("Couldn't find the page you asked for!")
            return resp(environ, start_response)
        except Exception as err:
            if type(err) != UnknownSystemEntity:
                logger.exception("%s" % err)
            if debug:
                raise

            resp = ServiceError("%s" % err)
            return resp(environ, start_response)


def make_app(satosa_config):
    try:
        if "LOGGING" in satosa_config:
            logging.config.dictConfig(satosa_config["LOGGING"])
        else:
            stderr_handler = logging.StreamHandler(sys.stderr)
            stderr_handler.setLevel(logging.DEBUG)

            root_logger = logging.getLogger("")
            root_logger.addHandler(stderr_handler)
            root_logger.setLevel(logging.DEBUG)

        try:
            pkg = pkg_resources.get_distribution(module.__name__)
            logger.info("Running SATOSA version %s",
                        pkg_resources.get_distribution("SATOSA").version)
        except (NameError, pkg_resources.DistributionNotFound):
            pass
        return ToBytesMiddleware(WsgiApplication(satosa_config))
    except Exception:
        logger.exception("Failed to create WSGI app.")
        raise
