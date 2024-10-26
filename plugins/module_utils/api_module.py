# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import socket
import json

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils._text import to_bytes, to_text
from ansible.module_utils.six.moves.urllib.parse import urlparse, urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import Request, SSLValidationError


class APIModuleError(Exception):
    """API request error exception.

    :param error_message: Error message.
    :type error_message: str
    """

    def __init__(self, error_message):
        """Initialize the object."""
        self.error_message = error_message

    def __str__(self):
        """Return the error message."""
        return self.error_message


class APIModule(AnsibleModule):
    """Ansible module for managing RHACS/Stackrox."""

    AUTH_ARGSPEC = dict(
        rhacs_host=dict(
            fallback=(env_fallback, ["ROX_ENDPOINT"]), default="https://localhost:8443"
        ),
        skip_validate_certs=dict(
            type="bool",
            aliases=["insecure_skip_tls_verify", "skip_tls_verify"],
            default=False,
            fallback=(env_fallback, ["ROX_INSECURE_CLIENT_SKIP_TLS_VERIFY"]),
        ),
        rhacs_username=dict(fallback=(env_fallback, ["ROX_USERNAME"])),
        rhacs_password=dict(
            no_log=True,
            fallback=(env_fallback, ["ROX_ADMIN_PASSWORD", "ROX_PASSWORD"]),
        ),
        rhacs_token=dict(no_log=True, fallback=(env_fallback, ["ROX_API_TOKEN"])),
    )

    MUTUALLY_EXCLUSIVE = [
        ("rhacs_username", "rhacs_token"),
        ("rhacs_password", "rhacs_token"),
    ]

    REQUIRED_TOGETHER = [("rhacs_username", "rhacs_password")]

    REQUIRED_ONE_OF = [("rhacs_username", "rhacs_token")]

    def __init__(self, argument_spec, **kwargs):
        """Initialize the object.

        Sets:
        * :py:attr:``self.host_url``: :py:class:``urllib.parse.ParseResult``
          object that represents the base URL of RHACS central.
        """

        full_argspec = {}
        full_argspec.update(self.AUTH_ARGSPEC)
        full_argspec.update(argument_spec)

        kwargs["mutually_exclusive"] = (
            kwargs.get("mutually_exclusive", []) + self.MUTUALLY_EXCLUSIVE
        )

        kwargs["required_together"] = (
            kwargs.get("required_together", []) + self.REQUIRED_TOGETHER
        )

        kwargs["required_one_of"] = kwargs.get("required_one_of", []) + self.REQUIRED_ONE_OF

        super(APIModule, self).__init__(argument_spec=full_argspec, **kwargs)

        host = self.params.get("rhacs_host")

        if not host.startswith("https://") and not host.startswith("http://"):
            host = "https://{host}".format(host=host)

        # Try to parse the hostname as a URL
        try:
            self.host_url = urlparse(host)
        except Exception as e:
            self.fail_json(
                msg="Unable to parse `rhacs_host' as a URL ({host}): {error}".format(
                    host=host, error=e
                )
            )

        # Try to resolve the hostname
        try:
            socket.gethostbyname(self.host_url.hostname)
        except Exception as e:
            self.fail_json(
                msg="Unable to resolve `rhacs_host' ({host}): {error}".format(
                    host=self.host_url.hostname, error=e
                )
            )

        # Create a network session object
        self.create_session()

        # Authenticate
        token = self.params.get("rhacs_token")
        if token:
            self.session.headers.update(
                {"Authorization": "Bearer {token}".format(token=token)}
            )
        else:
            authstr = to_text(
                base64.b64encode(
                    to_bytes(
                        self.params.get("rhacs_username")
                        + ":"
                        + self.params.get("rhacs_password")
                    )
                )
            )
            self.session.headers.update(
                {"Authorization": "Basic {auth}".format(auth=authstr)}
            )

    def create_session(self):
        """Create a network session.

        The session preserves cookies and headers between calls.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.session = Request(
            validate_certs=not self.params.get("skip_validate_certs"),
            headers=headers,
            timeout=30,
        )

    def build_url(self, endpoint, query_params=None):
        """Return a URL for the given endpoint.

        The URL is build as follows::

            https://<self.host_url><endpoint>[?<query>]

        :param endpoint: The API path
        :type endpoint: str
        :param query_params: The optional query to append to the URL
        :type query_params: dict

        :return: The full URL built from the given endpoint.
        :rtype: :py:class:``urllib.parse.ParseResult``
        """
        url = self.host_url._replace(path=endpoint)
        if query_params:
            url = url._replace(query=urlencode(query_params))
        return url

    def make_raw_request(self, method, url, ok_error_codes=None, **kwargs):
        """Perform an API call and return the retrieved data.

        :param method: GET, PUT, POST, or DELETE
        :type method: str
        :param url: URL to the API endpoint
        :type url: :py:class:``urllib.parse.ParseResult``
        :param ok_error_codes: HTTP error codes that are acceptable (not errors)
                               when returned by the API. 404 by default.
        :type ok_error_codes: list
        :param kwargs: Additional parameter to pass to the API (headers, data
                       for PUT and POST requests, ...)

        :raises APIModuleError: The API request failed.

        :return: A dictionary with three entries: ``status_code`` provides the
                 API call returned code, ``body`` provides the returned data,
                 and ``headers`` provides the returned headers (dictionary)
        :rtype: dict
        """
        if ok_error_codes is None:
            ok_error_codes = [404]
        # In case someone is calling us directly; make sure we were given a
        # method, let's not just assume a GET
        if not method:
            raise Exception("The HTTP method must be provided.")

        # Extract the provided headers and data
        headers = kwargs.get("headers", {})
        data = kwargs.get("data")
        if isinstance(data, dict):
            data = json.dumps(data)

        try:
            response = self.session.open(method, url.geturl(), headers=headers, data=data)
        except SSLValidationError as ssl_err:
            raise APIModuleError(
                "Could not establish a secure connection to {host}: {error}.".format(
                    host=url.netloc, error=ssl_err
                )
            )
        except ConnectionError as con_err:
            raise APIModuleError(
                "Network error when trying to connect to {host}: {error}.".format(
                    host=url.netloc, error=con_err
                )
            )
        except HTTPError as he:
            if he.code in ok_error_codes:
                response = he
            # Sanity check: Did the server send back some kind of internal error?
            elif he.code >= 500:
                raise APIModuleError(
                    ("The host sent back a server error: {path}: {error}.").format(
                        path=url.path, error=he
                    )
                )
            # Sanity check: Did we fail to authenticate properly?
            # If so, fail out now; this is always a failure.
            elif he.code == 401:
                raise APIModuleError(
                    "Authentication required for {path} (HTTP 401).".format(path=url.path)
                )
            # Sanity check: Did we get a forbidden response, which means that
            # the user isn't allowed to do this? Report that.
            elif he.code == 403:
                raise APIModuleError(
                    "You do not have permission to {method} {path} (HTTP 403).".format(
                        method=method, path=url.path
                    )
                )
            # Sanity check: Did we get a 404 response?
            # Requests with primary keys will return a 404 if there is no
            # response, and we want to consistently trap these.
            elif he.code == 405:
                raise APIModuleError(
                    "Cannot make a {method} request to this endpoint {path}.".format(
                        method=method, path=url.path
                    )
                )
            # Sanity check: Did we get some other kind of error?  If so, write
            # an appropriate error message.
            elif he.code >= 400:
                # We are going to return a 400 so the module can decide what to
                # do with it.
                response = he
            elif he.code == 204 and method == "DELETE":
                # A 204 is a normal response for a delete function
                response = he
            else:
                raise APIModuleError(
                    "Unexpected return code when calling {url}: {error}".format(
                        url=url.geturl(), error=he
                    )
                )
        except Exception as e:
            raise APIModuleError(
                (
                    "There was an unknown error when trying to connect"
                    " to {url}: {name}: {error}."
                ).format(name=type(e).__name__, error=e, url=url.geturl())
            )

        try:
            response_body = response.read()
            # Convert the list of tuples to a dictionary
            response_headers = {}
            for r in response.getheaders():
                response_headers[r[0]] = r[1]
        except Exception as e:
            raise APIModuleError(
                "Cannot read response from the {method} request to {path}: {error}.".format(
                    method=method, path=url.path, error=e
                )
            )

        return {
            "status_code": response.status,
            "body": response_body,
            "headers": response_headers,
        }

    def make_json_request(self, method, url, ok_error_codes=None, **kwargs):
        """Perform an API call and return the retrieved JSON data.

        :param method: GET, PUT, POST, or DELETE
        :type method: str
        :param url: URL to the API endpoint
        :type url: :py:class:``urllib.parse.ParseResult``
        :param ok_error_codes: HTTP error codes that are acceptable (not errors)
                               when returned by the API. 404 by default.
        :type ok_error_codes: list
        :param kwargs: Additional parameter to pass to the API (data
                       for PUT and POST requests, ...)

        :raises APIModuleError: The API request failed.

        :return: A dictionary with three entries: ``status_code`` provides the
                 API call returned code, ``json`` provides the returned data
                 in JSON format, and ``headers`` provides the returned headers
                 (dictionary)
        :rtype: dict
        """
        response = self.make_raw_request(method, url, ok_error_codes, **kwargs)
        response_body = response.get("body")
        response_json = {}
        if response_body:
            try:
                response_json = json.loads(response_body)
            except Exception as e:
                raise APIModuleError(
                    (
                        "Failed to parse the JSON response from the"
                        " {method} request to {path}: {error}."
                    ).format(method=method, path=url.path, error=e)
                )

        return {
            "status_code": response["status_code"],
            "json": response_json,
            "headers": response["headers"],
        }

    def get_error_message(self, response):
        """Return the error message provided in the API response.

        :param response: The response message from the API. This dictionary has
                         two keys: ``status_code`` provides the API call
                         returned code and ``json`` provides the returned data
                         in JSON format.
        :type response: dict

        :return: The error message or an empty string if the response does not
                 provide a message.
        :rtype: str
        """
        if not response or "json" not in response:
            return ""

        # Some API calls do not return JSON, but a string
        if isinstance(response["json"], str):
            return response["json"]

        message = response["json"].get("message") or response["json"].get("error")
        return message if message else ""

    def get_object_path(
        self, endpoint, query_params=None, exit_on_error=True, ok_error_codes=None
    ):
        """Retrieve a single object from a GET API call.

        :param endpoint: API endpoint path.
        :type endpoint: str
        :param query_params: The optional query to append to the URL
        :type query_params: dict
        :param exit_on_error: If ``True`` (the default), exit the module on API
                              error. Otherwise, raise the
                              :py:class:``APIModuleError`` exception.
        :type exit_on_error: bool
        :param ok_error_codes: HTTP error codes that are acceptable (not errors)
                               when returned by the API. 404 by default.
        :type ok_error_codes: list

        :raises APIModuleError: An API error occurred. That exception is only
                                raised when ``exit_on_error`` is ``False``.

        :return: The response from the API or ``None`` if the object does not
                 exist.
        :rtype: dict
        """
        if ok_error_codes is None:
            ok_error_codes = [404]

        url = self.build_url(endpoint, query_params=query_params)
        try:
            response = self.make_json_request("GET", url, ok_error_codes=ok_error_codes)
        except APIModuleError as e:
            if exit_on_error:
                self.fail_json(msg=str(e))
            else:
                raise

        if response["status_code"] in ok_error_codes:
            return None

        if response["status_code"] != 200:
            error_msg = self.get_error_message(response)
            if error_msg:
                fail_msg = "Unable to get {path}: {code}: {error}.".format(
                    path=url.path,
                    code=response["status_code"],
                    error=error_msg,
                )
            else:
                fail_msg = "Unable to get {path}: {code}.".format(
                    path=url.path,
                    code=response["status_code"],
                )
            if exit_on_error:
                self.fail_json(msg=fail_msg)
            else:
                raise APIModuleError(fail_msg)

        return response["json"]

    def delete(
        self,
        object,
        object_type,
        object_name,
        endpoint,
        query_params=None,
        auto_exit=True,
        exit_on_error=True,
        not_found_codes=None,
    ):
        """Delete an object.

        :param object: The object to delete. The function only uses that
                       parameter to decide if there is something to do. If
                       ``None`` then the function considers that the object
                       does no exist and therefore does not perform the DELETE
                       API call. This is usually the object you got from the
                       :py:meth:``get_object_path`` method.
        :type object: dict
        :param object_type: Type of the object to delete. Only used to return
                            error messages.
        :type object_type: str
        :param object_name: Name of the object to delete. Only used to return
                            error messages.
        :type object_name: str
        :param endpoint: API endpoint path.
        :type endpoint: str
        :param query_params: The optional query to append to the URL
        :type query_params: dict
        :param auto_exit: Exit the module when the API call is done.
        :type auto_exit: bool
        :param exit_on_error: If ``True`` (the default), exit the module on API
                              error. Otherwise, raise the
                              :py:class:``APIModuleError`` exception.
        :type exit_on_error: bool
        :param not_found_codes: HTTP codes that are acceptable (no change)
                                when returned by the API. 400 and 404 by
                                default.
        :type not_found_codes: list

        :raises APIModuleError: An API error occurred. That exception is only
                                raised when ``exit_on_error`` is ``False``.

        :return: ``True`` if something has changed (object deleted), ``False``
                 otherwise.
        :rtype: bool
        """
        if not_found_codes is None:
            not_found_codes = [400, 404]

        if object is None:
            if auto_exit:
                self.exit_json(changed=False)
            return False

        if self.check_mode:
            if auto_exit:
                self.exit_json(changed=True)
            return True

        url = self.build_url(endpoint, query_params=query_params)
        try:
            response = self.make_json_request("DELETE", url)
        except APIModuleError as e:
            if exit_on_error:
                self.fail_json(msg=str(e))
            else:
                raise

        # Success
        if response["status_code"] in [200, 201, 202, 204]:
            if auto_exit:
                self.exit_json(changed=True)
            return True

        # Object not found
        if response["status_code"] in not_found_codes:
            if auto_exit:
                self.exit_json(changed=False)
            return False

        # Failure
        error_msg = self.get_error_message(response)
        if error_msg:
            fail_msg = "Unable to delete {object_type} {name}: {error}".format(
                object_type=object_type, name=object_name, error=error_msg
            )
        else:
            fail_msg = "Unable to delete {object_type} {name}: {code}".format(
                object_type=object_type,
                name=object_name,
                code=response["status_code"],
            )
        if exit_on_error:
            self.fail_json(msg=fail_msg)
        else:
            raise APIModuleError(fail_msg)

    def create(
        self,
        object_type,
        object_name,
        endpoint,
        new_item,
        auto_exit=True,
        exit_on_error=True,
        ok_error_codes=None,
    ):
        """Create an object.

        :param object_type: Type of the object to create. Only used to return
                            error messages.
        :type object_type: str
        :param object_name: Name of the object to create. Only used to return
                            error messages.
        :type object_name: str
        :param endpoint: API endpoint path.
        :type endpoint: str
        :param new_item: The data to pass to the API call. This provides the
                         object details. For example,
                         ``{"username": "jdoe","email":"jdoe@example.com"}``
        :type new_item: dict
        :param auto_exit: Exit the module when the API call is done.
        :type auto_exit: bool
        :param exit_on_error: If ``True`` (the default), exit the module on API
                              error. Otherwise, raise the
                              :py:class:``APIModuleError`` exception.
        :type exit_on_error: bool
        :param ok_error_codes: HTTP error codes that are acceptable (not errors)
                               when returned by the API. 200, 201, and 204 by
                               default.
        :type ok_error_codes: list

        :raises APIModuleError: An API error occurred. That exception is only
                                raised when ``exit_on_error`` is ``False``.

        :return: The data returned by the API call.
        :rtype: dict
        """
        if ok_error_codes is None:
            ok_error_codes = [200, 201, 204]
        if self.check_mode:
            if auto_exit:
                self.exit_json(changed=True)
            return {}

        url = self.build_url(endpoint)
        try:
            response = self.make_json_request(
                "POST", url, ok_error_codes=ok_error_codes, data=new_item
            )
        except APIModuleError as e:
            if exit_on_error:
                self.fail_json(msg=str(e))
            else:
                raise

        # Success
        if response["status_code"] in ok_error_codes:
            if auto_exit:
                self.exit_json(changed=True)
            return response.get("json", {})

        # Failure
        error_msg = self.get_error_message(response)
        if error_msg:
            fail_msg = "Unable to create {object_type} {name}: {error}".format(
                object_type=object_type, name=object_name, error=error_msg
            )
        else:
            fail_msg = "Unable to create {object_type} {name}: {code}".format(
                object_type=object_type,
                name=object_name,
                code=response["status_code"],
            )
        if exit_on_error:
            self.fail_json(msg=fail_msg)
        else:
            raise APIModuleError(fail_msg)

    def patch(self, object_type, object_name, endpoint, data=None, exit_on_error=True):
        """Send a PATH request.

        :param object_type: Type of the object to patch. Only used to return
                            error messages.
        :type object_type: str
        :param object_name: Name of the object to patch. Only used to return
                            error messages.
        :type object_name: str
        :param endpoint: API endpoint path.
        :type endpoint: str
        :param data: The data to pass to the API call. This provides the
                     object details. For example,
                     ``{"enabled": False,"password":"Sup3r53cr3t"}``
        :type new_item: dict
        :param exit_on_error: If ``True`` (the default), exit the module on API
                              error. Otherwise, raise the
                              :py:class:``APIModuleError`` exception.
        :type exit_on_error: bool

        :raises APIModuleError: An API error occurred. That exception is only
                                raised when ``exit_on_error`` is ``False``.

        :return: The data returned by the API call.
        :rtype: dict
        """
        if self.check_mode:
            return {}

        url = self.build_url(endpoint)
        try:
            response = self.make_json_request("PATCH", url, data=data)
        except APIModuleError as e:
            if exit_on_error:
                self.fail_json(msg=str(e))
            else:
                raise

        # Failure
        if response["status_code"] not in [200, 201, 204]:
            error_msg = self.get_error_message(response)
            if error_msg:
                fail_msg = "Unable to update {object_type} {name}: {error}".format(
                    object_type=object_type, name=object_name, error=error_msg
                )
            else:
                fail_msg = "Unable to update {object_type} {name}: {code}".format(
                    object_type=object_type,
                    name=object_name,
                    code=response["status_code"],
                )
            if exit_on_error:
                self.fail_json(msg=fail_msg)
            else:
                raise APIModuleError(fail_msg)

        return response.get("json", {})

    def unconditional_update(
        self, object_type, object_name, endpoint, new_item, exit_on_error=True
    ):
        """Update an object without checking if it needs to be updated.

        :param object_type: Type of the object to update. Only used to return
                            error messages.
        :type object_type: str
        :param object_name: Name of the object to update. Only used to return
                            error messages.
        :type object_name: str
        :param endpoint: API endpoint path.
        :type endpoint: str
        :param new_item: The data to pass to the API call. This provides the
                         object details. For example,
                         ``{"enabled": False,"password":"Sup3r53cr3t"}``
        :type new_item: dict
        :param exit_on_error: If ``True`` (the default), exit the module on API
                              error. Otherwise, raise the
                              :py:class:``APIModuleError`` exception.
        :type exit_on_error: bool

        :raises APIModuleError: An API error occurred. That exception is only
                                raised when ``exit_on_error`` is ``False``.

        :return: The data returned by the API call.
        :rtype: dict
        """
        if self.check_mode:
            return {}

        url = self.build_url(endpoint)
        try:
            response = self.make_json_request("PUT", url, data=new_item)
        except APIModuleError as e:
            if exit_on_error:
                self.fail_json(msg=str(e))
            else:
                raise

        # Failure
        if response["status_code"] not in [200, 201, 204]:
            error_msg = self.get_error_message(response)
            if error_msg:
                fail_msg = "Unable to update {object_type} {name}: {error}".format(
                    object_type=object_type, name=object_name, error=error_msg
                )
            else:
                fail_msg = "Unable to update {object_type} {name}: {code}".format(
                    object_type=object_type,
                    name=object_name,
                    code=response["status_code"],
                )
            if exit_on_error:
                self.fail_json(msg=fail_msg)
            else:
                raise APIModuleError(fail_msg)

        return response.get("json", {})

    def get_item_from_resource_list(self, name_or_id, resource_list, name_attribute="name"):
        """Retrieve an RHACS object from a list or objects.

        :param name_or_id: Name or ID of the object to retrieve.
        :type name_or_id: str
        :param resource_list: List of objects. Each object is a dictionary and
                              must have the ``name`` and ``id`` keys.
        :type resource_list: list
        :param name_attribute: The attribute in the list that contains the
                               object name.
        :type name_attribute: str

        :return: The object or None if the object is not found.
        :rtype: dict
        """
        if not name_or_id or not resource_list:
            return None
        for res in resource_list:
            if name_or_id == res.get(name_attribute) or name_or_id == res.get("id"):
                return res
        return None

    def get_id_from_resource_list(
        self,
        name_or_id,
        resource_list,
        exit_on_error=True,
        error_msg="the object does not exist",
    ):
        """Retrieve an object ID from a list or objects.

        :param name_or_id: Name or ID of the object to retrieve.
        :type name_or_id: str
        :param resource_list: List of objects. Each object is a dictionary and
                              must have the ``name`` and ``id`` keys.
        :type resource_list: list
        :param exit_on_error: If ``True`` (the default), exit the module when
                              the object is not found. Otherwise, return
                              ``None``.
        :type exit_on_error: bool
        :param error_msg: Error message on module exit. Only used when
                          ``exit_on_error`` is ``True``.
        :type error_msg: str

        :return: The object ID or None if the object is not found and
                 ``exit_on_error`` is ``False``
        :rtype: dict
        """
        obj = self.get_item_from_resource_list(name_or_id, resource_list)
        if obj:
            return obj.get("id")
        if exit_on_error:
            self.fail_json(msg="{err}: {name}".format(err=error_msg, name=name_or_id))
        return None

    def get_policies(self):
        """Retrieve the list of security policies.

        :return: The list of policy objects
        :rtype: list
        """
        try:
            return self.policies
        except AttributeError:
            # Retrieve the existing policies
            #
            # GET /v1/policies
            # {
            #   "policies": [
            #     {
            #       "id": "da4e0776-159b-42a3-90a9-18cdd9b485ba",
            #       "name": "OpenShift: Central Admin Secret Accessed",
            #       "description": "Alert when the Central secret is accessed.",
            #       "severity": "MEDIUM_SEVERITY",
            #       "disabled": false,
            #       "lifecycleStages": [
            #         "RUNTIME"
            #       ],
            #       "notifiers": [],
            #       "lastUpdated": null,
            #       "eventSource": "AUDIT_LOG_EVENT",
            #       "isDefault": true
            #     },
            #     {
            #       "id": "18cbcb62-7d18-4a6c-b2ca-dd1242746943",
            #       "name": "OpenShift: Kubeadmin Secret Accessed",
            #       "description": "Alert when the secret is accessed",
            #       "severity": "HIGH_SEVERITY",
            #       "disabled": false,
            #       "lifecycleStages": [
            #         "RUNTIME"
            #       ],
            #       "notifiers": [],
            #       "lastUpdated": null,
            #       "eventSource": "AUDIT_LOG_EVENT",
            #       "isDefault": true
            #     },
            #     ...
            #   ]
            # }
            p = self.get_object_path("/v1/policies", query_params={"pagination.limit": 10000})
            self.policies = p.get("policies", [])
            return self.policies

    def get_policy(self, name_or_id):
        """Retrieve a security policy.

        :param name_or_id: Name or ID of the security policy to retrieve.
        :type name_or_id: str

        :return: The policy object or None if the policy is not found.
        :rtype: dict
        """
        return self.get_item_from_resource_list(name_or_id, self.get_policies())

    def get_clusters(self):
        """Retrieve the list of the secured clusters.

        :return: The list of secured cluster objects
        :rtype: list
        """
        try:
            return self.clusters
        except AttributeError:
            # Retrieve the existing clusters
            #
            # GET /v1/clusters
            # {
            #     "clusters": [
            #         {
            #             "id": "179a071b-38c0-4c00-99cb-248e7737be63",
            #             "name": "production",
            #             "type": "OPENSHIFT4_CLUSTER",
            #             "labels": {},
            #             ...
            #         }
            #     ]
            # }
            c = self.get_object_path("/v1/clusters")
            self.clusters = c.get("clusters", [])
            return self.clusters

    def get_cluster(self, name_or_id):
        """Retrieve a secured cluster object.

        :param name_or_id: Name or ID of the secured cluster to retrieve.
        :type name_or_id: str

        :return: The cluster object or None if the cluster is not found.
        :rtype: dict
        """
        return self.get_item_from_resource_list(name_or_id, self.get_clusters())

    def get_cluster_id(self, name_or_id):
        """Return the ID of a secured cluster.

        :param name_or_id: Name or ID of the secured cluster to retrieve.
        :type name_or_id: str

        :return: The cluster ID. If the cluster is not found, then the module
                 exists in error.
        :rtype: str
        """
        return self.get_id_from_resource_list(
            name_or_id, self.get_clusters(), error_msg="the cluster does not exist"
        )

    def get_notifiers(self):
        """Retrieve the list of the notifier method configurations.

        :return: The list of notifier method configuration objects
        :rtype: list
        """
        try:
            return self.notifiers
        except AttributeError:
            # Retrieve the existing notifier method configuration
            #
            # GET /v1/notifiers
            # {
            #   "notifiers": [
            #     {
            #       "id": "0263296a-d1bd-42bf-b6b6-4dee998d8fcc",
            #       "name": "email1",
            #       "type": "email",
            #       "uiEndpoint": "https://central.example.com",
            #       "labelKey": "annotationkey",
            #       "labelDefault": "alerts@example.com",
            #       "email": {
            #         "server": "smtp.example.com:465",
            #         "sender": "sender@example.com",
            #         "username": "username",
            #         "password": "******",
            #         "disableTLS": true,
            #         "DEPRECATEDUseStartTLS": false,
            #         "from": "from",
            #         "startTLSAuthMethod": "LOGIN",
            #         "allowUnauthenticatedSmtp": false
            #       },
            #       "notifierSecret": "******",
            #       "traits": null
            #     },
            #     {
            #       "id": "0ab69cc7-301a-4e8f-8761-748b59e652c7",
            #       "name": "slack11",
            #       "type": "slack",
            #       "uiEndpoint": "https://central.example.com",
            #       "labelKey": "annotationkey",
            #       "labelDefault": "https://hooks.slack.com/services/EXAMPLE",
            #       "notifierSecret": "******",
            #       "traits": null
            #     },
            #     {
            #       "id": "d8f69af5-3b52-48e0-9e3f-b610ce7ba436",
            #       "name": "google cloud scc",
            #       "type": "cscc",
            #       "uiEndpoint": "https://central.example.com",
            #       "labelKey": "",
            #       "labelDefault": "",
            #       "cscc": {
            #         "serviceAccount": "******",
            #         "sourceId": "organizations/123/sources/456",
            #         "wifEnabled": true
            #       },
            #       "notifierSecret": "******",
            #       "traits": null
            #     },
            #     {
            #       "id": "a317e4b0-d4fd-49b8-891e-00eaf5cae08d",
            #       "name": "splunk1",
            #       "type": "splunk",
            #       "uiEndpoint": "https://central.example.com",
            #       "labelKey": "",
            #       "labelDefault": "",
            #       "splunk": {
            #         "httpToken": "******",
            #         "httpEndpoint": "collector.example.com",
            #         "insecure": true,
            #         "truncate": "10000",
            #         "auditLoggingEnabled": true,
            #         "sourceTypes": {
            #           "alert": "stackrox-alert",
            #           "audit": "stackrox-audit-message"
            #         }
            #       },
            #       "notifierSecret": "******",
            #       "traits": null
            #     },
            #         ...
            #     ]
            # }
            c = self.get_object_path("/v1/notifiers")
            self.notifiers = c.get("notifiers", [])
            return self.notifiers

    def get_notifier(self, name_or_id):
        """Retrieve a notifier method configuration object.

        :param name_or_id: Name or ID of the notifier method configuration to
                           retrieve.
        :type name_or_id: str

        :return: The notifier method configuration object or None if the
                 configuration is not found.
        :rtype: dict
        """
        return self.get_item_from_resource_list(name_or_id, self.get_notifiers())

    def get_notifier_id(self, name_or_id):
        """Return the ID of a notifier method configuration.

        :param name_or_id: Name or ID of the notifier method configuration to
                           retrieve.
        :type name_or_id: str

        :return: The notifier method configuration ID. If the configuration is
                 not found, then the module exists in error.
        :rtype: str
        """
        return self.get_id_from_resource_list(
            name_or_id,
            self.get_notifiers(),
            error_msg="the notifier method (in `notifiers') does not exist",
        )

    def get_collections(self):
        """Retrieve the list of the deployment collections.

        :return: The list of deployment collection objects
        :rtype: list
        """
        try:
            return self.collections
        except AttributeError:
            # Retrieve the existing deployment collections
            #
            # GET /v1/collections
            # {
            #     "collections": [
            #         {
            #             "id": "7e4a265e-2d5a-4ff4-81a8-e426b102dbae",
            #             "name": "My collection",
            #             "description": "My description",
            #             "createdAt": "2024-10-03T14:07:18.562326152Z",
            #             "lastUpdated": "2024-10-03T14:07:18.562326152Z",
            #             "createdBy": {
            #                 "id": "sso:4df1...b62d:admin",
            #                 "name": "admin"
            #             },
            #             "updatedBy": {
            #                 "id": "sso:4df1...b62d:admin",
            #                 "name": "admin"
            #             },
            #             "resourceSelectors": [
            #                 {
            #                     "rules": [
            #                         {
            #                             "fieldName": "Namespace Label",
            #                             "operator": "OR",
            #                             "values": [
            #                                 {
            #                                     "value": "team=payment",
            #                                     "matchType": "EXACT"
            #                                 },
            #                                 {
            #                                     "value": "foo=bar",
            #                                     "matchType": "EXACT"
            #                                 }
            #                             ]
            #                         },
            #                         {
            #                             "fieldName": "Namespace Label",
            #                             "operator": "OR",
            #                             "values": [
            #                                 {
            #                                     "value": "toto=titi",
            #                                     "matchType": "EXACT"
            #                                 }
            #                             ]
            #                         },
            #                         {
            #                             "fieldName": "Deployment",
            #                             "operator": "OR",
            #                             "values": [
            #                                 {
            #                                     "value": "nginx-deployment",
            #                                     "matchType": "EXACT"
            #                                 },
            #                                 {
            #                                     "value": "^nginx-deployment$",
            #                                     "matchType": "REGEX"
            #                                 }
            #                             ]
            #                         }
            #                     ]
            #                 }
            #             ],
            #             "embeddedCollections": [
            #                 {
            #                     "id": "a7e188bb-f4f5-4023-a91f-4d4585809d17"
            #                 }
            #             ]
            #         },
            #         ...
            #     ]
            # }
            c = self.get_object_path(
                "/v1/collections", query_params={"query.pagination.limit": 10000}
            )
            self.collections = c.get("collections", [])
            return self.collections

    def get_collection(self, name_or_id):
        """Retrieve a deployment collection object.

        :param name_or_id: Name or ID of the collection to retrieve.
        :type name_or_id: str

        :return: The collection object or None if the collection is not found.
        :rtype: dict
        """
        return self.get_item_from_resource_list(name_or_id, self.get_collections())

    def get_collection_id(self, name_or_id):
        """Return the ID of a deployment collection.

        :param name_or_id: Name or ID of the collection to retrieve.
        :type name_or_id: str

        :return: The deployment collection ID. If the collection is not found,
                 then the module exists in error.
        :rtype: str
        """
        return self.get_id_from_resource_list(
            name_or_id,
            self.get_collections(),
            error_msg="the deployment collection (in `collection') does not exist",
        )
