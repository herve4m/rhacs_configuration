# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Ansible Galaxy documentation fragment
    DOCUMENTATION = r"""
options:
  rhacs_host:
    description:
      - URL for accessing the API. U(https://rhacs.example.com:8443)
        for example.
      - If you do not set the parameter, then the module uses the
        E(ROX_ENDPOINT) environment variable.
      - If you do no set the environment variable either, then the module uses
        the U(https://localhost:8443) URL.
    type: str
    default: https://localhost:8443
  skip_validate_certs:
    description:
      - Whether to allow insecure connections to the API.
      - If V(true), then the module does not validate SSL certificates.
      - If you do not set the parameter, then the module tries the
        E(ROX_INSECURE_CLIENT_SKIP_TLS_VERIFY) environment variable (V(yes),
        V(1), and V(True) mean true, and V(no), V(0), V(False), and no value
        mean false).
    type: bool
    default: false
    aliases:
      - insecure_skip_tls_verify
      - skip_tls_verify
  rhacs_username:
    description:
      - The username to use for authenticating against the API.
      - If you do not set the parameter, then the module tries the
        E(ROX_USERNAME) environment variable.
      - If you set O(rhacs_username), then you also need to set
        O(rhacs_password).
      - Mutually exclusive with O(rhacs_token).
    type: str
  rhacs_password:
    description:
      - The password to use for authenticating against the API.
      - If you do not set the parameter, then the module tries the
        E(ROX_ADMIN_PASSWORD) and E(ROX_PASSWORD) environment variables,
        in that order.
      - If you set O(rhacs_password), then you also need to set
        O(rhacs_username).
      - Mutually exclusive with O(rhacs_token).
    type: str
  rhacs_token:
    description:
      - Token for authenticating against the API.
      - If you do not set the parameter, then the module tries the
        E(ROX_API_TOKEN) environment variable.
      - Mutually exclusive with O(rhacs_username) and O(rhacs_password).
    type: str
"""
