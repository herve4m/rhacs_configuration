#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_group
short_description: Manage roles for authentication providers
description:
  - Create, delete, and update role assignments to users who log in by using
    an authentication provider.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  auth_provider:
    description:
      - Name or identifier of the authentication provider.
      - See the M(herve4m.rhacs_configuration.rhacs_auth_provider) module for
        managing authentication providers.
    type: str
    required: true
  key:
    description:
      - Metadata key from the identity provider to use for granting roles
        to users.
      - When O(key=default), the module creates a rule that applies to all
        users.
      - Some identity providers support only some of these keys. For example,
        Google IAP supports only V(email) and V(userid), and OpenShift Auth
        supports V(groups), V(name), and V(userid).
    required: true
    type: str
    choices:
      - default
      - email
      - groups
      - name
      - userid
  value:
    description:
      - Value that RHACS uses to verify whether the rule applies.
      - The O(value) parameter is ignore when O(key=default).
    type: str
  role:
    description:
      - Role to grant to users who match the O(key) and O(value) parameters.
      - The special V(None) value does not grant any role. You usually use that
        value when O(key=default) to deny all access by default.
      - V(None) by default.
    type: str
  state:
    description:
      - If V(absent), then the module deletes the rule matching the O(key)
        and O(value) parameters. If you do not provide the O(value) parameter,
        then the module deletes all the rules matching the O(key) parameter.
      - The module does not fail if the rule does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the rule if it does not
        already exist.
      - If the rule already exists, then the module updates its state.
    type: str
    default: present
    choices: [absent, present]
notes:
  - See the M(herve4m.rhacs_configuration.rhacs_auth_provider) module to
    create authentication providers configurations.
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    support: full
    platforms: all
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - herve4m.rhacs_configuration.auth
"""

EXAMPLES = r"""
# Define the minimum access role that RHACS grants to all the users who sign
# in with the authentication provider.
- name: Ensure minimum access role is set for the OIDC provider
  herve4m.rhacs_configuration.rhacs_group:
    auth_provider: Organization OIDC
    key: default
    # Set the role to None, so that no role is granted by default, and only
    # the rules defined in the next tasks apply.
    role: None
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the administrators group has the Admin role
  herve4m.rhacs_configuration.rhacs_group:
    auth_provider: Organization OIDC
    key: groups
    value: administrators
    role: Admin
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure that the lvasquez user has the Analyst role
  herve4m.rhacs_configuration.rhacs_group:
    auth_provider: Organization OIDC
    key: email
    value: lvasquez@example.com
    role: Analyst
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure that the jziglar user has the Network Graph Viewer role
  herve4m.rhacs_configuration.rhacs_group:
    auth_provider: Organization OIDC
    key: email
    value: jziglar@example.com
    role: Network Graph Viewer
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure that all the email rules are removed
  herve4m.rhacs_configuration.rhacs_group:
    auth_provider: Organization OIDC
    key: email
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r""" # """

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        auth_provider=dict(required=True),
        key=dict(required=True, choices=["default", "email", "groups", "name", "userid"]),
        value=dict(),
        role=dict(),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    auth_provider = module.params.get("auth_provider")
    key = module.params.get("key")
    value = module.params.get("value")
    role = module.params.get("role")
    state = module.params.get("state")

    if key == "default":
        key = ""
        value = ""

    # Retrieve the authentication provider ID
    if not auth_provider:
        module.fail_json(msg="the `auth_provider' parameter cannot be empty")
    c = module.get_object_path("/v1/authProviders")
    auth_provider_id = module.get_id_from_resource_list(
        auth_provider,
        c.get("authProviders", []),
        error_msg="the authentication provider (`auth_provider') does not exist",
    )

    # Retrieve the existing groups. The group where key = "" and value = ""
    # defines the default role (minimum access role)
    #
    # GET /v1/groups
    # {
    #   "groups": [
    #     {
    #       "props": {
    #         "id": "io.stackrox.authz.group.2a17...357b",
    #         "traits": null,
    #         "authProviderId": "651f44f7-fe88-42e6-a9aa-0c3f2ad0503f",
    #         "key": "email",
    #         "value": "e-value"
    #       },
    #       "roleName": "Vulnerability Management Requester"
    #     },
    #     {
    #       "props": {
    #         "id": "io.stackrox.authz.group.3a89...557d",
    #         "traits": null,
    #         "authProviderId": "651f44f7-fe88-42e6-a9aa-0c3f2ad0503f",
    #         "key": "userid",
    #         "value": "u-value"
    #       },
    #       "roleName": "Sensor Creator"
    #     },
    #     {
    #       "props": {
    #         "id": "io.stackrox.authz.group.0b71...f68f",
    #         "traits": null,
    #         "authProviderId": "651f44f7-fe88-42e6-a9aa-0c3f2ad0503f",
    #         "key": "",
    #         "value": ""
    #       },
    #       "roleName": "Analyst"
    #     },
    #     ...
    #   ]
    # }

    c = module.get_object_path(
        "/v1/groups", query_params={"authProviderId": auth_provider_id}
    )

    # Retrieve the groups from the given key
    configs = []
    for group in c.get("groups", []):
        props = group.get("props", {})
        if key == props.get("key") and (value is None or value == props.get("value")):
            configs.append(group)

    # Remove all the groups matching the key (and value if value was provided)
    if state == "absent":
        if not configs:
            module.exit_json(changed=False)
        for config in configs:
            module.delete(
                config,
                "group",
                auth_provider,
                "/v1/groups",
                query_params={
                    "id": config.get("props", {}).get("id"),
                    "authProviderId": auth_provider_id,
                },
                auto_exit=False,
            )
        module.exit_json(changed=True)

    # Create the group
    if not configs:
        new_fields = {
            "roleName": role if role else "None",
            "props": {
                "traits": None,
                "authProviderId": auth_provider_id,
                "key": key,
                "value": value if value else "",
            },
        }
        module.create("group", auth_provider, "/v1/groups", new_fields)

    # Searching for the rule matching the role
    if role is None:
        module.exit_json(changed=False)
    for config in configs:
        if role == config.get("roleName"):
            module.exit_json(changed=False)

    # Update all the rules
    for config in configs:
        props = config.get("props", {})
        new_fields = {
            "roleName": role,
            "props": {
                "id": props.get("id"),
                "traits": None,
                "authProviderId": auth_provider_id,
                "key": key,
                "value": value if value is not None else props.get("value"),
            },
        }

        module.unconditional_update("group", auth_provider, "/v1/groups", new_fields)
    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
