#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_api_token
short_description: Create API tokens for accessing the RHACS API
description:
  - Create API tokens for authenticating with the Red Hat Advanced Cluster
    Security for Kubernetes (RHACS) API.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description:
      - Name of the API token to create or delete.
      - Several tokens can have the same name.
    required: true
    type: str
  role:
    description:
      - The role to associate with the token.
    type: str
    default: Admin
  expiration:
    description:
      - The date and time at which the token becomes invalid.
      - The format for the O(expiration) parameter is ISO 8601 UTC, such
        as 2025-12-02T21:06:00Z.
      - If you do not provide the O(expiration) parameter, the token expires in
        one year.
    type: str
  state:
    description:
      - If V(absent), then the module deletes the tokens that match both the
        O(name) and the O(role) parameters. You cannot use a deleted token
        anymore for authenticating with the API.
      - The module does not fail if the token does not exist, because the
        state is already as expected.
      - If V(present), then the module creates the token if it does not
        already exist. The module returns the token string that you can use for
        authenticating with the API.
      - If the token already exists, then the module returns the token details,
        except the token string, which cannot be retrieved after the initial
        token creation.
    type: str
    default: present
    choices: [absent, present]
notes:
  - Several tokens can have the same name. The module uses the O(name) and
    O(role) parameters to uniquely identify tokens.
  - You cannot retrieve the token value again after its initial creation.
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
- name: Generate an API token
  herve4m.rhacs_configuration.rhacs_api_token:
    name: my_token
    role: Vulnerability Management Approver
    expiration: "2025-10-30T21:06:00Z"
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
  register: token_details

- name: Display the new API token
  ansible.builtin.debug:
    msg: "The API token is: {{ token_details['token'] }}"
  # If the `my_token' token already exists, then the `token' return value is
  # not defined, because you cannot retrieve the token after its initial
  # creation.
  when: "'token' in token_details"

- name: Ensure the API token is removed
  herve4m.rhacs_configuration.rhacs_api_token:
    # The name and role parameters must match the token to delete
    name: my_token
    role: Vulnerability Management Approver
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
token:
  description:
    - The token string that you can use for authenticating with the API.
    - When the API token already exists, the RV(token) return value is not
      defined, because the token cannot be retrieved after its initial
      creation.
  type: str
  returned: only when the token is created
  sample: eyJh....tfQI
name:
  description: The name of the token.
  type: str
  returned: always
  sample: my_token
role:
  description: The role associated with the token.
  type: str
  returned: always
  sample: Vulnerability Management Approver
expiration:
  description: The date and time at which the token becomes invalid.
  type: str
  returned: always
  sample: "2025-10-30T21:06:00Z"
issuedAt:
  description: The date and time at which the token was created.
  type: str
  returned: always
  sample: "2024-09-12T12:13:59Z"
id:
  description: Internal identifier of the token.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
revoked:
  description:
    - Token are not deleted, but instead they are revoked.
    - You cannot use revoked tokens anymore for authenticating with the API.
    - The RV(revoked) return value is always V(false), because the module does
      not consider revoked tokens.
  type: bool
  returned: always
  sample: false
 """

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        name=dict(required=True),
        role=dict(default="Admin"),
        state=dict(choices=["present", "absent"], default="present"),
        expiration=dict(),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    role = module.params.get("role")
    state = module.params.get("state")
    expiration = module.params.get("expiration")

    # Retrieve the existing token
    #
    # GET /v1/apitokens?revoked=false
    # {
    #   "tokens": [
    #     {
    #       "id": "0a07385c-7cdc-49a6-aba5-fe2b0387d4e1",
    #       "name": "pipelines-ci-token",
    #       "roles": [
    #         "Admin"
    #       ],
    #       "issuedAt": "2024-09-12T07:59:54Z",
    #       "expiration": "2025-09-12T07:59:54Z",
    #       "revoked": false,
    #       "role": "Admin"
    #     },
    #     {
    #       "id": "862ba387-230e-4a27-929d-ac48fa3e4916",
    #       "name": "mytest",
    #       "roles": [
    #         "Continuous Integration"
    #       ],
    #       "issuedAt": "2024-09-12T09:54:21Z",
    #       "expiration": "2025-09-12T09:54:21Z",
    #       "revoked": false,
    #       "role": "Continuous Integration"
    #     },
    #     {
    #       "id": "1012861d-e7fb-4d60-9492-3b891f54bfc0",
    #       "name": "mytest",
    #       "roles": [
    #         "Continuous Integration"
    #       ],
    #       "issuedAt": "2024-09-12T09:54:54Z",
    #       "expiration": "2025-09-12T09:54:54Z",
    #       "revoked": false,
    #       "role": "Continuous Integration"
    #     }
    #   ]
    # }

    t = module.get_object_path("/v1/apitokens", query_params={"revoked": False})

    # Retrieve the tokens that match the provided parameters
    tokens = []
    for token in t.get("tokens", []):
        token_role = token.get("roles", [])
        if name == token.get("name") and len(token_role) == 1 and role == token_role[0]:
            tokens.append(token)

    # Revoke the tokens
    if state == "absent":
        if not tokens:
            module.exit_json(changed=False)
        for token in tokens:
            module.patch(
                "API token", name, "/v1/apitokens/revoke/{id}".format(id=token["id"])
            )
        module.exit_json(changed=True)

    if tokens:
        result = {"changed": False}
        # Only return the first matching token
        result.update(tokens[0])
        module.exit_json(**result)

    new_fields = {"name": name, "roles": [role]}
    if expiration:
        new_fields["expiration"] = expiration

    token = module.create(
        "API token", name, "/v1/apitokens/generate", new_fields, auto_exit=False
    )
    result = {"changed": True, "token": token.get("token", "")}
    result.update(token.get("metadata", {}))
    module.exit_json(**result)


if __name__ == "__main__":
    main()
