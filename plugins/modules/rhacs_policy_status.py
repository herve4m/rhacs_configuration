#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_policy_status
short_description: Enable or disable policies
description: Enable or disable security policies.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  enable:
    description:
      - Whether to enable or disable the security policies listed in the
        O(policies) parameter.
    required: true
    type: bool
  policies:
    description:
      - List of the policies to enable or disable.
      - You can specify policies by their names or their identifiers.
    type: list
    elements: str
  ignore_missing:
    description:
      - Whether to skip the security policies that do not exist in the
        O(policies) parameter.
      - If O(ignore_missing=true), then the module changes the status of the
        existing policies, and ignore the policies that do not exist.
      - If O(ignore_missing=false) and some policies do not exist, then the
        module does not perform any change, and returns an error.
    default: false
    type: bool
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
- name: Ensure some security policies are enabled
  herve4m.rhacs_configuration.rhacs_policy_status:
    enable: true
    policies:
      - ADD Command used instead of COPY
      - "80267b36-2182-4fb3-8b53-e80c031f4ad8"
      - Curl in Image
    # Skip non-existing policies
    ignore_missing: true
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r""" # """

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        enable=dict(required=True, type="bool"),
        policies=dict(type="list", elements="str"),
        ignore_missing=dict(type="bool", default=False),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    enable = module.params.get("enable")
    policies = module.params.get("policies")
    ignore_missing = module.params.get("ignore_missing")

    if not policies:
        module.exit_json(changed=False)

    ids = []
    unknown_policies = []
    for pol_name_or_id in policies:
        policy_obj = module.get_policy(pol_name_or_id)
        if policy_obj:
            if policy_obj.get("disabled") == enable:
                ids.append([policy_obj.get("id"), pol_name_or_id])
        else:
            unknown_policies.append(pol_name_or_id)
    if unknown_policies and not ignore_missing and enable is True:
        module.fail_json(
            msg="some policies in `policies' do not exist: {pols}".format(
                pols=", ".join(unknown_policies)
            )
        )

    if not ids:
        module.exit_json(changed=False)

    for id in ids:
        module.patch(
            "security policy",
            id[1],
            "/v1/policies/{i}".format(i=id[0]),
            {"disabled": not enable},
        )
    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
