#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_policy_notifier
short_description: Associate notifiers to policies
description: Associate notifiers to security policies.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  notifiers:
    description:
      - List of the notifiers to associate to the security policies given in
        the O(policies) parameter.
      - If the O(notifiers) parameter is an empty list (V([])), then the
        module removes all the notifiers from the security policies.
      - You can specify notifiers by their names or their identifiers.
      - See the M(herve4m.rhacs_configuration.rhacs_notifier_integration)
        module to manage notifier integrations.
    type: list
    elements: str
    required: true
  policies:
    description:
      - List of policies.
      - You can specify policies by their names or their identifiers.
    type: list
    elements: str
  ignore_missing:
    description:
      - Whether to skip the security policies that do not exist in the
        O(policies) parameter.
      - If O(ignore_missing=true), then the module associates the notifiers to
        the existing policies, and ignore the policies that do not exist.
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
- name: Ensure the Splunk notifier is associated with security policies
  herve4m.rhacs_configuration.rhacs_policy_notifier:
    notifiers:
      - Splunk notifications
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
        notifiers=dict(required=True, type="list", elements="str"),
        policies=dict(type="list", elements="str"),
        ignore_missing=dict(type="bool", default=False),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    notifiers = module.params.get("notifiers")
    policies = module.params.get("policies")
    ignore_missing = module.params.get("ignore_missing")

    if not policies:
        module.exit_json(changed=False)

    notifier_ids = set([module.get_notifier_id(id) for id in notifiers])
    policy_ids = []
    unknown_policies = []
    for pol_name_or_id in policies:
        policy_obj = module.get_policy(pol_name_or_id)
        if policy_obj:
            curr_notifiers = set(policy_obj.get("notifiers", []))
            if notifier_ids != curr_notifiers:
                policy_ids.append([policy_obj.get("id"), pol_name_or_id, curr_notifiers])
        else:
            unknown_policies.append(pol_name_or_id)
    if unknown_policies and not ignore_missing and notifier_ids:
        module.fail_json(
            msg="some policies in `policies' do not exist: {pols}".format(
                pols=", ".join(unknown_policies)
            )
        )

    if not policy_ids:
        module.exit_json(changed=False)

    for id in policy_ids:
        if notifier_ids:
            disable = False
            ids = list(notifier_ids)
        else:
            disable = True
            ids = list(id[2])
        module.patch(
            "security policy",
            id[1],
            "/v1/policies/{i}/notifiers".format(i=id[0]),
            {"notifierIds": ids, "disable": disable},
        )
    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
