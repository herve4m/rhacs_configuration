#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_policy_export
short_description: Export security policies
description: Export security policies.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  policies:
    description:
      - List of the policies to export.
      - You can specify policies by their names or their identifiers.
    type: list
    elements: str
  ignore_missing:
    description:
      - Export the policies even if some of the policies listed in the
        O(policies) parameter do not exist.
      - If O(ignore_missing=true), then the module exports the existing
        policies, and ignore the policies that do not exist.
      - If O(ignore_missing=false) and some policies do not exist, then the
        module returns an error.
    default: false
    type: bool
notes:
  - See the M(herve4m.rhacs_configuration.rhacs_policy_import) module to
    import previously exported security policies.
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
- name: Ensure some policies are exported
  herve4m.rhacs_configuration.rhacs_policy_export:
    policies:
      - ADD Command used instead of COPY
      - "80267b36-2182-4fb3-8b53-e80c031f4ad8"
      - Curl in Image
    # Ignore non-existing policies
    ignore_missing: true
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
  register: exp

- name: Save the export into a file
  ansible.builtin.copy:
    content: "{{ exp['export'] }}"
    dest: /etc/RHACS/exports/exported_policies.json
    mode: '0600'
"""

RETURN = r"""
export:
  description:
    - The exported security policies in JSON format.
    - Use the M(ansible.builtin.copy) module to save the export into a file,
      for example.
  type: raw
  returned: changed
  sample: '{"policies": [ {...}, {...}, ...]}'
"""

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        policies=dict(type="list", elements="str"),
        ignore_missing=dict(type="bool", default=False),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    policies = module.params.get("policies")
    ignore_missing = module.params.get("ignore_missing")

    if not policies:
        module.exit_json(changed=False)

    ids = []
    unknown_policies = []
    for pol_name_or_id in policies:
        policy_obj = module.get_policy(pol_name_or_id)
        if policy_obj:
            ids.append(policy_obj.get("id"))
        else:
            unknown_policies.append(pol_name_or_id)
    if unknown_policies and not ignore_missing:
        module.fail_json(
            msg="some policies in `policies' do not exist: {pols}".format(
                pols=", ".join(unknown_policies)
            )
        )

    if not ids:
        module.exit_json(changed=False)

    ret = module.create(
        "security policy",
        "export",
        "/v1/policies/export",
        {"policyIds": ids},
        auto_exit=False,
    )
    module.exit_json(changed=True, export=ret)


if __name__ == "__main__":
    main()
