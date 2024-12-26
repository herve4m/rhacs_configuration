#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_policy_clone
short_description: Clone security policies
description: Copie security policies.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  policy:
    description:
      - Name or identifier of the security policy to copy.
    required: true
    type: str
    aliases:
      - src
  clone_name:
    description:
      - Name of the copied policy.
      - If the policy already exists, then the module does not change anything.
        The module does not reconcile the destination policy if the two
        policies differ.
      - By default, the name of the copy is the source policy name with the
        C( (CLONE)) suffix.
    type: str
    aliases:
      - dest
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
- name: Ensure a copy of the ADD vs COPY security policy exists
  herve4m.rhacs_configuration.rhacs_policy_clone:
    policy: ADD Command used instead of COPY
    clone_name: My ADD vs COPY
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure a copy of the curl security policy exists
  herve4m.rhacs_configuration.rhacs_policy_clone:
    # Because the `clone_name' parameter is not provided, the name of the
    # cloned policy is `Curl in Image (COPY)'
    policy: Curl in Image
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure a copy of the drop capability security policy exists
  herve4m.rhacs_configuration.rhacs_policy_clone:
    # Specifying a security policy by its ID
    policy: "80267b36-2182-4fb3-8b53-e80c031f4ad8"
    clone_name: Copy of Drop All Capabilities
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the cloned security policy.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        policy=dict(required=True, aliases=["src"]),
        clone_name=dict(aliases=["dest"]),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    policy = module.params.get("policy")
    clone_name = module.params.get("clone_name")

    policy_obj = module.get_policy(policy)
    if not policy_obj:
        module.fail_json(msg="the policy does not exist: {pol}".format(pol=policy))

    if not clone_name:
        clone_name = policy_obj.get("name") + " (CLONE)"

    # Verify whether the destination policy exists
    clone_obj = module.get_policy(clone_name)
    if clone_obj:
        module.exit_json(changed=False, id=clone_obj.get("id", ""))

    # Retrieve the policy details
    policy_id = policy_obj.get("id")
    p = module.get_object_path("/v1/policies/{id}".format(id=policy_id))

    # Create the clone
    p["name"] = clone_name
    p["id"] = ""
    p["lastUpdated"] = None
    p["criteriaLocked"] = p["mitreVectorsLocked"] = p["isDefault"] = False
    resp = module.create("security policy", clone_name, "/v1/policies", p, auto_exit=False)
    module.exit_json(changed=True, id=resp.get("id", ""))


if __name__ == "__main__":
    main()
