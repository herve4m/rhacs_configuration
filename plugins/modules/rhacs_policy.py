#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_policy
short_description: Manage security policies
description: Create, delete, and update security policies.
version_added: '1.3.0'
author: Hervé Quatremain (@herve4m)
options:
  policy:
    description:
      - Name or identifier of the security policy to manage.
      - The policy name defined in the O(data) parameter overwites the name
        that you define with the O(policy) parameter.
    required: true
    type: str
  data:
    description:
      - Security policy structure in JSON format.
      - You can use the P(ansible.builtin.file#lookup) lookup plugin
        to read the file from the system.
      - Required only when O(state=present).
    type: jsonarg
  state:
    description:
      - If V(absent), then the module deletes the security policy.
      - The module does not fail if the security policy does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the security policy if it does
        not already exist.
      - If the security policy already exists, then the module updates its
        state, and renames the collection if you provide the
        O(new_name) parameter.
    type: str
    default: present
    choices: [absent, present]
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
- name: Ensure a security policy exists to verify image ages
  herve4m.rhacs_configuration.rhacs_policy:
    policy: Verify old images
    data: "{{ lookup('ansible.builtin.file', '120-days.json') }}"
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure a security policy exists to verify the ADD command in Dockerfile
  herve4m.rhacs_configuration.rhacs_policy:
    policy: COPY instead of ADD
    data:
      # The previous "policy" parameter differs from the following "name"
      # parameter.
      # If the policy does not exist, then "name" is used for the name ("name"
      # overwrites "policy").
      # If a policy with a name "COPY instead of ADD" exists, then it is
      # renamed in "Use COPY instead of ADD in Dockerfile".
      name: Use COPY instead of ADD in Dockerfile
      description: Alert on deployments using an ADD command
      rationale: >
        ADD incorporates a broader set of capabilities than COPY, including the
        ability to specify URLs as the source argument and automatic unpacking
        of compressed files onto the local filesystem. The effects of ADD can
        be unpredictable and can lead to larger images. Unless ADD's additional
        capabilities are required, COPY is recommended.
      remediation: >
        Replace ADD with COPY when adding new files to the image. It is better
        to use RUN curl instead of ADD if you need to access a URL.
      disabled: true
      categories:
        - DevOps Best Practices
        - Docker CIS
      lifecycleStages:
        - BUILD
        - DEPLOY
      eventSource: NOT_APPLICABLE
      severity: LOW_SEVERITY
      policySections:
        - policyGroups:
            - fieldName: Dockerfile Line
              booleanOperator: OR
              values:
                - value: "ADD=.*"
      criteriaLocked: false
      mitreVectorsLocked: false
      isDefault: false
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
  register: pol

- name: Ensure the security policy that verifies the ADD command is removed
  herve4m.rhacs_configuration.rhacs_policy:
    # Specifying the security policy by its ID
    policy: "{{ pol['id'] }}"
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the security policy.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

from ..module_utils.api_module import APIModule


def diff_dict(t1, t2):
    for k in t1:
        if k not in t2 or not are_same(t1[k], t2[k]):
            return False
    return True


def diff_list(t1, t2):
    if len(t1) != len(t2):
        return False
    for i1 in t1:
        for i2 in t2:
            if are_same(i1, i2):
                break
        else:
            return False
    return True


def are_same(t1, t2):
    """Deep compare two structures.

    All the variables in the ``t1`` structure must be in ``t2``.
    However, variables in ``t2`` not in ``t1`` are ignored.
    """
    # flake8 E721 "do not compare types"
    # if type(t1) != type(t2):
    if not isinstance(t1, type(t2)):
        return False

    if isinstance(t1, (list, tuple)):
        return diff_list(t1, t2)
    if isinstance(t1, dict):
        return diff_dict(t1, t2)
    return t1 == t2


def main():

    argument_spec = dict(
        policy=dict(required=True, aliases=["src"]),
        data=dict(type="jsonarg"),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(
        argument_spec=argument_spec,
        required_if=[("state", "present", ["data"])],
        supports_check_mode=True,
    )

    # Extract our parameters
    policy = module.params.get("policy")
    data = module.params.get("data")
    state = module.params.get("state")

    policy_obj = module.get_policy(policy)
    id = policy_obj.get("id", "") if policy_obj else ""

    # Remove the security policy
    if state == "absent":
        if not policy_obj:
            module.exit_json(changed=False)
        if policy_obj.get("isDefault"):
            module.fail_json(
                msg="you cannot delete system (default) policies: {pol}".format(pol=policy)
            )
        module.delete(
            policy_obj, "security policy", policy, "/v1/policies/{id}".format(id=id)
        )

    data = module.from_json(data)
    data["id"] = id

    # YAML resource files use the "policyName" option for the policy name, but
    # the RHACS API use "name"
    if "policyName" in data:
        data["name"] = data.pop("policyName")

    # Create the policy
    if not policy_obj:
        resp = module.create(
            "security policy", data.get("name", policy), "/v1/policies", data, auto_exit=False
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    # Verify whether an update is required
    data.pop("lastUpdated", None)
    if are_same(data, policy_obj):
        module.exit_json(changed=False, id=id)

    module.unconditional_update(
        "security policy", data.get("name", policy), "/v1/policies/{id}".format(id=id), data
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
