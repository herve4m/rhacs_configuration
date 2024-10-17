#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_policy_import
short_description: Import security policies
description: Import security policies.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  data:
    description:
      - Previously exported security polices to import.
      - You can use the P(ansible.builtin.file#lookup) lookup plugin
        to read a file from the system.
      - See the M(herve4m.rhacs_configuration.rhacs_policy_export) module to
        export security policies.
    type: jsonarg
    required: true
  ignore_import_errors:
    description:
      - Whether to fail when some security policies fail to import.
      - If O(ignore_import_errors=true), then the module imports the policies,
        but ignore the import errors. The list of the security policies that
        fail to import is available in the RV(error_details) and
        RV(error_message) return values.
      - If O(ignore_import_errors=false) and some imports fail, then the
        module returns an error.
    default: false
    type: bool
  overwrite:
    description:
      - Overwrite the security policies that might already exist.
      - You can overwrite only user generated security policies, and not system
        policies.
    default: false
    type: bool
notes:
  - See the M(herve4m.rhacs_configuration.rhacs_policy_export) module to
    export security policies.
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
- name: Ensure the previously exported security policies are imported
  herve4m.rhacs_configuration.rhacs_policy_import:
    data: "{{ lookup('ansible.builtin.file',
      '/etc/RHACS/exports/exported_policies.json') }}"
    ignore_import_errors: true
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
  register: imports

- name: Display the import error message
  ansible.builtin.debug:
    var: "imports['error_message']"
  when: "imports['error'] > 0"
"""

RETURN = r"""
success:
  description: Number of successfully imported security policies.
  type: int
  returned: always
  sample: 1
error:
  description: Number of failed security policy imports.
  type: int
  returned: always
  sample: 2
error_message:
  description: Error message.
  type: str
  returned: when RV(error) is not V(0).
  sample: "import failed for some security policies: Drop All Capabilities
    (duplicate_system_policy_name, duplicate_system_policy_id),
    My policy (duplicate_name)"
error_details:
  description: List of the security policies that failed to import.
  type: list
  elements: dict
  returned: when RV(error) is not V(0).
  contains:
    policy_name:
      description: Name of the security policy that failed to import.
      type: str
      returned: when RV(error) is not V(0).
      sample: Drop All Capabilities
    error:
      description: Type of the error.
      type: str
      returned: when RV(error) is not V(0).
      sample:
        - duplicate_id
        - duplicate_name
        - duplicate_system_policy_id
        - duplicate_system_policy_name
"""

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        data=dict(required=True, type="jsonarg"),
        ignore_import_errors=dict(type="bool", default=False),
        overwrite=dict(type="bool", default=False),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    data = module.params.get("data")
    ignore_import_errors = module.params.get("ignore_import_errors")
    overwrite = module.params.get("overwrite")

    if not data:
        module.exit_json(changed=False, success=0, error=0)

    data = module.from_json(data)
    data["metadata"] = {"overwrite": overwrite}

    ret = module.create(
        "security policy",
        "import",
        "/v1/policies/import",
        data,
        auto_exit=False,
    )
    if ret.get("allSucceeded"):
        if ret.get("responses"):
            module.exit_json(changed=True, success=len(ret.get("responses")), error=0)
        else:
            module.exit_json(changed=False, success=0, error=0)
    error_policies = []
    error_messages = []
    succeeded = failed = 0
    for r in ret.get("responses", []):
        if not r.get("succeeded", False):
            policy_name = r.get("policy", {}).get("name", "")
            errors = [err.get("type", "") for err in r.get("errors", [])]
            error_policies.append(
                {
                    "policy_name": policy_name,
                    "error": ", ".join(errors),
                }
            )
            error_messages.append(
                "{name} ({err})".format(name=policy_name, err=", ".join(errors))
            )
            failed += 1
        else:
            succeeded += 1
    error_message = "import failed for some security policies: {err}".format(
        err=", ".join(error_messages)
    )
    if not ignore_import_errors:
        module.fail_json(msg=error_message)
    result = {
        "changed": True if succeeded else False,
        "success": succeeded,
        "error": failed,
        "error_details": error_policies,
        "error_message": error_message,
    }
    module.exit_json(**result)


if __name__ == "__main__":
    main()
