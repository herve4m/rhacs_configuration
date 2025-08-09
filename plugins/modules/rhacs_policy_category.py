#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, 2025 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_policy_category
short_description: Manage policy categories
description:
  - Create, delete, and rename policy categories.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description:
      - Name of the policy category.
      - The name is case insensitive.
    required: true
    type: str
  new_name:
    description:
      - New name for the policy category.
      - Setting this option changes the name of the category, which current
        name is provided in the O(name) parameter.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  state:
    description:
      - If V(absent), then the module deletes the category.
      - The module does not fail if the category does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the category if it does not
        already exist.
      - If the category already exists, then the module renames it if
        you provided the O(new_name) parameter. Otherwise, the category is not
        changed.
    type: str
    default: present
    choices: [absent, present]
notes:
  - You cannot update or delete the default policy categories.
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
- name: Ensure the OS Tools policy category exists
  herve4m.rhacs_configuration.rhacs_policy_category:
    name: OS Tools
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the OS Tools policy category is renamed
  herve4m.rhacs_configuration.rhacs_policy_category:
    name: OS Tools
    new_name: System Tools
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the System Tools policy category is removed
  herve4m.rhacs_configuration.rhacs_policy_category:
    name: System Tools
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the policy category configuration.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    new_name = module.params.get("new_name")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the existing policy categories
    #
    # GET /v1/policycategories
    # {
    #   "categories": [
    #     {
    #       "id": "1cf56ef4-2669-4bcd-928c-cae178e5873f",
    #       "name": "Anomalous Activity",
    #       "isDefault": true
    #     },
    #     {
    #       "id": "0683afb2-5890-4749-a119-adec5d9d895e",
    #       "name": "System Tools",
    #       "isDefault": false
    #     },
    #     {
    #       "id": "a1245e73-00b8-422c-a2c5-cac95d87cc4e",
    #       "name": "Cryptocurrency Mining",
    #       "isDefault": true
    #     },
    #     ...
    #   ]
    # }

    c = module.get_object_path(
        "/v1/policycategories", query_params={"pagination.limit": 10000}
    )
    categories = c.get("categories", [])

    # Retrieve the objects for the given names
    config = module.get_item_from_resource_list(name, categories, case_sensitive=False)
    new_config = module.get_item_from_resource_list(
        new_name, categories, case_sensitive=False
    )

    # Remove the object. For delete operations, the new_name parameter is
    # ignored.
    if state == "absent":
        if not config:
            module.exit_json(changed=False)
        if config.get("isDefault"):
            module.fail_json(
                msg="you cannot delete default policy categories: {c}".format(c=name)
            )
        module.delete(
            config,
            "policy category",
            name,
            "/v1/policycategories/{id}".format(id=config.get("id", "")),
        )

    # Create the object
    if not config and not new_config:
        name = new_name if new_name else name
        new_fields = {"name": name, "isDefault": False}
        resp = module.create(
            "policy category", name, "/v1/policycategories", new_fields, auto_exit=False
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    # The object has already been renamed
    if not config and new_config:
        module.exit_json(changed=False, id=new_config.get("id", ""))

    id = config.get("id", "")

    # The the renamed object already exists: delete the source object
    if new_config:
        if config.get("isDefault"):
            module.fail_json(
                msg="you cannot delete or rename default policy categories: {c}".format(
                    c=name
                )
            )
        module.delete(
            config,
            "policy category",
            name,
            "/v1/policycategories/{id}".format(id=config.get("id", "")),
            auto_exit=False,
        )
        module.exit_json(changed=True, id=id)

    # No rename required
    if not new_name:
        module.exit_json(changed=False, id=id)

    # Rename the object
    if config.get("isDefault"):
        module.fail_json(
            msg="you cannot rename default policy categories: {c}".format(c=name)
        )
    new_fields = {"id": id, "newCategoryName": new_name}
    module.unconditional_update(
        "policy category", new_name, "/v1/policycategories", new_fields
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
