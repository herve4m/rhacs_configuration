#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_role
short_description: Manage roles
description: Create, delete, and update roles for access control.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description: Name of the role.
    required: true
    type: str
  description:
    description: Optional description for the role.
    type: str
  permission_set:
    description:
      - Name or identifier of the permission set to associate with the role.
      - See the M(herve4m.rhacs_configuration.rhacs_permission_set) module for
        managing permission sets.
    type: str
  access_scope:
    description:
      - Name or identifier of the access scope to associate with the role.
      - See the M(herve4m.rhacs_configuration.rhacs_access_scope) module for
        managing access scopes.
    type: str
  state:
    description:
      - If V(absent), then the module deletes the role.
      - The module does not fail if the role does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the role if it does not
        already exist.
      - If the role already exists, then the module updates its state.
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
- name: Ensure the role for the managers exists
  herve4m.rhacs_configuration.rhacs_role:
    name: Manager role
    description: Role for the managers
    permission_set: Analyst
    access_scope: Unrestricted
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the role for the managers is removed
  herve4m.rhacs_configuration.rhacs_role:
    name: Manager role
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

# Create a permission set, and then create a role by using the ID of the new
# permission set.
- name: Ensure the developer view permission set exists
  herve4m.rhacs_configuration.rhacs_permission_set:
    name: Developer View
    description: Provides a read access to developers
    resource_accesses:
      Access: READ_ACCESS
      Administration: READ_ACCESS
      Alert: READ_ACCESS
      CVE: READ_ACCESS
      Cluster: READ_ACCESS
      Compliance: READ_ACCESS
      Deployment: READ_ACCESS
      DeploymentExtension: READ_ACCESS
      Detection: READ_ACCESS
      Image: READ_ACCESS
      Integration: READ_ACCESS
      K8sRole: READ_ACCESS
      K8sRoleBinding: READ_ACCESS
      K8sSubject: READ_ACCESS
      Namespace: READ_ACCESS
      NetworkGraph: READ_ACCESS
      NetworkPolicy: READ_ACCESS
      Node: READ_ACCESS
      Secret: READ_ACCESS
      ServiceAccount: READ_ACCESS
      VulnerabilityManagementApprovals: READ_ACCESS
      VulnerabilityManagementRequests: READ_ACCESS
      WatchedImage: READ_ACCESS
      WorkflowAdministration: READ_ACCESS
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
  register: pset

- name: Ensure the role for the development team exists
  herve4m.rhacs_configuration.rhacs_role:
    name: Dev role
    description: Role for the development team
    permission_set: "{{ pset['id'] }}"
    access_scope: Unrestricted
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r""" # """


import copy

from ansible.module_utils.six.moves.urllib.parse import quote
from ..module_utils.api_module import APIModule


def get_permission_set_id(module, name_or_id):
    if not name_or_id:
        return None

    c = module.get_object_path("/v1/permissionsets")
    return module.get_id_from_resource_list(
        name_or_id,
        c.get("permissionSets", []),
        error_msg="the permission set (in `permission_set') does not exist",
    )


def get_access_scope_id(module, name_or_id):
    if not name_or_id:
        return None

    c = module.get_object_path("/v1/simpleaccessscopes")
    return module.get_id_from_resource_list(
        name_or_id,
        c.get("accessScopes", []),
        error_msg="the access scope (`access_scope') does not exist",
    )


def main():

    argument_spec = dict(
        name=dict(required=True),
        description=dict(),
        permission_set=dict(),
        access_scope=dict(),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    description = module.params.get("description")
    permission_set = module.params.get("permission_set")
    access_scope = module.params.get("access_scope")
    state = module.params.get("state")

    # Retrieve the existing roles
    #
    # GET /v1/roles/{name}
    # {
    #   "name": "test",
    #   "description": "test",
    #   "permissionSetId": "ffffffff-ffff-fff4-f5ff-ffffffffffff",
    #   "accessScopeId": "ffffffff-ffff-fff4-f5ff-ffffffffffff",
    #   "globalAccess": "NO_ACCESS",
    #   "resourceToAccess": {},
    #   "traits": null
    # }

    config = module.get_object_path("/v1/roles/{name}".format(name=quote(name)))

    # Remove the role
    if state == "absent":
        if not config:
            module.exit_json(changed=False)
        if config.get("traits") and config.get("traits").get("origin") == "DEFAULT":
            module.fail_json(msg="you cannot delete default roles: {c}".format(c=name))
        module.delete(config, "role", name, "/v1/roles/{name}".format(name=quote(name)))

    # Create the role
    if not config:
        missing_args = []
        if not permission_set:
            missing_args.append("permission_set")
        if not access_scope:
            missing_args.append("access_scope")
        if missing_args:
            module.fail_json(
                msg="missing required arguments: {args}".format(args=", ".join(missing_args))
            )

        new_fields = {
            "name": name,
            "description": description if description else "",
            "permissionSetId": get_permission_set_id(module, permission_set),
            "accessScopeId": get_access_scope_id(module, access_scope),
            "resourceToAccess": {},
        }

        module.create(
            "role",
            name,
            "/v1/roles/{name}".format(name=quote(name)),
            new_fields,
        )

    permission_set_id = get_permission_set_id(module, permission_set)
    access_scope_id = get_access_scope_id(module, access_scope)
    if (
        (description is None or description == config.get("description"))
        and (not permission_set_id or permission_set_id == config.get("permissionSetId"))
        and (not access_scope_id or access_scope_id == config.get("accessScopeId"))
    ):
        module.exit_json(changed=False)

    if config.get("traits") and config.get("traits").get("origin") == "DEFAULT":
        module.fail_json(msg="you cannot update default roles: {c}".format(c=name))

    new_fields = copy.deepcopy(config)
    if description is not None:
        new_fields["description"] = description
    if permission_set_id:
        new_fields["permissionSetId"] = permission_set_id
    if access_scope_id:
        new_fields["accessScopeId"] = access_scope_id

    module.unconditional_update(
        "role", name, "/v1/roles/{name}".format(name=quote(name)), new_fields
    )
    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
