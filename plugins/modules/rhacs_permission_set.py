#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_permission_set
short_description: Manage permission sets
description:
  - Create, delete, and rename permission sets.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description: Name of the permission set.
    required: true
    type: str
  new_name:
    description:
      - New name for the permission set.
      - Setting this option changes the name of the permission set, which
        current name is provided in the O(name) parameter.
      - The module returns an error if the destination permission set already
        exists.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  description:
    description: Optional description for the permission set.
    type: str
  resource_accesses:
    description: Set of permissions
    type: dict
    suboptions:
      Access:
        description:
          - V(READ_ACCESS) - View the configuration for authentication and
            authorization, such as authentication services, roles, groups, and
            users.
          - V(READ_WRITE_ACCESS) - Modify the configuration for authentication
            and authorization.
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Administration:
        description:
          - V(READ_ACCESS) - View the platform configuration, such as network
            graph, sensor, and debugging configurations.
          - V(READ_WRITE_ACCESS) - Modify the platform configuration.
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Alert:
        description:
          - V(READ_ACCESS) - View policy violations.
          - V(READ_WRITE_ACCESS) - Resolve or edit policy violations.
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      CVE:
        description: Internal use only. V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Cluster:
        description:
          - V(READ_ACCESS) - View the secured clusters.
          - V(READ_WRITE_ACCESS) - Add, modify, or delete the secured clusters.
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Compliance:
        description:
          - V(READ_ACCESS) - View compliance standards, results, and runs.
          - V(READ_WRITE_ACCESS) - Add, modify, or delete scheduled compliance
            runs.
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Deployment:
        description:
          - V(READ_ACCESS) - View deployments (workloads) in secured clusters.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      DeploymentExtension:
        description:
          - V(READ_ACCESS) - View network, process listening on ports,
            process baseline extensions, and risk score of deployments.
          - V(READ_WRITE_ACCESS) - Modify the process, process listening on
            ports, and network baseline extensions of deployments.
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Detection:
        description:
          - V(READ_ACCESS) - Verify build-time policies against images or
            deployment YAML resources.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Image:
        description:
          - V(READ_ACCESS) - View images, their components, and their
            vulnerabilities.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Integration:
        description:
          - V(READ_ACCESS) - View integrations and their configuration. This
            includes backup, registry, image signature, notification systems,
            and API tokens.
          - V(READ_WRITE_ACCESS) - Add, modify, delete integrations, and API
            tokens.
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      K8sRole:
        description:
          - V(READ_ACCESS) - View roles for Kubernetes role-based access
            control in secured clusters.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      K8sRoleBinding:
        description:
          - V(READ_ACCESS) - View role bindings for Kubernetes role-based
            access control in secured clusters.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      K8sSubject:
        description:
          - V(READ_ACCESS) - View users and groups for Kubernetes role-based
            access control in secured clusters.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Namespace:
        description:
          - V(READ_ACCESS) - View Kubernetes namespaces in secured clusters.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      NetworkGraph:
        description:
          - V(READ_ACCESS) - View active and allowed network connections in
            secured clusters.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      NetworkPolicy:
        description:
          - V(READ_ACCESS) - View network policies in secured clusters, and
            simulate changes.
          - V(READ_WRITE_ACCESS) - Apply network policy changes in secured
            clusters.
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Node:
        description:
          - V(READ_ACCESS) - View Kubernetes nodes in secured clusters.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      Secret:
        description:
          - V(READ_ACCESS) - View metadata about secrets in secured clusters.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      ServiceAccount:
        description:
          - V(READ_ACCESS) - List Kubernetes service accounts in secured
            clusters.
          - V(READ_WRITE_ACCESS) - Not applicable
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      VulnerabilityManagementApprovals:
        description:
          - V(READ_ACCESS) - View all pending deferral or false positive
            requests for vulnerabilities.
          - V(READ_WRITE_ACCESS) - Approve or deny any pending deferral or
            false positive requests, and move any previously approved requests
            back to observed.
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      VulnerabilityManagementRequests:
        description:
          - V(READ_ACCESS) - View all pending deferral or false positive
            requests for vulnerabilities.
          - V(READ_WRITE_ACCESS) - Request a deferral on a vulnerability, mark
            it as a false positive, or move a pending or previously approved
            request (made by the same user) back to observed.
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      WatchedImage:
        description:
          - V(READ_ACCESS) - View undeployed watched images monitored.
          - V(READ_WRITE_ACCESS) - Configure watched images.
          - V(NO_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
      WorkflowAdministration:
        description:
          - V(READ_ACCESS) - View collections, vulnerability reports, policies,
            and policy categories.
          - V(READ_WRITE_ACCESS) - Add, modify, or delete collections,
            vulnerability reports, policies, and policy categories.
          - V(READ_ACCESS) by default.
        type: str
        choices:
          - NO_ACCESS
          - READ_ACCESS
          - READ_WRITE_ACCESS
  state:
    description:
      - If V(absent), then the module deletes the permission set.
      - The module does not fail if the permission set does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the permission set if it does
        not already exist.
      - If the permission set already exists, then the module updates its
        state, and renames the set if you provide the O(new_name) parameter.
    type: str
    default: present
    choices: [absent, present]
notes:
  - You cannot update or delete the default permission sets.
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
- name: Ensure the management view permission set exists
  herve4m.rhacs_configuration.rhacs_permission_set:
    name: Management View
    description: Provides a read access to managers
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

- name: Removes the access to the CVE resources
  herve4m.rhacs_configuration.rhacs_permission_set:
    name: Management View
    resource_accesses:
      CVE: NO_ACCESS
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the management view permission set is removed
  herve4m.rhacs_configuration.rhacs_permission_set:
    name: Management View
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the permission set.
  type: str
  returned: always
  sample: 763fd7f0-3095-48e4-a3fd-d85706172e49
"""

import copy

from ..module_utils.api_module import APIModule

resources_default_accesses = {
    "Access": "NO_ACCESS",
    "Administration": "READ_ACCESS",
    "Alert": "READ_ACCESS",
    "CVE": "NO_ACCESS",
    "Cluster": "READ_ACCESS",
    "Compliance": "NO_ACCESS",
    "Deployment": "READ_ACCESS",
    "DeploymentExtension": "NO_ACCESS",
    "Detection": "NO_ACCESS",
    "Image": "READ_ACCESS",
    "Integration": "NO_ACCESS",
    "K8sRole": "NO_ACCESS",
    "K8sRoleBinding": "NO_ACCESS",
    "K8sSubject": "NO_ACCESS",
    "Namespace": "READ_ACCESS",
    "NetworkGraph": "READ_ACCESS",
    "NetworkPolicy": "READ_ACCESS",
    "Node": "READ_ACCESS",
    "Secret": "READ_ACCESS",
    "ServiceAccount": "NO_ACCESS",
    "VulnerabilityManagementApprovals": "NO_ACCESS",
    "VulnerabilityManagementRequests": "NO_ACCESS",
    "WatchedImage": "NO_ACCESS",
    "WorkflowAdministration": "READ_ACCESS",
}


def main():

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        description=dict(),
        resource_accesses=dict(
            type="dict",
            options=dict(
                [
                    (res, dict(choices=["NO_ACCESS", "READ_ACCESS", "READ_WRITE_ACCESS"]))
                    for res in resources_default_accesses
                ]
            ),
        ),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    new_name = module.params.get("new_name")
    description = module.params.get("description")
    resource_accesses = module.params.get("resource_accesses")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the existing permission sets
    #
    # GET /v1/permissionsets
    # {
    #   "permissionSets": [
    #     {
    #       "id": "ffffffff-ffff-fff4-f5ff-ffffffffffff",
    #       "name": "Admin",
    #       "description": "For users: provide read and write access to all the resources",
    #       "resourceToAccess": {
    #         "Access": "READ_WRITE_ACCESS",
    #         "Administration": "READ_WRITE_ACCESS",
    #         "Alert": "READ_WRITE_ACCESS",
    #         "CVE": "READ_WRITE_ACCESS",
    #         "Cluster": "READ_WRITE_ACCESS",
    #         "Compliance": "READ_WRITE_ACCESS",
    #         "Deployment": "READ_WRITE_ACCESS",
    #         "DeploymentExtension": "READ_WRITE_ACCESS",
    #         "Detection": "READ_WRITE_ACCESS",
    #         "Image": "READ_WRITE_ACCESS",
    #         "Integration": "READ_WRITE_ACCESS",
    #         "K8sRole": "READ_WRITE_ACCESS",
    #         "K8sRoleBinding": "READ_WRITE_ACCESS",
    #         "K8sSubject": "READ_WRITE_ACCESS",
    #         "Namespace": "READ_WRITE_ACCESS",
    #         "NetworkGraph": "READ_WRITE_ACCESS",
    #         "NetworkPolicy": "READ_WRITE_ACCESS",
    #         "Node": "READ_WRITE_ACCESS",
    #         "Secret": "READ_WRITE_ACCESS",
    #         "ServiceAccount": "READ_WRITE_ACCESS",
    #         "VulnerabilityManagementApprovals": "READ_WRITE_ACCESS",
    #         "VulnerabilityManagementRequests": "READ_WRITE_ACCESS",
    #         "WatchedImage": "READ_WRITE_ACCESS",
    #         "WorkflowAdministration": "READ_WRITE_ACCESS"
    #       },
    #       "traits": {
    #         "mutabilityMode": "ALLOW_MUTATE",
    #         "visibility": "VISIBLE",
    #         "origin": "DEFAULT"
    #       }
    #     },
    #     {
    #       "id": "7c855498-4ac5-422d-a37d-b8497c6f291c",
    #       "name": "default",
    #       "description": "",
    #       "resourceToAccess": {
    #         "Access": "NO_ACCESS",
    #         "Administration": "READ_ACCESS",
    #         "Alert": "READ_ACCESS",
    #         "CVE": "NO_ACCESS",
    #         "Cluster": "READ_ACCESS",
    #         "Compliance": "NO_ACCESS",
    #         "Deployment": "READ_ACCESS",
    #         "DeploymentExtension": "NO_ACCESS",
    #         "Detection": "NO_ACCESS",
    #         "Image": "READ_ACCESS",
    #         "Integration": "NO_ACCESS",
    #         "K8sRole": "NO_ACCESS",
    #         "K8sRoleBinding": "NO_ACCESS",
    #         "K8sSubject": "NO_ACCESS",
    #         "Namespace": "READ_ACCESS",
    #         "NetworkGraph": "READ_ACCESS",
    #         "NetworkPolicy": "READ_ACCESS",
    #         "Node": "READ_ACCESS",
    #         "Secret": "READ_ACCESS",
    #         "ServiceAccount": "NO_ACCESS",
    #         "VulnerabilityManagementApprovals": "NO_ACCESS",
    #         "VulnerabilityManagementRequests": "NO_ACCESS",
    #         "WatchedImage": "NO_ACCESS",
    #         "WorkflowAdministration": "READ_ACCESS"
    #       },
    #       "traits": null
    #     }
    #   ]
    # }

    c = module.get_object_path("/v1/permissionsets")
    permissionsets = c.get("permissionSets", [])

    # Retrieve the objects for the given names
    config = module.get_item_from_resource_list(name, permissionsets)
    new_config = module.get_item_from_resource_list(new_name, permissionsets)

    # Remove the object. For delete operations, the new_name parameter is
    # ignored.
    if state == "absent":
        if not config:
            module.exit_json(changed=False)
        if config.get("traits") and config.get("traits").get("origin") == "DEFAULT":
            module.fail_json(
                msg="you cannot delete default permission sets: {c}".format(c=name)
            )
        module.delete(
            config,
            "permission set",
            name,
            "/v1/permissionsets/{id}".format(id=config.get("id", "")),
        )

    # Create the object
    if not config and not new_config:
        name = new_name if new_name else name
        pset = resources_default_accesses.copy()
        if resource_accesses:
            pset.update(resource_accesses)
        new_fields = {
            "name": name,
            "description": description if description else "",
            "resourceToAccess": pset,
        }
        resp = module.create(
            "permission set", name, "/v1/permissionsets", new_fields, auto_exit=False
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    if not config and new_config:
        config = new_config
        name = new_name
        new_config = new_name = None

    # The permission set with the new name already exists
    if new_config:
        module.fail_json(
            msg="the destination permission set (`new_name') already exists: {name}".format(
                name=new_name
            )
        )

    if config.get("traits") and config.get("traits").get("origin") == "DEFAULT":
        module.fail_json(msg="you cannot update default permission sets: {c}".format(c=name))

    curr_access = dict([(key, "NO_ACCESS") for key in resources_default_accesses])
    curr_access.update(config.get("resourceToAccess", {}))
    req_access = curr_access.copy()
    if resource_accesses:
        req_access.update(dict([(key, val) for key, val in resource_accesses.items() if val]))

    if (
        not new_name
        and (description is None or description == config.get("description"))
        and curr_access == req_access
    ):
        module.exit_json(changed=False, id=config.get("id", ""))

    new_fields = copy.deepcopy(config)
    if new_name:
        new_fields["name"] = new_name
    if description is not None:
        new_fields["description"] = description
    new_fields["resourceToAccess"] = req_access

    id = config.get("id", "")
    module.unconditional_update(
        "permission set",
        new_name,
        "/v1/permissionsets/{id}".format(id=id),
        new_fields,
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
