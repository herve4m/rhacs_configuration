#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_access_scope
short_description: Manage access scopes
description:
  - Create, delete, and rename access scopes.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description: Name of the access scope.
    required: true
    type: str
  new_name:
    description:
      - New name for the access scope.
      - Setting this option changes the name of the access scope, which
        current name is provided in the O(name) parameter.
      - The module returns an error if the destination access scope already
        exists.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  description:
    description: Optional description for the access scope.
    type: str
  rules:
    description:
      - Rules for the access scope.
      - If you omit the O(rules) parameter when creating an access scope, or
        if you set the parameter to an empty dictionary (V({})), then
        no rules are configured, and the access scope denies access to all
        clusters and namespaces.
    type: dict
    suboptions:
      clusters:
        description:
          - List of clusters to allow the access.
          - An empty list (V([])) denies the access to all the clusters, unless
            another rule in the O(rules.namespaces),
            O(rules.cluster_selectors), or O(rules.namespace_selectors)
            parameters grants the access.
          - You can list clusters that are not already configured in RHACS.
            Note that the access scope view in the RHACS portal does not
            display these clusters.
        type: list
        elements: str
      clusters_append:
        description:
          - If V(true), then the module adds the clusters listed in the
            O(rules.clusters) list to the existing list.
          - If V(false), then the module replaces the current list of clusters
            with the list from the O(rules.clusters) parameter.
        type: bool
        default: true
      namespaces:
        description:
          - List of the namespaces and their clusters to allow the access.
          - An empty list (V([])) denies the access to all the namespaces,
            unless another rule in the O(rules.clusters),
            O(rules.cluster_selectors), or O(rules.namespace_selectors)
            parameters grants the access.
          - You can list namespaces that do not already exist.
            Note that the access scope view in the RHACS portal does not
            display these namespaces.
        type: list
        elements: dict
        suboptions:
          cluster:
            description: Name of the cluster that contains the namespace.
            required: true
            type: str
          namespace:
            description: Name of the namespace.
            required: true
            type: str
      namespaces_append:
        description:
          - If V(true), then the module adds the namespaces listed in the
            O(rules.namespaces) list to the existing list.
          - If V(false), then the module replaces the current list of
            namespaces with the list from the O(rules.namespaces) parameter.
        type: bool
        default: true
      cluster_selectors:
        description:
          - Label selectors that allow access to clusters based on labels.
          - An empty list (V([])) denies the access to all the clusters,
            unless another rule in the O(rules.clusters), O(rules.namespaces),
            or O(rules.namespace_selectors) parameters grants the access.
        type: list
        elements: dict
        suboptions:
          label:
            description: Name of the label.
            required: true
            type: str
          values:
            description: List of values that allow the access.
            required: true
            type: list
            elements: str
      cluster_selectors_append:
        description:
          - If V(true), then the module adds the cluster label selectors
            listed in the O(rules.cluster_selectors) list to the existing list.
          - If V(false), then the module replaces the current list of cluster
            label selectors with the list from the O(rules.cluster_selectors)
            parameter.
        type: bool
        default: true
      namespace_selectors:
        description:
          - Label selectors that allow access to namespaces based on labels.
          - An empty list (V([])) denies the access to all the namespaces,
            unless another rule in the O(rules.clusters), O(rules.namespaces),
            or O(rules.cluster_selectors) parameters grants the access.
        type: list
        elements: dict
        suboptions:
          label:
            description: Name of the label.
            required: true
            type: str
          values:
            description: List of values that allow the access.
            required: true
            type: list
            elements: str
      namespace_selectors_append:
        description:
          - If V(true), then the module adds the namespace label selectors
            listed in the O(rules.namespace_selectors) list to the existing
            list.
          - If V(false), then the module replaces the current list of
            namespaces label selectors with the list from the
            O(rules.namespace_selectors) parameter.
        type: bool
        default: true
  state:
    description:
      - If V(absent), then the module deletes the access scope.
      - The module does not fail if the access scope does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the access scope if it does
        not already exist.
      - If the access scope already exists, then the module updates its
        state, and renames the access scope if you provide the O(new_name)
        parameter.
    type: str
    default: present
    choices: [absent, present]
notes:
  - You cannot update or delete the default access scopes.
  - You cannot create an "Allow All" access scope. The C(Unrestricted) access
    scope, which is available by default in RHACS installations, provides this
    feature.
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
- name: Ensure the access scope for accessing the frontent application exists
  herve4m.rhacs_configuration.rhacs_access_scope:
    name: Allow frontend
    description: Access to the frontend namespaces in the production cluster
    rules:
      namespaces:
        - cluster: production
          namespace: frontend_app1
        - cluster: production
          namespace: frontend_app2
        - cluster: production
          namespace: frontend_intranet
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the development access scope exists
  herve4m.rhacs_configuration.rhacs_access_scope:
    name: Allow development
    description: Grant access to the namespaces based on the environment label
    rules:
      namespace_selectors:
        - label: environment
          values:
            - dev
            - development
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the development access scope has an additional selector rule
  herve4m.rhacs_configuration.rhacs_access_scope:
    name: Allow development
    rules:
      namespace_selectors:
        - label: project_type
          values:
            - development
            - test
      namespace_selectors_append: true
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the development access scope does not exist
  herve4m.rhacs_configuration.rhacs_access_scope:
    name: Allow development
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

# Note: A "Deny all" access scopes already exist by default
# in RHACS installations.
- name: Ensure the Allow all access scope exists
  herve4m.rhacs_configuration.rhacs_access_scope:
    name: Deny all accesses
    description: Deny access to all the clusters and namespaces
    rules: {}
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the access scope.
  type: str
  returned: always
  sample: 763fd7f0-3095-48e4-a3fd-d85706172e49
"""

import copy

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        description=dict(),
        rules=dict(
            type="dict",
            options=dict(
                clusters=dict(type="list", elements="str"),
                clusters_append=dict(type="bool", default=True),
                namespaces=dict(
                    type="list",
                    elements="dict",
                    options=dict(cluster=dict(required=True), namespace=dict(required=True)),
                ),
                namespaces_append=dict(type="bool", default=True),
                cluster_selectors=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        label=dict(required=True),
                        values=dict(required=True, type="list", elements="str"),
                    ),
                ),
                cluster_selectors_append=dict(type="bool", default=True),
                namespace_selectors=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        label=dict(required=True),
                        values=dict(required=True, type="list", elements="str"),
                    ),
                ),
                namespace_selectors_append=dict(type="bool", default=True),
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
    rules = module.params.get("rules")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the rules parameters from the Ansible task
    req_rules = rules if rules else {}
    clusters = req_rules.get("clusters")
    clusters_append = req_rules.get("clusters_append", True)
    namespaces = req_rules.get("namespaces")
    namespaces_append = req_rules.get("namespaces_append", True)
    cluster_selectors = req_rules.get("cluster_selectors")
    cluster_selectors_append = req_rules.get("cluster_selectors_append", True)
    namespace_selectors = req_rules.get("namespace_selectors")
    namespace_selectors_append = req_rules.get("namespace_selectors_append", True)

    # Retrieve the existing access scopes
    #
    # GET /v1/simpleaccessscopes
    # {
    #   "accessScopes": [
    #     {
    #       "id": "ffffffff-ffff-fff4-f5ff-fffffffffffe",
    #       "name": "Deny All",
    #       "description": "No access to scoped resources",
    #       "rules": {
    #         "includedClusters": [],
    #         "includedNamespaces": [],
    #         "clusterLabelSelectors": [],
    #         "namespaceLabelSelectors": []
    #       },
    #       "traits": {
    #         "mutabilityMode": "ALLOW_MUTATE",
    #         "visibility": "VISIBLE",
    #         "origin": "DEFAULT"
    #       }
    #     },
    #     {
    #       "id": "ffffffff-ffff-fff4-f5ff-ffffffffffff",
    #       "name": "Unrestricted",
    #       "description": "Access to all clusters and namespaces",
    #       "rules": null,
    #       "traits": {
    #         "mutabilityMode": "ALLOW_MUTATE",
    #         "visibility": "VISIBLE",
    #         "origin": "DEFAULT"
    #       }
    #     }
    #   ]
    # }

    c = module.get_object_path("/v1/simpleaccessscopes")
    scopes = c.get("accessScopes", [])

    # Retrieve the objects for the given names
    config = module.get_item_from_resource_list(name, scopes)
    new_config = module.get_item_from_resource_list(new_name, scopes)

    # Remove the object. For delete operations, the new_name parameter is
    # ignored.
    if state == "absent":
        if not config:
            module.exit_json(changed=False)
        if config.get("traits") and config.get("traits").get("origin") == "DEFAULT":
            module.fail_json(
                msg="you cannot delete default access scopes: {c}".format(c=name)
            )
        module.delete(
            config,
            "access scope",
            name,
            "/v1/simpleaccessscopes/{id}".format(id=config.get("id", "")),
        )

    # Create the object
    if not config and not new_config:
        name = new_name if new_name else name
        new_rules = {
            "includedClusters": [],
            "includedNamespaces": [],
            "clusterLabelSelectors": [],
            "namespaceLabelSelectors": [],
        }
        if rules:
            if clusters:
                new_rules["includedClusters"] = clusters
            if namespaces:
                new_rules["includedNamespaces"] = [
                    {"clusterName": ns["cluster"], "namespaceName": ns["namespace"]}
                    for ns in namespaces
                ]
            if cluster_selectors:
                new_rules["clusterLabelSelectors"] = [
                    {
                        "requirements": [
                            {"key": cl["label"], "op": "IN", "values": cl["values"]}
                            for cl in cluster_selectors
                        ]
                    }
                ]
            if namespace_selectors:
                new_rules["namespaceLabelSelectors"] = [
                    {
                        "requirements": [
                            {"key": cl["label"], "op": "IN", "values": cl["values"]}
                            for cl in namespace_selectors
                        ]
                    }
                ]

        new_fields = {
            "name": name,
            "description": description if description else "",
            "rules": new_rules,
        }
        resp = module.create(
            "access scope", name, "/v1/simpleaccessscopes", new_fields, auto_exit=False
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    if not config and new_config:
        config = new_config
        name = new_name
        new_config = new_name = None

    # The access scope with the new name already exists
    if new_config:
        module.fail_json(
            msg="the destination access scope (`new_name') already exists: {name}".format(
                name=new_name
            )
        )

    if config.get("traits") and config.get("traits").get("origin") == "DEFAULT":
        module.fail_json(msg="you cannot update default access scopes: {c}".format(c=name))

    # Convert the data into sets for easier comparison
    curr_rules = config.get("rules", {})

    curr_clusters = set(curr_rules.get("includedClusters", []))
    req_clusters = set(clusters if clusters else [])
    clusters_to_add = req_clusters - curr_clusters

    curr_namespaces = set(
        [
            (ns.get("clusterName"), ns.get("namespaceName"))
            for ns in curr_rules.get("includedNamespaces", [])
        ]
    )
    req_namespaces = set(
        [(ns.get("cluster"), ns.get("namespace")) for ns in namespaces] if namespaces else []
    )
    namespaces_to_add = req_namespaces - curr_namespaces

    labels = []
    if len(curr_rules.get("clusterLabelSelectors", [])) > 0:
        for label in curr_rules.get("clusterLabelSelectors")[0].get("requirements", []):
            v = label.get("values", [])
            v.sort()
            labels.append((label.get("key"), "#".join(v)))
    curr_cl_labels = set(labels)
    labels = []
    if cluster_selectors:
        for label in cluster_selectors:
            v = label.get("values", [])
            v.sort()
            labels.append((label.get("label"), "#".join(v)))
    req_cl_labels = set(labels)
    cl_labels_to_add = req_cl_labels - curr_cl_labels

    labels = []
    if len(curr_rules.get("namespaceLabelSelectors", [])) > 0:
        for label in curr_rules.get("namespaceLabelSelectors")[0].get("requirements", []):
            v = label.get("values", [])
            v.sort()
            labels.append((label.get("key"), "#".join(v)))
    curr_ns_labels = set(labels)
    labels = []
    if namespace_selectors:
        for label in namespace_selectors:
            v = label.get("values", [])
            v.sort()
            labels.append((label.get("label"), "#".join(v)))
    req_ns_labels = set(labels)
    ns_labels_to_add = req_ns_labels - curr_ns_labels

    if (
        not new_name
        and (description is None or description == config.get("description"))
        and (
            rules is None
            or (
                (
                    clusters is None
                    or curr_clusters == req_clusters
                    or (clusters_append is True and not clusters_to_add)
                )
                and (
                    namespaces is None
                    or curr_namespaces == req_namespaces
                    or (namespaces_append is True and not namespaces_to_add)
                )
                and (
                    cluster_selectors is None
                    or curr_cl_labels == req_cl_labels
                    or (cluster_selectors_append is True and not cl_labels_to_add)
                )
                and (
                    namespace_selectors is None
                    or curr_ns_labels == req_ns_labels
                    or (namespace_selectors_append is True and not ns_labels_to_add)
                )
            )
        )
    ):
        module.exit_json(changed=False, id=config.get("id", ""))

    new_fields = copy.deepcopy(config)
    if new_name:
        new_fields["name"] = name = new_name
    if description is not None:
        new_fields["description"] = description
    if rules is not None:
        if not new_fields.get("rules"):
            new_fields["rules"] = {
                "includedClusters": [],
                "includedNamespaces": [],
                "clusterLabelSelectors": [{"requirements": []}],
                "namespaceLabelSelectors": [{"requirements": []}],
            }

        if clusters_append is True:
            new_fields["rules"]["includedClusters"].extend(clusters_to_add)
        elif clusters is not None:
            new_fields["rules"]["includedClusters"] = clusters

        if namespaces_append is True:
            to_add = []
            for ns in namespaces_to_add:
                to_add.append({"clusterName": ns[0], "namespaceName": ns[1]})
            new_fields["rules"]["includedNamespaces"].extend(to_add)
        elif namespaces is not None:
            new_fields["rules"]["includedNamespaces"] = [
                {
                    "clusterName": ns.get("cluster", ""),
                    "namespaceName": ns.get("namespace", ""),
                }
                for ns in namespaces
            ]

        if cluster_selectors_append is True:
            to_add = []
            if cluster_selectors:
                for cl in cl_labels_to_add:
                    val = []
                    for sel in cluster_selectors:
                        if sel["label"] == cl[0]:
                            val = sel["values"]
                            break
                    to_add.append({"key": cl[0], "op": "IN", "values": val})
            try:
                new_fields["rules"]["clusterLabelSelectors"][0]["requirements"].extend(to_add)
            except (KeyError, IndexError):
                new_fields["rules"]["clusterLabelSelectors"] = [{"requirements": to_add}]
        elif cluster_selectors is not None:
            new_fields["rules"]["clusterLabelSelectors"] = [
                {
                    "requirements": [
                        {"key": sel["label"], "op": "IN", "values": sel["values"]}
                        for sel in cluster_selectors
                    ]
                }
            ]

        if namespace_selectors_append is True:
            to_add = []
            if namespace_selectors:
                for ns in ns_labels_to_add:
                    val = []
                    for sel in req_rules.get("namespace_selectors", []):
                        if sel["label"] == ns[0]:
                            val = sel["values"]
                            break
                    to_add.append({"key": ns[0], "op": "IN", "values": val})
            try:
                new_fields["rules"]["namespaceLabelSelectors"][0]["requirements"].extend(
                    to_add
                )
            except (KeyError, IndexError):
                new_fields["rules"]["namespaceLabelSelectors"] = [{"requirements": to_add}]
        elif namespace_selectors is not None:
            new_fields["rules"]["namespaceLabelSelectors"] = [
                {
                    "requirements": [
                        {"key": sel["label"], "op": "IN", "values": sel["values"]}
                        for sel in namespace_selectors
                    ]
                }
            ]

    id = config.get("id", "")
    module.unconditional_update(
        "access scope",
        name,
        "/v1/simpleaccessscopes/{id}".format(id=id),
        new_fields,
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
