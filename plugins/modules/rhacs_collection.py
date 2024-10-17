#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_collection
short_description: Manage deployment collections
description:
  - Create, delete, and update deployment collections to associate with other
    workflows.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description: Name of the collection.
    required: true
    type: str
  new_name:
    description:
      - New name for the collection.
      - Setting this option changes the name of the collection, which
        current name is provided in the O(name) parameter.
      - The module returns an error if the destination collection already
        exists.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  description:
    description: Optional description for the collection.
    type: str
  rules:
    description:
      - List of collection rules.
      - You can define a collection by selecting one or more deployments,
        namespaces, or clusters.
      - For update operations, the modules cannot update individual rules.
        You have to provide the complete list of rules every time you call the
        module.
    type: dict
    suboptions:
      deployments:
        description:
          - Rules for selecting deployment resources.
          - If O(rules.deployments={}), then all the deployment resources
            are selected.
        required: true
        type: dict
        suboptions:
          name_matchings:
            description:
              - Match the deployments by their names.
              - Any rule in the list can match (logical OR).
              - Mutually exclusive with O(rules.deployments.label_matchings).
            type: list
            elements: dict
            suboptions:
              value:
                description:
                  - Value for matching with the name of the deployments.
                  - If O(rules.deployments.name_matchings[].match_type=REGEX),
                    then you can use a regular expression, such as
                    C(.*-frontend$).
                required: true
                type: str
              match_type:
                description:
                  - Specify the rule by using exact matches or regular
                    expressions.
                required: true
                type: str
                choices:
                  - EXACT
                  - REGEX
          label_matchings:
            description:
              - Match the deployments by their labels.
              - All the rules in the list must match (logical AND).
              - Mutually exclusive with O(rules.deployments.name_matchings).
            type: list
            elements: dict
            suboptions:
              or_values:
                description:
                  - List of labels, such as C(env=production).
                  - Any label can match (logical OR).
                type: list
                elements: str
      namespaces:
        description:
          - Rules for selecting namespace resources.
          - If O(rules.namespaces={}), then all the namespace resources
            are selected.
        required: true
        type: dict
        suboptions:
          name_matchings:
            description:
              - Match the namespaces by their names.
              - Any rule in the list can match (logical OR).
              - Mutually exclusive with O(rules.namespaces.label_matchings).
            type: list
            elements: dict
            suboptions:
              value:
                description:
                  - Value for matching with the name of the namespaces.
                  - If O(rules.namespaces.name_matchings[].match_type=REGEX),
                    then you can use a regular expression, such as
                    C(.*-frontend$).
                required: true
                type: str
              match_type:
                description:
                  - Specify the rule by using exact matches or regular
                    expressions.
                required: true
                type: str
                choices:
                  - EXACT
                  - REGEX
          label_matchings:
            description:
              - Match the namespaces by their labels.
              - All the rules in the list must match (logical AND).
              - Mutually exclusive with O(rules.namespaces.name_matchings).
            type: list
            elements: dict
            suboptions:
              or_values:
                description:
                  - List of labels, such as C(env=production).
                  - Any label can match (logical OR).
                type: list
                elements: str
      clusters:
        description:
          - Rules for selecting clusters.
          - If O(rules.clusters={}), then all the clusters are selected.
        required: true
        type: dict
        suboptions:
          name_matchings:
            description:
              - Match the clusters by their names.
              - Any rule in the list can match (logical OR).
              - Mutually exclusive with O(rules.clusters.label_matchings).
            type: list
            elements: dict
            suboptions:
              value:
                description:
                  - Value for matching with the cluster name.
                  - If O(rules.clusters.name_matchings[].match_type=REGEX),
                    then you can use a regular expression, such as
                    C(.*-frontend$).
                required: true
                type: str
              match_type:
                description:
                  - Specify the rule by using exact matches or regular
                    expressions.
                required: true
                type: str
                choices:
                  - EXACT
                  - REGEX
          label_matchings:
            description:
              - Match the clusters by their labels.
              - All the rules in the list must match (logical AND).
              - Mutually exclusive with O(rules.clusters.name_matchings).
            type: list
            elements: dict
            suboptions:
              or_values:
                description:
                  - List of labels, such as C(env=production).
                  - Any label can match (logical OR).
                type: list
                elements: str
  attached_collections:
    description:
      - Extend the collection by attaching other collections.
      - You can specify the collections by name or by identifier.
    type: list
    elements: str
  append_collections:
    description:
      - If V(true), then the module adds the collections listed in the
        O(attached_collections) section to the configuration.
      - If V(false), then the module sets the collections listed in the
        O(attached_collections) section, removing all other collections from
        the configuration.
    type: bool
    default: true
  state:
    description:
      - If V(absent), then the module deletes the collection.
      - If the collection is referenced in another collection, then the
        delete process fails.
      - The module does not fail if the collection does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the collection if it does
        not already exist.
      - If the collection already exists, then the module updates its
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
- name: Ensure the credit card collection exists
  herve4m.rhacs_configuration.rhacs_collection:
    name: Credit card processors
    description: Deployments that handle financial information
    rules:
      deployments:
        name_matchings:
          - match_type: REGEX
            value: ".*-cc$"
          - match_type: EXACT
            value: credit-cards
      namespaces:
        label_matchings:
          - or_values:
              - "app=cc"
              - "app=financial"
          - or_values:
              - "env=production"
      clusters:
        name_matchings:
          - match_type: EXACT
            value: production
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the sensitive collection exists
  herve4m.rhacs_configuration.rhacs_collection:
    name: Sensitive data
    description: Deployments that access personal user data
    attached_collections:
      - Credit card processors
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the credit card collection selects all the clusters
  herve4m.rhacs_configuration.rhacs_collection:
    name: Credit card processors
    description: Deployments that handle financial information
    rules:
      deployments:
        name_matchings:
          - match_type: REGEX
            value: ".*-cc$"
          - match_type: EXACT
            value: credit-cards
      namespaces:
        label_matchings:
          - or_values:
              - "app=cc"
              - "app=financial"
          - or_values:
              - "env=production"
      clusters: {}
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

# You cannot delete the "Credit card processors" collection because it is
# referred in the "Sensitive data" collection. Delete this collection first.
- name: Ensure the sensitive collection is removed
  herve4m.rhacs_configuration.rhacs_collection:
    name: Sensitive data
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the credit card processors collection is removed
  herve4m.rhacs_configuration.rhacs_collection:
    name: Credit card processors
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the collection.
  type: str
  returned: always
  sample: 763fd7f0-3095-48e4-a3fd-d85706172e49
"""

import copy

from ..module_utils.api_module import APIModule


def get_collection_ids(module, existing_collections, collections):
    if collections is None:
        return []
    return [
        module.get_id_from_resource_list(
            c,
            existing_collections,
            error_msg="the collection (in `attached_collections') does not exist",
        )
        for c in collections
    ]


def detect_loop_rec(embeded_ids, col_name, existing_collections, col_id):
    if col_id in embeded_ids:
        return [col_name]
    for id in embeded_ids:
        for next_col in existing_collections:
            if id == next_col.get("id"):
                ret = detect_loop_rec(
                    [col.get("id") for col in next_col.get("embeddedCollections", [])],
                    next_col.get("name"),
                    existing_collections,
                    col_id,
                )
                if ret:
                    ret.append(col_name)
                    return ret
    return None


def detect_loop(module, embeded_ids, col_name, existing_collections, col_id):
    if not embeded_ids:
        return
    if col_id in embeded_ids:
        module.fail_json(
            msg=(
                "the {name} collection is attached to itself (`attached_collections')"
            ).format(name=col_name)
        )
    col_loop = detect_loop_rec(embeded_ids, col_name, existing_collections, col_id)
    if col_loop:
        names = [col_name]
        names.extend(col_loop)
        module.fail_json(
            msg=(
                "in the {name} collection, attached collections "
                "(`attached_collections') create a loop: {names}"
            ).format(name=col_name, names=" <- ".join(names))
        )


def build_resource_selectors(rules):
    if not rules:
        return [{"rules": []}]

    # POST data example
    # {
    #     "name": "My collection",
    #     "description": "My description",
    #     "embeddedCollectionIds": [],
    #     "resourceSelectors": [
    #         {
    #             "rules": [
    #                 {
    #                     "fieldName": "Namespace Label",
    #                     "operator": "OR",
    #                     "values": [
    #                         {
    #                             "value": "team=payment",
    #                             "matchType": "EXACT"
    #                         },
    #                         {
    #                             "value": "foo=bar",
    #                             "matchType": "EXACT"
    #                         }
    #                     ]
    #                 },
    #                 {
    #                     "fieldName": "Namespace Label",
    #                     "operator": "OR",
    #                     "values": [
    #                         {
    #                             "value": "env=prod",
    #                             "matchType": "EXACT"
    #                         }
    #                     ]
    #                 },
    #                 {
    #                     "fieldName": "Deployment",
    #                     "operator": "OR",
    #                     "values": [
    #                         {
    #                             "value": "nginx-deployment",
    #                             "matchType": "EXACT"
    #                         },
    #                         {
    #                             "value": "^nginx-deployment$",
    #                             "matchType": "REGEX"
    #                         }
    #                     ]
    #                 }
    #             ]
    #         }
    #     ]
    # }
    deployments = rules.get("deployments")
    namespaces = rules.get("namespaces")
    clusters = rules.get("clusters")
    data = []

    if deployments.get("name_matchings") is not None:
        d = {
            "fieldName": "Deployment",
            "operator": "OR",
            "values": [
                {"value": rule["value"], "matchType": rule["match_type"]}
                for rule in deployments.get("name_matchings")
            ],
        }
        data.append(d)
    elif deployments.get("label_matchings") is not None:
        for label in deployments.get("label_matchings"):
            if label.get("or_values") is not None:
                d = {
                    "fieldName": "Deployment Label",
                    "operator": "OR",
                    "values": [
                        {"value": rule, "matchType": "EXACT"}
                        for rule in label.get("or_values")
                    ],
                }
            data.append(d)

    if namespaces.get("name_matchings") is not None:
        d = {
            "fieldName": "Namespace",
            "operator": "OR",
            "values": [
                {"value": rule["value"], "matchType": rule["match_type"]}
                for rule in namespaces.get("name_matchings")
            ],
        }
        data.append(d)
    elif namespaces.get("label_matchings") is not None:
        for label in namespaces.get("label_matchings"):
            if label.get("or_values") is not None:
                d = {
                    "fieldName": "Namespace Label",
                    "operator": "OR",
                    "values": [
                        {"value": rule, "matchType": "EXACT"}
                        for rule in label.get("or_values")
                    ],
                }
            data.append(d)

    if clusters.get("name_matchings") is not None:
        d = {
            "fieldName": "Cluster",
            "operator": "OR",
            "values": [
                {"value": rule["value"], "matchType": rule["match_type"]}
                for rule in clusters.get("name_matchings")
            ],
        }
        data.append(d)
    elif clusters.get("label_matchings") is not None:
        for label in clusters.get("label_matchings"):
            if label.get("or_values") is not None:
                d = {
                    "fieldName": "Cluster Label",
                    "operator": "OR",
                    "values": [
                        {"value": rule, "matchType": "EXACT"}
                        for rule in label.get("or_values")
                    ],
                }
            data.append(d)

    return [{"rules": data}]


def main():

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        description=dict(),
        rules=dict(
            type="dict",
            options=dict(
                deployments=dict(
                    type="dict",
                    required=True,
                    options=dict(
                        name_matchings=dict(
                            type="list",
                            elements="dict",
                            options=dict(
                                value=dict(required=True),
                                match_type=dict(required=True, choices=["EXACT", "REGEX"]),
                            ),
                        ),
                        label_matchings=dict(
                            type="list",
                            elements="dict",
                            options=dict(or_values=dict(type="list", elements="str")),
                        ),
                    ),
                    mutually_exclusive=[("name_matchings", "label_matchings")],
                ),
                namespaces=dict(
                    type="dict",
                    required=True,
                    options=dict(
                        name_matchings=dict(
                            type="list",
                            elements="dict",
                            options=dict(
                                value=dict(required=True),
                                match_type=dict(required=True, choices=["EXACT", "REGEX"]),
                            ),
                        ),
                        label_matchings=dict(
                            type="list",
                            elements="dict",
                            options=dict(or_values=dict(type="list", elements="str")),
                        ),
                    ),
                    mutually_exclusive=[("name_matchings", "label_matchings")],
                ),
                clusters=dict(
                    type="dict",
                    required=True,
                    options=dict(
                        name_matchings=dict(
                            type="list",
                            elements="dict",
                            options=dict(
                                value=dict(required=True),
                                match_type=dict(required=True, choices=["EXACT", "REGEX"]),
                            ),
                        ),
                        label_matchings=dict(
                            type="list",
                            elements="dict",
                            options=dict(or_values=dict(type="list", elements="str")),
                        ),
                    ),
                    mutually_exclusive=[("name_matchings", "label_matchings")],
                ),
            ),
        ),
        attached_collections=dict(type="list", elements="str"),
        append_collections=dict(type="bool", default=True),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    new_name = module.params.get("new_name")
    description = module.params.get("description")
    rules = module.params.get("rules")
    attached_collections = module.params.get("attached_collections")
    append_collections = module.params.get("append_collections")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the existing collections
    #
    # GET /v1/collections
    # {
    #     "collections": [
    #         {
    #             "id": "7e4a265e-2d5a-4ff4-81a8-e426b102dbae",
    #             "name": "My collection",
    #             "description": "My description",
    #             "createdAt": "2024-10-03T14:07:18.562326152Z",
    #             "lastUpdated": "2024-10-03T14:07:18.562326152Z",
    #             "createdBy": {
    #                 "id": "sso:4df1b98c-24ed-4073-a9ad-356aec6bb62d:admin",
    #                 "name": "admin"
    #             },
    #             "updatedBy": {
    #                 "id": "sso:4df1b98c-24ed-4073-a9ad-356aec6bb62d:admin",
    #                 "name": "admin"
    #             },
    #             "resourceSelectors": [
    #                 {
    #                     "rules": [
    #                         {
    #                             "fieldName": "Namespace Label",
    #                             "operator": "OR",
    #                             "values": [
    #                                 {
    #                                     "value": "team=payment",
    #                                     "matchType": "EXACT"
    #                                 },
    #                                 {
    #                                     "value": "foo=bar",
    #                                     "matchType": "EXACT"
    #                                 }
    #                             ]
    #                         },
    #                         {
    #                             "fieldName": "Namespace Label",
    #                             "operator": "OR",
    #                             "values": [
    #                                 {
    #                                     "value": "toto=titi",
    #                                     "matchType": "EXACT"
    #                                 }
    #                             ]
    #                         },
    #                         {
    #                             "fieldName": "Deployment",
    #                             "operator": "OR",
    #                             "values": [
    #                                 {
    #                                     "value": "nginx-deployment",
    #                                     "matchType": "EXACT"
    #                                 },
    #                                 {
    #                                     "value": "^nginx-deployment$",
    #                                     "matchType": "REGEX"
    #                                 }
    #                             ]
    #                         }
    #                     ]
    #                 }
    #             ],
    #             "embeddedCollections": [
    #                 {
    #                     "id": "a7e188bb-f4f5-4023-a91f-4d4585809d17"
    #                 }
    #             ]
    #         },
    #         ...
    #     ]
    # }

    c = module.get_object_path(
        "/v1/collections", query_params={"query.pagination.limit": 10000}
    )
    existing_collections = c.get("collections", [])

    # Retrieve the objects for the given names
    config = module.get_item_from_resource_list(name, existing_collections)
    new_config = module.get_item_from_resource_list(new_name, existing_collections)

    # Remove the object. For delete operations, the new_name parameter is
    # ignored.
    if state == "absent":
        if not config:
            module.exit_json(changed=False)
        module.delete(
            config,
            "collection",
            name,
            "/v1/collections/{id}".format(id=config.get("id", "")),
            not_found_codes=[404],
        )

    # Create the object
    if not config and not new_config:
        name = new_name if new_name else name

        if not attached_collections and (
            not rules
            or (
                not rules.get("deployments")
                and not rules.get("namespaces")
                and not rules.get("clusters")
            )
        ):
            module.fail_json(
                msg=(
                    "at least a rule (in `rules'), or a collection (in "
                    "`attached_collections') is required when creating a "
                    "deployment collection."
                )
            )

        new_fields = {
            "name": name,
            "description": description if description else "",
            "resourceSelectors": build_resource_selectors(rules),
            "embeddedCollectionIds": get_collection_ids(
                module, existing_collections, attached_collections
            ),
        }

        resp = module.create(
            "collection", name, "/v1/collections", new_fields, auto_exit=False
        )
        module.exit_json(changed=True, id=resp.get("collection", {}).get("id"))

    if not config and new_config:
        config = new_config
        name = new_name
        new_config = new_name = None

    # The collection with the new name already exists
    if new_config:
        module.fail_json(
            msg="the destination collection (`new_name') already exists: {name}".format(
                name=new_name
            )
        )

    new_fields = copy.deepcopy(config)
    new_fields.pop("id", None)
    new_fields.pop("createdAt", None)
    new_fields.pop("lastUpdated", None)
    new_fields.pop("createdBy", None)
    new_fields.pop("updatedBy", None)
    new_fields.pop("embeddedCollections", None)
    new_fields["embeddedCollectionIds"] = [
        c.get("id") for c in config.get("embeddedCollections", [])
    ]

    id = config.get("id", "")
    changed = False

    if new_name:
        changed = True
        new_fields["name"] = new_name

    if description is not None and description != config.get("description"):
        changed = True
        new_fields["description"] = description

    if attached_collections is not None:
        curr_cols = set([c.get("id") for c in config.get("embeddedCollections", [])])
        req_cols = set(get_collection_ids(module, existing_collections, attached_collections))
        to_add = req_cols - curr_cols
        if curr_cols != req_cols and (append_collections is False or to_add):
            changed = True
            if append_collections is False:
                new_fields["embeddedCollectionIds"] = list(req_cols)
            else:
                new_fields["embeddedCollectionIds"].extend(list(to_add))

        detect_loop(
            module,
            new_fields["embeddedCollectionIds"],
            new_fields["name"],
            existing_collections,
            id,
        )

    if rules is not None:
        try:
            curr_rules = config["resourceSelectors"][0]["rules"]
        except (KeyError, IndexError):
            curr_rules = []
        resource_selector = build_resource_selectors(rules)
        req_rules = resource_selector[0]["rules"]

        if len(req_rules) != len(curr_rules):
            changed = True
            new_fields["resourceSelectors"] = resource_selector
        else:
            # Verifying whether all the requested rules exist
            for rr in req_rules:
                for cr in curr_rules:
                    if rr.get("fieldName") == cr.get("fieldName"):
                        curr_val = set(
                            [(v["value"], v["matchType"]) for v in cr.get("values", [])]
                        )
                        req_val = set(
                            [(v["value"], v["matchType"]) for v in rr.get("values", [])]
                        )
                        if curr_val == req_val:
                            break
                else:
                    # Requested rule no found
                    changed = True
                    new_fields["resourceSelectors"] = resource_selector
                    break

    if changed is False:
        module.exit_json(changed=False, id=id)

    if (
        not new_fields["embeddedCollectionIds"]
        and not new_fields["resourceSelectors"][0]["rules"]
    ):
        module.fail_json(
            msg=(
                "at least a rule (in `deployments', `namespaces', or `clusters'), "
                "or a collection (in `attached_collections') is required."
            )
        )

    module.patch(
        "collection",
        new_fields["name"],
        "/v1/collections/{id}".format(id=id),
        new_fields,
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
