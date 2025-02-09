#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_delegated_image_scan
short_description: Manage delegated image scanning configuration
description:
  - Manage the delegation of image scannings by secured clusters.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  enabled_for:
    description:
      - Scope of the image delegation.
      - Choose V(NONE) to prevent the secured clusters from scanning images,
        except for the images from the integrated Red Hat OpenShift image
        registry.
      - Choose V(ALL) for the secured clusters to scan all the images.
      - Choose V(SPECIFIC) to specifies the images to scan based on their
        registry. You provide the list of registries in the O(registries)
        parameter.
    type: str
    choices:
      - NONE
      - ALL
      - SPECIFIC
  default_cluster:
    description:
      - Name or identifier of the default secured cluster that processes the
        scan requests coming from the command-line interface and the API.
    type: str
  registries:
    description:
      - Provides a list of image registries to scan, and the secured clusters
        to use for that process.
    type: list
    elements: dict
    suboptions:
      path:
        description: Image registry, such as C(registry.example.com).
        type: str
        required: true
      cluster:
        description:
          - Name or identifier of the secured cluster that processes the scans
            for the registry specified in the O(registries[].path) parameter.
        type: str
        required: true
  append:
    description:
      - If V(true), then the module adds the registries listed in the
        O(registries) section to the configuration.
      - If V(false), then the module sets the registries listed in the
        O(registries) section, removing all other registries from
        the configuration.
    type: bool
    default: true
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
- name: Ensure secured clusters scan images from example.com registries
  herve4m.rhacs_configuration.rhacs_delegated_image_scan:
    enabled_for: SPECIFIC
    default_cluster: infra
    registries:
      - path: registry.example.com
        cluster: "179a071b-38c0-4c00-99cb-248e7737be63"
      - path: registry2.example.com
        cluster: public
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r""" # """

import copy

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        enabled_for=dict(choices=["NONE", "ALL", "SPECIFIC"]),
        default_cluster=dict(),
        registries=dict(
            type="list",
            elements="dict",
            options=dict(path=dict(required=True), cluster=dict(required=True)),
        ),
        append=dict(type="bool", default=True),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    enabled_for = module.params.get("enabled_for")
    default_cluster = module.params.get("default_cluster")
    registries = module.params.get("registries")
    append = module.params.get("append")

    # Retrieve the existing delegated image scanning configuration
    #
    # GET /v1/delegatedregistryconfig
    # {
    #     "enabledFor": "SPECIFIC",
    #     "defaultClusterId": "179a071b-38c0-4c00-99cb-248e7737be63",
    #     "registries": [
    #         {
    #             "path": "reg.example.com",
    #             "clusterId": "179a071b-38c0-4c00-99cb-248e7737be63",
    #         }
    #     ]
    # }

    c = module.get_object_path("/v1/delegatedregistryconfig")

    new_fields = copy.deepcopy(c)
    changed = False

    if enabled_for is not None and enabled_for != c.get("enabledFor"):
        changed = True
        new_fields["enabledFor"] = enabled_for

    if default_cluster is not None:
        default_cluster_id = (
            "" if not default_cluster else module.get_cluster_id(default_cluster)
        )
        if default_cluster_id != c.get("defaultClusterId"):
            changed = True
            new_fields["defaultClusterId"] = default_cluster_id

    if registries is not None:
        curr_set = set([(r.get("path"), r.get("clusterId")) for r in c.get("registries", [])])
        req_set = set()
        for r in registries:
            cluster = r.get("cluster")
            if not cluster:
                req_set.add((r.get("path"), ""))
            else:
                req_set.add((r.get("path"), module.get_cluster_id(cluster)))
        to_add = req_set - curr_set
        if curr_set != req_set:
            if append is False:
                changed = True
                new_fields["registries"] = [
                    {"path": r[0], "clusterId": r[1]} for r in req_set
                ]
            elif to_add:
                changed = True
                new_fields["registries"].extend(
                    [{"path": r[0], "clusterId": r[1]} for r in to_add]
                )

    if changed is False:
        module.exit_json(changed=False)

    if enabled_for == "NONE":
        new_fields["defaultClusterId"] = ""
        new_fields["registries"] = []

    module.unconditional_update(
        "delegated image scanning configuration",
        "RHACS",
        "/v1/delegatedregistryconfig",
        new_fields,
    )
    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
