#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_cloud_management_platform
short_description: Manage RHACS integration with cloud platforms
description:
  - Create, delete, and update Red Hat Advanced Cluster Security for Kubernetes
    (RHACS) integrations with the Paladin Cloud and Red Hat OpenShift Cluster
    Manager platforms.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description: Name of the configuration.
    required: true
    type: str
  type:
    description:
      - Cloud platform type.
      - For Paladin Cloud, set the parameter to V(PALADIN), and for
        Red Hat OpenShift Cluster Manager, set the parameter to V(OCM).
      - V(PALADIN) by default.
    type: str
    choices: [PALADIN, OCM]
  endpoint_url:
    description:
      - URL for accessing the API of the cloud platform.
      - V(https://api.paladincloud.io) by default for Paladin Cloud.
      - V(https://api.openshift.com) by default for Red Hat OpenShift Cluster
        Manager.
    type: str
  api_token:
    description:
      - Authentication token for accessing the cloud platform.
      - The O(api_token) parameter is required for creating a configuration or
        when changing the platform type of an existing configuration.
    type: str
  state:
    description:
      - If V(absent), then the module deletes the configuration.
      - The module does not fail if the configuration does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the configuration if it does not
        already exist.
      - If the configuration already exists, then the module updates its state.
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
- name: Ensure the Red Hat OpenShift Cluster Manager integration exists
  herve4m.rhacs_configuration.rhacs_cloud_management_platform:
    name: OCM_integration
    type: OCM
    api_token: "eyJh...VQBQ"
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the Red Hat OpenShift Cluster Manager integration is removed
  herve4m.rhacs_configuration.rhacs_cloud_management_platform:
    name: OCM_integration
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the cloud platform configuration.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

import copy

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        name=dict(required=True),
        type=dict(choices=["PALADIN", "OCM"]),
        api_token=dict(no_log=True),
        endpoint_url=dict(),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    platform = module.params.get("type")
    api_token = module.params.get("api_token")
    endpoint = module.params.get("endpoint_url")
    state = module.params.get("state")

    platform_type = "TYPE_OCM" if platform == "OCM" else "TYPE_PALADIN_CLOUD"
    platform_key = "ocm" if platform == "OCM" else "paladinCloud"

    # Retrieve the existing machine configurations
    #
    # GET /v1/cloud-sources
    # {
    #   "cloudSources": [
    #     {
    #       "id": "75575cd9-4102-4904-8ba0-de73e1bd5d85",
    #       "name": "foobar",
    #       "type": "TYPE_PALADIN_CLOUD",
    #       "credentials": {
    #         "secret": "******"
    #       },
    #       "skipTestIntegration": true,
    #       "paladinCloud": {
    #         "endpoint": "https://api.paladincloud.io"
    #       }
    #     },
    #     {
    #       "id": "03f69f36-45ef-4be5-a600-134b40d11235",
    #       "name": "myocp",
    #       "type": "TYPE_OCM",
    #       "credentials": {
    #         "secret": "******"
    #       },
    #       "skipTestIntegration": true,
    #       "ocm": {
    #         "endpoint": "https://api.openshift.com"
    #       }
    #     }
    #   ]
    # }

    c = module.get_object_path(
        "/v1/cloud-sources",
        query_params={"filter.names": name},
    )

    # Remove the objects that match both the name and type parameters
    if state == "absent":
        if len(c.get("cloudSources", [])) == 0:
            module.exit_json(changed=False)
        for config in c["cloudSources"]:
            id = config.get("id", "")
            module.delete(
                config,
                "cloud management platform",
                id,
                "/v1/cloud-sources/{id}".format(id=id),
                auto_exit=False,
            )
        module.exit_json(changed=True)

    # Create the object
    if len(c.get("cloudSources", [])) == 0:
        if not api_token:
            module.fail_json(msg="missing required argument: api_token")
        new_fields = {
            "updateCredentials": True,
            "cloudSource": {
                "name": name,
                "type": platform_type,
                "skipTestIntegration": True,
                "credentials": {"secret": api_token},
            },
        }
        if platform_type == "TYPE_PALADIN_CLOUD":
            new_fields["cloudSource"]["paladinCloud"] = {
                "endpoint": endpoint if endpoint else "https://api.paladincloud.io"
            }
        else:
            new_fields["cloudSource"]["ocm"] = {
                "endpoint": endpoint if endpoint else "https://api.openshift.com"
            }
        resp = module.create(
            "cloud management platform",
            name,
            "/v1/cloud-sources",
            new_fields,
            auto_exit=False,
        )
        module.exit_json(changed=True, id=resp.get("cloudSource", {}).get("id", ""))

    # Compare the existing objects to the requested configuration to verify
    # if a change is required
    for config in c["cloudSources"]:
        e = config.get(platform_key, {}).get("endpoint")
        if (
            (platform is None or platform_type == config.get("type"))
            and (endpoint is None or endpoint == e)
            and not api_token
        ):
            module.exit_json(changed=False, id=config.get("id", ""))

    # Only process the first returned object
    config = c["cloudSources"][0]

    # The type (Paladin or OCM) does not need to change
    if not platform or platform_type == config.get("type"):
        new_fields = {
            "updateCredentials": False if not api_token else True,
            "cloudSource": copy.deepcopy(config),
        }
        new_fields["cloudSource"]["credentials"]["secret"] = api_token if api_token else ""
        if endpoint:
            new_fields["cloudSource"][platform_key]["endpoint"] = endpoint
    else:
        # Verify that the user provides the api_token parameter
        if not api_token:
            module.fail_json(
                msg="missing required `api_token' argument when changing the platform type"
            )
        new_fields = {
            "updateCredentials": True,
            "cloudSource": copy.deepcopy(config),
        }
        new_fields["cloudSource"]["type"] = platform_type
        new_fields["cloudSource"]["credentials"]["secret"] = api_token
        if platform_type == "TYPE_PALADIN_CLOUD":
            new_fields["cloudSource"][platform_key] = new_fields["cloudSource"].pop("ocm")
        else:
            new_fields["cloudSource"][platform_key] = new_fields["cloudSource"].pop(
                "paladinCloud"
            )
        if endpoint:
            new_fields["cloudSource"][platform_key]["endpoint"] = endpoint

    id = config.get("id", "")
    module.unconditional_update(
        "cloud management platform", name, "/v1/cloud-sources/{id}".format(id=id), new_fields
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
