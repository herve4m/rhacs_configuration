#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_init_bundle
short_description: Manage cluster init bundles
description:
  - Create or delete cluster init bundles for registering
    new secured clusters.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description:
      - Name of the cluster init bundle to create or delete.
      - "The name can have only the following characters: letters, digits,
        periods, underscores, hyphens, but no spaces."
    required: true
    type: str
  state:
    description:
      - If V(absent), then the module deletes the cluster init bundle. You
        cannot delete cluster init bundles that are still used by secured
        clusters.
      - The module does not fail if the cluster init bundle does not exist,
        because the state is already as expected.
      - If V(present), then the module creates the cluster init bundle if it
        does not already exist. The module returns the init bundle encoded in
        Base64 in the RV(b64_kubectl) and RV(b64_helm) return values.
      - If the cluster init bundle already exists, then the module returns the
        cluster init bundle details, except the Base64 encoded RV(b64_kubectl)
        and RV(b64_helm) return values, which cannot be retrieved after the
        initial init bundle creation.
    type: str
    default: present
    choices: [absent, present]
notes:
  - "You cannot retrieve the cluster init bundle again after its initial
    creation: the returned values RV(b64_kubectl) and RV(b64_helm) are defined
    only when the cluster init bundle is created for the first time."
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
- name: Create the cluster init bundle for development secured clusters
  herve4m.rhacs_configuration.rhacs_init_bundle:
    name: Development
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
  register: bundle_details

- name: Save the Kubernetes secrets to create secrets for new secured clusters
  ansible.builtin.copy:
    content: "{{ bundle_details['b64_kubectl'] |
      ansible.builtin.b64decode }}"
    dest: /etc/RHACS/bundles/development.yaml
    mode: '0600'
  # If the `Development' cluster init bundle already exists, then the
  # `b64_kubectl' return value is not defined, because you cannot retrieve the
  # cluster init bundle after its initial creation.
  when: "'b64_kubectl' in bundle_details"
"""

RETURN = r"""
b64_kubectl:
  description:
    - Kubernetes secret resources in the YAML format that to you must create in
      new secured clusters.
    - The RV(b64_kubectl) return value is Base64 encoded. Use the
      P(ansible.builtin.b64decode#filter) filter to decode the value.
    - You cannot retrieve this value again after the initial creation of the
      cluster init bundle.
    - When the cluster init bundle already exists, the RV(b64_kubectl) return
      value is not defined.
  type: str
  returned: only when the cluster init bundle is created
  sample: IyBU....LS0K
b64_helm:
  description:
    - Helm values file in YAML format that contains the secret resources
      for new secured clusters.
    - The RV(b64_helm) return value is Base64 encoded. Use the
      P(ansible.builtin.b64decode#filter) filter to decode the value.
    - You cannot retrieve this value again after the initial creation of the
      cluster init bundle.
    - When the cluster init bundle already exists, the RV(b64_helm) return
      value is not defined.
  type: str
  returned: only when the cluster init bundle is created
  sample: IyBU....LS0K
name:
  description: The name of the cluster init bundle.
  type: str
  returned: always
  sample: Development-bundle-1
expiration:
  description:
    - The date and time at which the cluster init bundle becomes invalid.
  type: str
  returned: always
  sample: "2025-10-30T21:06:00Z"
id:
  description: Internal identifier of the cluster init bundle.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

import re

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        name=dict(required=True),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    state = module.params.get("state")

    if not re.match(r"[a-z0-9\._-]+$", name, re.IGNORECASE):
        module.fail_json(
            msg=(
                "the name can have only the following characters: letters, "
                "digits, periods, underscores, hyphens (but no spaces): {name}"
            ).format(name=name)
        )

    # Retrieve the existing cluster init bundles
    #
    # GET /v1/cluster-init/init-bundles
    # {
    #   "items": [
    #     {
    #       "id": "066f1024-1fc9-41ae-9023-2f3cbaaf8856",
    #       "name": "prod-wboqk0jn",
    #       "impactedClusters": [
    #         {
    #           "name": "production",
    #           "id": "179a071b-38c0-4c00-99cb-248e7737be63"
    #         }
    #       ],
    #       "createdAt": "2024-10-09T05:49:32.668122649Z",
    #       "createdBy": {
    #         "id": "admin",
    #         "authProviderId": "4df1b98c-24ed-4073-a9ad-356aec6bb62d",
    #         "attributes": [
    #           {
    #             "key": "username",
    #             "value": "admin"
    #           },
    #           {
    #             "key": "role",
    #             "value": "Admin"
    #           }
    #         ],
    #         "idpToken": ""
    #       },
    #       "expiresAt": "2025-10-09T05:50:00Z"
    #     },
    #     {
    #       "id": "e6a215ac-52ee-4ecc-8695-3c7631ab2cc6",
    #       "name": "mybundle",
    #       "impactedClusters": [],
    #       "createdAt": "2024-10-09T06:39:02.430105516Z",
    #       "createdBy": {
    #         "id": "sso:4df1b98c-24ed-4073-a9ad-356aec6bb62d:admin",
    #         "authProviderId": "4df1b98c-24ed-4073-a9ad-356aec6bb62d",
    #         "attributes": [
    #           {
    #             "key": "role",
    #             "value": "Admin"
    #           },
    #           {
    #             "key": "username",
    #             "value": "admin"
    #           }
    #         ],
    #         "idpToken": ""
    #       },
    #       "expiresAt": "2025-10-09T06:39:00Z"
    #     }
    #   ]
    # }

    b = module.get_object_path("/v1/cluster-init/init-bundles")

    # Retrieve the cluster init bundle that matches the provided name
    bundle = module.get_item_from_resource_list(name, b.get("items", []))

    # Revoke the cluster init bundle
    if state == "absent":
        if not bundle:
            module.exit_json(changed=False)

        clusters = [c.get("name") for c in bundle.get("impactedClusters", [])]
        if clusters:
            module.fail_json(
                msg=(
                    "cannot delete the {name} cluster init bundle, because the "
                    "following secure clusters depend on this bundle: {cls}"
                ).format(name=name, cls=", ".join("clusters"))
            )

        module.patch(
            "cluster init bundle",
            name,
            "/v1/cluster-init/init-bundles/revoke",
            {"ids": [bundle.get("id")], "confirmImpactedClustersIds": []},
        )
        module.exit_json(changed=True)

    # If the cluster init bundle already exits, then no change is needed,
    # but the secrets cannot be returned again
    if bundle:
        result = {
            "changed": False,
            "id": bundle.get("id", ""),
            "name": name,
            "expiration": bundle.get("expiresAt", ""),
        }
    else:
        ret = module.create(
            "cluster init bundle",
            name,
            "/v1/cluster-init/init-bundles",
            {"name": name},
            auto_exit=False,
        )
        result = {
            "changed": True,
            "id": ret.get("meta", {}).get("id", ""),
            "name": name,
            "expiration": ret.get("meta", {}).get("expiresAt", ""),
            "b64_kubectl": ret.get("kubectlBundle", ""),
            "b64_helm": ret.get("helmValuesBundle", ""),
        }
    module.exit_json(**result)


if __name__ == "__main__":
    main()
