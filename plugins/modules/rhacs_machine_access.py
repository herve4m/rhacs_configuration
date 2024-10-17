#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_machine_access
short_description: Manage machine access configurations
description:
  - Create, delete, and update machine access configurations.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  type:
    description:
      - Configuration type.
      - You can create only one GitHub configuration
        (when O(type=GITHUB_ACTIONS)).
      - When O(type=GENERIC), you can create several configurations, as long
        as the O(issuer) parameter differs.
    type: str
    default: GENERIC
    choices: [GENERIC, GITHUB_ACTIONS]
  expiration:
    description:
      - Token lifetime.
      - The O(expiration) parameter specifies the lifetime in hours, minutes,
        and seconds, such as 10h5m30s. The accepted time units are
        C(s), C(m), and C(h).
      - The lifetime cannot exceed 24 hours (24h).
    type: str
    default: 10m
  issuer:
    description:
      - URL of the OpenID Connect (OIDC) provider that issues the tokens to
        exchange for RHACS short-lived API tokens.
      - The O(issuer) parameter is only required when O(type=GENERIC).
        For GitHub (when O(type=GITHUB_ACTIONS)), the issuer is automatically
        set to https://token.actions.githubusercontent.com
    type: str
  rules:
    description:
      - Map OIDC token claims to RHACS roles.
      - If a rule matches, then the exchanged token is granted the role that
        the rule defines.
    type: list
    elements: dict
    suboptions:
      key:
        description:
          - The name of the claim to use for evaluating the OIDC token.
          - You can get a list of standard claims at
            U(https://openid.net/specs/openid-connect-core-1_0.html#Claims).
        type: str
        required: true
        aliases:
          - claim
      value:
        description:
          - Regular expression that is used to evaluate against the claim.
        required: true
        type: str
      role:
        description:
          - The role to associate with the exchanged token if the claim matches
            the O(rules[].value) parameter.
        type: str
        default: Admin
  append:
    description:
      - If V(true), then the module adds the rules listed in the O(rules)
        section to the configuration.
      - If V(false), then the module sets the rules listed in the O(rules)
        section, removing all other rules from the configuration.
    type: bool
    default: true
  state:
    description:
      - If V(absent), then the module deletes the configuration that matches the
        O(issuer) parameter.
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
- name: Ensure the machine access configuration for GitHub Actions exists
  herve4m.rhacs_configuration.rhacs_machine_access:
    type: GITHUB_ACTIONS
    expiration: 4h
    rules:
      - key: sub
        value: "repo:test/test-repo.*"
        role: Continuous Integration
      - key: sub
        value: "repo:example/example-repo.*"
        role: Continuous Integration
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Adds (append) a new rule to the GitHub Actions configuration
  herve4m.rhacs_configuration.rhacs_machine_access:
    type: GITHUB_ACTIONS
    expiration: 4h
    rules:
      - key: sub
        value: "repo:example2/example2-repo.*"
        role: Continuous Integration
    append: true
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the machine access configuration for GitHub Actions is removed
  herve4m.rhacs_configuration.rhacs_machine_access:
    # Because only one GitHub Actions configuration is allowed, no need to
    # specify the issuer.
    type: GITHUB_ACTIONS
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the machine access configuration for my OIDC provider exists
  herve4m.rhacs_configuration.rhacs_machine_access:
    type: GENERIC
    issuer: https://accounts.google.com
    expiration: 5m
    rules:
      - key: sub
        value: "repo:test/test-repo.*"
        role: Continuous Integration
      - key: sub
        value: "repo:example/example-repo.*"
        role: Continuous Integration
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the machine access configuration for my OIDC provider is removed
  herve4m.rhacs_configuration.rhacs_machine_access:
    # Because several configurations for generic OIDC providers are allowed,
    # you must specify the issuer.
    type: GENERIC
    issuer: https://accounts.google.com
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the machine configuration.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        type=dict(choices=["GENERIC", "GITHUB_ACTIONS"], default="GENERIC"),
        expiration=dict(default="10m"),
        issuer=dict(),
        rules=dict(
            type="list",
            elements="dict",
            options=dict(
                key=dict(required=True, aliases=["claim"], no_log=False),
                value=dict(required=True),
                role=dict(default="Admin"),
            ),
        ),
        append=dict(type="bool", default=True),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(
        argument_spec=argument_spec,
        required_if=[("type", "GENERIC", ["issuer"]), ("append", False, ["rules"])],
        supports_check_mode=True,
    )

    # Extract our parameters
    oidc_type = module.params.get("type")
    expiration = module.params.get("expiration")
    issuer = module.params.get("issuer")
    rules = module.params.get("rules")
    if not rules:
        rules = []
    append = module.params.get("append")
    state = module.params.get("state")

    # Retrieve the existing machine configurations
    #
    # GET /v1/auth/m2m
    # {
    #   "configs": [
    #     {
    #       "id": "a22894d7-77c4-4427-8a33-dccc05fdf86a",
    #       "type": "GITHUB_ACTIONS",
    #       "tokenExpirationDuration": "10m",
    #       "mappings": [
    #         {
    #           "key": "test",
    #           "valueExpression": "test",
    #           "role": "Admin"
    #         },
    #         {
    #           "key": "foo",
    #           "valueExpression": "bar",
    #           "role": "Sensor Creator"
    #         }
    #       ],
    #       "issuer": "https://token.actions.githubusercontent.com"
    #     }
    #   ]
    # }
    c = module.get_object_path("/v1/auth/m2m")

    # Retrieve the configuration that matches the provided parameters
    for config in c.get("configs", []):
        if oidc_type == config.get("type") and (
            oidc_type == "GITHUB_ACTIONS" or issuer == config.get("issuer")
        ):
            break
    else:
        config = None

    # Remove the configuration
    if state == "absent":
        if not config:
            module.exit_json(changed=False)
        module.delete(
            config,
            "machine access configuration",
            oidc_type,
            "/v1/auth/m2m/{id}".format(id=config.get("id", "")),
        )

    # If the configuration does not exist, then create it
    if not config:
        if not rules:
            module.fail_json(
                msg=(
                    "the `rules' parameter is required when creating a"
                    " machine access configuration."
                )
            )
        new_fields = {"config": {"type": oidc_type, "tokenExpirationDuration": expiration}}
        if issuer:
            new_fields["config"]["issuer"] = issuer
        mappings = []
        for r in rules:
            mappings.append(
                {
                    "key": r.get("key"),
                    "valueExpression": r.get("value"),
                    "role": r.get("role"),
                }
            )
        new_fields["config"]["mappings"] = mappings
        resp = module.create(
            "machine access configuration",
            oidc_type,
            "/v1/auth/m2m",
            new_fields,
            auto_exit=False,
        )
        module.exit_json(changed=True, id=resp.get("config", {}).get("id"))

    # Compare the existing object to the requested configuration to verify
    # whether a change is required
    current_mappings = set(
        [(m["key"], m["valueExpression"], m["role"]) for m in config.get("mappings", [])]
    )
    requested_mappings = set([(m["key"], m["value"], m["role"]) for m in rules])
    to_add = requested_mappings - current_mappings

    if expiration == config.get("tokenExpirationDuration") and (
        current_mappings == requested_mappings or (append is True and not to_add)
    ):
        module.exit_json(changed=False, id=config.get("id", ""))

    # Update the configuration
    new_fields = {
        "config": {
            "type": oidc_type,
            "tokenExpirationDuration": expiration,
            "id": config.get("id"),
        }
    }
    if issuer:
        new_fields["config"]["issuer"] = issuer
    if append:
        mappings = config.get("mappings", [])
        for m in to_add:
            mappings.append(
                {
                    "key": m[0],
                    "valueExpression": m[1],
                    "role": m[2],
                }
            )
    else:
        mappings = []
        for r in rules:
            mappings.append(
                {
                    "key": r.get("key"),
                    "valueExpression": r.get("value"),
                    "role": r.get("role"),
                }
            )
    new_fields["config"]["mappings"] = mappings

    id = config.get("id", "")
    module.unconditional_update(
        "machine access configuration",
        oidc_type,
        "/v1/auth/m2m/{id}".format(id=id),
        new_fields,
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
