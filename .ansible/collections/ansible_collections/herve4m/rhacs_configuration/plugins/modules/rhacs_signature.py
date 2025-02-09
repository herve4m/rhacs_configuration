#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_signature
short_description: Manage RHACS integration with Cosign signatures
description:
  - Create, delete, and update Red Hat Advanced Cluster Security for Kubernetes
    (RHACS) integration with Cosign signatures.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description: Name of the integration configuration.
    required: true
    type: str
  cosign_pub_keys:
    description: Cosign public keys.
    type: list
    elements: dict
    suboptions:
      name:
        description: Name for the public key.
        type: str
        required: true
      key:
        description:
          - PEM-encoded public key.
          - You can use the P(ansible.builtin.file#lookup) lookup plugin
            to read the file from the system.
        required: true
        type: str
  cosign_certs:
    description: Cosign certificates.
    type: list
    elements: dict
    suboptions:
      identity:
        description:
          - Certificate identity.
          - You can use a regular expression.
        type: str
        required: true
      oidc_issuer:
        description:
          - Certificate OpenID Connect (OIDC) issuer.
          - You can use a regular expression.
        required: true
        type: str
      cert_chain:
        description:
          - PEM-encoded certificate chain.
          - You can use the P(ansible.builtin.file#lookup) lookup plugin
            to read the file from the system.
          - One of O(cosign_certs[].cert_chain) and O(cosign_certs[].cert) is
            required.
        type: str
      cert:
        description:
          - PEM-encoded certificate.
          - You can use the P(ansible.builtin.file#lookup) lookup plugin
            to read the file from the system.
          - One of O(cosign_certs[].cert_chain) and O(cosign_certs[].cert) is
            required.
        type: str
  append_keys:
    description:
      - If V(true), then the module adds the public keys listed in the
        O(cosign_pub_keys) section to the already existing keys.
      - If V(false), then the module sets the public keys listed in the
        O(cosign_pub_keys) section, removing all other keys from the
        configuration.
    type: bool
    default: true
  append_certs:
    description:
      - If V(true), then the module adds the certificates listed in the
        O(cosign_certs) section to the already existing certificates.
      - If V(false), then the module sets the certificates listed in the
        O(cosign_certs) section, removing all other certificates from the
        configuration.
    type: bool
    default: true
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
- name: Ensure the signature integration exists
  herve4m.rhacs_configuration.rhacs_signature:
    name: sig_integration
    cosign_pub_keys:
      - name: cosign_signature_pub1
        key: "{{ lookup('ansible.builtin.file', 'cosign1.pub') }}"
      - name: cosign_signature_pub2
        key: "{{ lookup('ansible.builtin.file', 'cosign2.pub') }}"
    cosign_certs:
      - identity: lvasquez@example.com
        oidc_issuer: https://github.com/login/oauth
        cert: "{{ lookup('ansible.builtin.file', 'sign_cert.pem') }}"
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the signature integration is removed
  herve4m.rhacs_configuration.rhacs_signature:
    name: sig_integration
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the Cosign signature configuration.
  type: str
  returned: always
  sample: io.stackrox.signatureintegration.8597c335-dfb1-4f99-90ba-bd0ae4ade693
"""

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        name=dict(required=True),
        cosign_pub_keys=dict(
            type="list",
            elements="dict",
            options=dict(
                name=dict(required=True),
                key=dict(required=True, no_log=False),
            ),
        ),
        cosign_certs=dict(
            type="list",
            elements="dict",
            options=dict(
                identity=dict(required=True),
                oidc_issuer=dict(required=True),
                cert_chain=dict(),
                cert=dict(),
            ),
            required_one_of=[("cert_chain", "cert")],
        ),
        append_keys=dict(type="bool", default=True),
        append_certs=dict(type="bool", default=True),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    cosign_pub_keys = module.params.get("cosign_pub_keys")
    cosign_certs = module.params.get("cosign_certs")
    append_keys = module.params.get("append_keys")
    append_certs = module.params.get("append_certs")
    state = module.params.get("state")

    if not cosign_pub_keys:
        cosign_pub_keys = []
    if not cosign_certs:
        cosign_certs = []

    # Retrieve the existing machine configurations
    #
    # GET /v1/signatureintegrations
    # {
    #   "integrations": [
    #     {
    #       "id": "io.stackrox.signatureintegration.7607...7f21",
    #       "name": "test",
    #       "cosign": {
    #         "publicKeys": [
    #           {
    #             "name": "k1",
    #             "publicKeyPemEnc": "-----BEGIN PUBLIC KEY-----..."
    #           },
    #           {
    #             "name": "k2",
    #             "publicKeyPemEnc": "-----BEGIN PUBLIC KEY-----..."
    #           }
    #         ]
    #       },
    #       "cosignCertificates": [
    #         {
    #           "certificatePemEnc": "-----BEGIN CERTIFICATE-----...",
    #           "certificateChainPemEnc": "-----BEGIN CERTIFICATE-----...",
    #           "certificateOidcIssuer": "issuer1",
    #           "certificateIdentity": "identity1"
    #         },
    #         {
    #           "certificatePemEnc": "-----BEGIN CERTIFICATE-----...",
    #           "certificateChainPemEnc": "-----BEGIN CERTIFICATE-----...",
    #           "certificateOidcIssuer": "issuer2",
    #           "certificateIdentity": "identity2"
    #         }
    #       ]
    #     }
    #   ]
    # }

    c = module.get_object_path("/v1/signatureintegrations")

    # Retrieve the configuration for the given name
    config = module.get_item_from_resource_list(name, c.get("integrations", []))

    # Remove the object.
    if state == "absent":
        id = config.get("id", "") if config else ""
        module.delete(
            config,
            "signature integration",
            name,
            "/v1/signatureintegrations/{id}".format(id=id),
        )

    # Create the object
    if not config:
        # At least one public key or one certificate must be provided
        if not cosign_pub_keys and not cosign_certs:
            module.fail_json(
                msg=(
                    "at least one public key (`cosign_pub_keys') or one "
                    "certificate (`cosign_certs') must be provided"
                )
            )
        new_fields = {"name": name, "cosign": {"publicKeys": []}, "cosignCertificates": []}

        for k in cosign_pub_keys:
            new_fields["cosign"]["publicKeys"].append(
                {"name": k.get("name", ""), "publicKeyPemEnc": k.get("key", "")}
            )
        for cert in cosign_certs:
            new_fields["cosignCertificates"].append(
                {
                    "certificateOidcIssuer": cert.get("oidc_issuer"),
                    "certificateIdentity": cert.get("identity"),
                    "certificateChainPemEnc": cert.get("cert_chain") or "",
                    "certificatePemEnc": cert.get("cert") or "",
                }
            )
        resp = module.create(
            "signature integration",
            name,
            "/v1/signatureintegrations",
            new_fields,
            auto_exit=False,
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    # Compare the existing object to the requested configuration to verify
    # if a change is required
    current_key_mappings = set(
        [
            (m["name"], m["publicKeyPemEnc"])
            for m in config.get("cosign", {}).get("publicKeys", [])
        ]
    )
    current_cert_mappings = set(
        [
            (
                m["certificateIdentity"],
                m["certificateOidcIssuer"],
                m["certificateChainPemEnc"],
                m["certificatePemEnc"],
            )
            for m in config.get("cosignCertificates", [])
        ]
    )

    requested_key_mappings = set([(m["name"], m["key"]) for m in cosign_pub_keys])
    requested_cert_mappings = set(
        [
            (
                m["identity"],
                m["oidc_issuer"],
                m.get("cert_chain") or "",
                m.get("cert") or "",
            )
            for m in cosign_certs
        ]
    )
    keys_to_add = requested_key_mappings - current_key_mappings
    certs_to_add = requested_cert_mappings - current_cert_mappings

    if (
        current_key_mappings == requested_key_mappings
        or (append_keys is True and not keys_to_add)
    ) and (
        current_cert_mappings == requested_cert_mappings
        or (append_certs is True and not certs_to_add)
    ):
        module.exit_json(changed=False, id=config.get("id", ""))

    # Update the configuration
    new_fields = {
        "id": config.get("id", ""),
        "name": name,
        "cosign": {"publicKeys": []},
        "cosignCertificates": [],
    }

    if append_keys:
        mappings = config.get("cosign", {}).get("publicKeys", [])
        for m in keys_to_add:
            mappings.append({"name": m[0], "publicKeyPemEnc": m[1]})
    else:
        mappings = []
        for r in cosign_pub_keys:
            mappings.append({"name": r.get("name"), "publicKeyPemEnc": r.get("key")})
    new_fields["cosign"]["publicKeys"] = mappings

    if append_certs:
        mappings = config.get("cosignCertificates", [])
        for m in certs_to_add:
            mappings.append(
                {
                    "certificateIdentity": m[0],
                    "certificateOidcIssuer": m[1],
                    "certificateChainPemEnc": m[2],
                    "certificatePemEnc": m[3],
                }
            )
    else:
        mappings = []
        for r in cosign_certs:
            mappings.append(
                {
                    "certificateIdentity": r.get("identity"),
                    "certificateOidcIssuer": r.get("oidc_issuer"),
                    "certificateChainPemEnc": r.get("cert_chain") or "",
                    "certificatePemEnc": r.get("cert") or "",
                }
            )
    new_fields["cosignCertificates"] = mappings

    id = config.get("id", "")
    module.unconditional_update(
        "signature integration",
        name,
        "/v1/signatureintegrations/{id}".format(id=id),
        new_fields,
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
