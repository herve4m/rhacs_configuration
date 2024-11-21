#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_auth_provider
short_description: Manage authentication providers
description:
  - Create, delete, and update Red Hat Advanced Cluster Security for Kubernetes
    (RHACS) authentication providers.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description: Name of the authentication provider configuration.
    required: true
    type: str
  new_name:
    description:
      - New name for the authentication provider configuration.
      - Setting this option changes the name of the configuration, which
        current name is provided in the O(name) parameter.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  type:
    description:
      - Type of the authentication provider.
      - You cannot change the type after creating the configuration.
      - Except for the OpenShift authentication provider, each authentication
        provider requires a set of parameters grouped in a dedicated section.
        For example, you configure the OpenID Connect (OIDC) provider by
        setting the O(type) parameter to V(oidc), and by providing the
        configuration for OIDC in the O(oidc) section.
      - The OpenShift authentication provider (O(type=openshift)) does not
        require further configuration, and therefore does not have a
        dedicated configuration section.
    required: true
    type: str
    choices:
      - auth0
      - google
      - oidc
      - openshift
      - saml
      - userpki
  rhacs_url:
    description:
      - URL of the RHACS web interface.
      - The network location of O(rhacs_host) by default, such as
        C(rhacs.example.com:8443) for example.
    type: str
  auth0:
    description:
      - Configuration for the Auth0 authentication provider.
      - Required when O(type=auth0).
    type: dict
    suboptions:
      tenant_url:
        description:
          - Auth0 tenant URL, such as C(your-tenant.auth0.com).
          - The parameter is required when creating the configuration.
        type: str
      client_id:
        description:
          - Unique identifier for your application.
          - The parameter is required when creating the configuration.
        type: str
  google:
    description:
      - Configuration for the Google Identity-Aware Proxy (IAP) authentication
        provider.
      - Required when O(type=google).
    type: dict
    suboptions:
      audience:
        description:
          - Audience validation string, such as
            C(/projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID).
          - The parameter is required when creating the authentication provider.
        type: str
  oidc:
    description:
      - Configuration for the OpenID Connect (OIDC) authentication provider.
      - Required when O(type=oidc).
    type: dict
    suboptions:
      mode:
        description:
          - Callback mode.
          - V(post) by default.
        type: str
        choices:
          - post
          - fragment
          - query
      issuer:
        description:
          - Issuer, such as C(tenant.auth-provider.com).
          - The parameter is required when creating the configuration.
        type: str
      client_id:
        description:
          - Unique identifier for your application.
          - The parameter is required when creating the configuration.
        type: str
      client_secret:
        description:
          - Client secret string.
          - The parameter is required when O(oidc.use_client_secret=true).
        type: str
      use_client_secret:
        description:
          - Whether to define a client secret, which is recommended.
          - If V(true), then you must define the secret in the
            O(oidc.client_secret) parameter.
        type: bool
      offline_access_scope:
        description:
          - Whether to use the C(offline_access) scope.
          - Set the parameter to V(false) if the identity provider has a limit
            on the number of offline tokens that it can issue.
          - V(true) by default.
        type: bool
      attributes:
        description:
          - List of the required attributes that the authentication provider
            must return.
        type: list
        elements: dict
        suboptions:
          key:
            description: Name of the attribute.
            type: str
            required: true
          value:
            description: Value for the attribute.
            type: str
            required: true
      claim_mappings:
        description:
          - List of mappings between the claims that the authentication
            provider returns and the RHACS-issued token.
        type: list
        elements: dict
        suboptions:
          key:
            description: Name of the claim.
            type: str
            required: true
          value:
            description: Value for the claim.
            type: str
            required: true
  saml:
    description:
      - Configuration for the Security Assertion Markup Language (SAML)
        authentication provider.
      - Required when O(type=saml).
    type: dict
    suboptions:
      mode:
        description:
          - Configuration mode.
          - V(dynamic) by default.
        type: str
        choices:
          - dynamic
          - static
      service_provider_issuer:
        description:
          - Service provider issuer, such as C(https://prevent.stackrox.io).
          - The parameter is required when creating the configuration.
        type: str
      metadata_url:
        description:
          - Identity provider URL for the metadata XML file, such as
            C(https://idp.example.com/metadata).
          - The parameter is required when O(saml.mode=dynamic).
        type: str
      idp_issuer:
        description:
          - Identity provider issuer, such as C(https://idp.example.com/) or
            C(urn:something:else).
          - The parameter is required when O(saml.mode=static).
        type: str
      idp_sso_url:
        description:
          - Identity provider SSO URL, such as
            C(https://idp.example.com/login).
          - The parameter is required when O(saml.mode=static).
        type: str
      idp_nameid_format:
        description:
          - Format for the name/ID, such as
            C(urn:oasis:names:tc:SAML:1.1:nameid-format:persistent).
        type: str
      idp_certificate:
        description:
          - Identity provider certificates in PEM format.
          - You can use the P(ansible.builtin.file#lookup) lookup plugin
            to read the file from the system.
          - The parameter is required when O(saml.mode=static).
        type: str
  userpki:
    description:
      - Configuration for the user certificates providers.
      - Required when O(type=userpki).
    type: dict
    suboptions:
      ca_certificate:
        description:
          - Certificate authority (CA) certificates in PEM format.
          - You can use the P(ansible.builtin.file#lookup) lookup plugin
            to read the file from the system.
          - The parameter is required when creating the configuration.
        type: str
  state:
    description:
      - If V(absent), then the module deletes the authentication provider
        configuration.
      - The module does not fail if the configuration does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the authentication provider
        configuration if it does not already exist.
      - If the configuration already exists, then the module updates its state.
    type: str
    default: present
    choices: [absent, present]
notes:
  - See the M(herve4m.rhacs_configuration.rhacs_group) module to grant roles
    to the users who sign in with the identity providers.
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
- name: Ensure the Google IAP authentication provider exists
  herve4m.rhacs_configuration.rhacs_auth_provider:
    name: Google IAP
    type: google
    google:
      audience: /projects/4242/global/backendServices/4242
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

# Define the minimum access role that RHACS grants to all the users who sign
# in with this authentication provider.
- name: Ensure minimum access role is set for the Google IAP provider
  herve4m.rhacs_configuration.rhacs_group:
    auth_provider_name: Google IAP
    key: default
    # Set the role to None, so that no role is granted by default, and only
    # the rule defined in the next task applies.
    role: None
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

# Grant the Admin role to the user with the lvasquez@example.com email address.
- name: Ensure lvasquez has the Admin role
  herve4m.rhacs_configuration.rhacs_group:
    auth_provider_name: Google IAP
    key: email
    value: lvasquez@example.com
    role: Admin
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the Google IAP authentication provider is renamed
  herve4m.rhacs_configuration.rhacs_auth_provider:
    name: Google IAP
    new_name: Google Identity-Aware Proxy
    type: google
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the user certificates provider configuration exists
  herve4m.rhacs_configuration.rhacs_auth_provider:
    name: User certificates
    type: userpki
    userpki:
      ca_certificate: "{{ lookup('ansible.builtin.file', 'CA.pem') }}"
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the user certificates provider configuration does not exist
  herve4m.rhacs_configuration.rhacs_auth_provider:
    name: User certificates
    type: userpki
  state: absent
  rhacs_host: central.example.com
  rhacs_username: admin
  rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the provider configuration.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

import copy

from ..module_utils.api_module import APIModule


def parameter_to_API_type(auth_type):
    if auth_type == "google":
        return "iap"
    return auth_type


def API_type_to_parameter(auth_type):
    if auth_type == "iap":
        return "google"
    return auth_type


def main():

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        type=dict(
            required=True,
            choices=["auth0", "google", "oidc", "openshift", "saml", "userpki"],
        ),
        rhacs_url=dict(),
        auth0=dict(
            type="dict",
            options=dict(
                tenant_url=dict(),
                client_id=dict(),
            ),
        ),
        google=dict(
            type="dict",
            options=dict(
                audience=dict(),
            ),
        ),
        oidc=dict(
            type="dict",
            options=dict(
                mode=dict(choices=["post", "fragment", "query"]),
                issuer=dict(),
                client_id=dict(),
                client_secret=dict(no_log=True),
                use_client_secret=dict(type="bool"),
                offline_access_scope=dict(type="bool"),
                attributes=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        key=dict(required=True, no_log=False),
                        value=dict(required=True),
                    ),
                ),
                claim_mappings=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        key=dict(required=True, no_log=False),
                        value=dict(required=True),
                    ),
                ),
            ),
            required_if=[("use_client_secret", True, ["client_secret"])],
        ),
        saml=dict(
            type="dict",
            options=dict(
                mode=dict(choices=["dynamic", "static"]),
                service_provider_issuer=dict(),
                metadata_url=dict(),
                idp_issuer=dict(),
                idp_sso_url=dict(),
                idp_nameid_format=dict(),
                idp_certificate=dict(),
            ),
            required_if=[
                ("mode", "dynamic", ["metadata_url"]),
                (
                    "mode",
                    "static",
                    ("idp_issuer", "idp_sso_url", "idp_certificate"),
                ),
            ],
        ),
        userpki=dict(
            type="dict",
            options=dict(
                ca_certificate=dict(),
            ),
        ),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    new_name = module.params.get("new_name")
    auth_type = module.params.get("type")
    rhacs_url = module.params.get("rhacs_url")
    auth0 = module.params.get("auth0")
    google = module.params.get("google")
    oidc = module.params.get("oidc")
    saml = module.params.get("saml")
    userpki = module.params.get("userpki")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the authentication providers configuration
    #
    # GET /v1/authProviders
    # {
    #     "authProviders": [
    #         {
    #             "id": "651f44f7-fe88-42e6-a9aa-0c3f2ad0503f",
    #             "name": "My Google IAP",
    #             "type": "iap",
    #             "uiEndpoint": "central.example.com",
    #             "enabled": true,
    #             "config": {
    #                 "audience": "/projects/4242/global/backendServices/4242"
    #             },
    #             "loginUrl": "/sso/login/651f44f7-fe88-42e6-a9aa-0c3f2ad0503f",
    #             "validated": false,
    #             "extraUiEndpoints": [],
    #             "active": false,
    #             "requiredAttributes": [],
    #             "traits": {
    #                 "mutabilityMode": "ALLOW_MUTATE",
    #                 "visibility": "VISIBLE",
    #                 "origin": "IMPERATIVE"
    #             },
    #             "claimMappings": {},
    #             "lastUpdated": "2024-09-30T11:01:49.537106708Z"
    #         },
    #         {
    #             "id": "5582b1d9-cda1-4f3e-b471-84277369f717",
    #             "name": "My OpenShift Auth",
    #             "type": "openshift",
    #             "uiEndpoint": "central.example.com",
    #             "enabled": true,
    #             "config": {},
    #             "loginUrl": "/sso/login/5582b1d9-cda1-4f3e-b471-84277369f717",
    #             "validated": false,
    #             "extraUiEndpoints": [],
    #             "active": false,
    #             "requiredAttributes": [],
    #             "traits": {
    #                 "mutabilityMode": "ALLOW_MUTATE",
    #                 "visibility": "VISIBLE",
    #                 "origin": "IMPERATIVE"
    #             },
    #             "claimMappings": {},
    #             "lastUpdated": "2024-09-30T11:13:49.004350184Z"
    #         },
    #         ...
    #     ]
    # }

    # Retrieve the configurations for the two given names
    c = module.get_object_path("/v1/authProviders", query_params={"name": name})
    try:
        config = c["authProviders"][0]
    except (KeyError, IndexError):
        config = None

    if new_name:
        c = module.get_object_path("/v1/authProviders", query_params={"name": new_name})
        try:
            new_config = c["authProviders"][0]
        except (KeyError, IndexError):
            new_config = None
    else:
        new_config = None

    # Remove the configurations
    if state == "absent":
        id = config.get("id", "") if config else ""
        module.delete(
            config, "authentication provider", name, "/v1/authProviders/{id}".format(id=id)
        )

    if not config and new_config:
        config = new_config
        name = new_name
        new_config = new_name = None

    if auth_type == "auth0":
        auth_conf = {"conf": auth0, "conf_name": "auth0"}
    elif auth_type == "google":
        auth_conf = {"conf": google, "conf_name": "google"}
    elif auth_type == "oidc":
        auth_conf = {"conf": oidc, "conf_name": "oidc"}
    elif auth_type == "openshift":
        auth_conf = {"conf": {}, "conf_name": "openshift"}
    elif auth_type == "saml":
        auth_conf = {"conf": saml, "conf_name": "saml"}
    else:  # auth_type == "userpki":
        auth_conf = {"conf": userpki, "conf_name": "userpki"}

    # Create the authentication provider
    if not config and not new_config:
        name = new_name if new_name else name

        # Verify that the user provided the registry configuration parameters
        if auth_conf["conf"] is None:
            module.fail_json(
                msg="type is {t} but the `{auth}' parameter is missing".format(
                    t=auth_type, auth=auth_conf["conf_name"]
                )
            )

        # Build the data to send to the API to create the configuration
        new_fields = {
            "name": name,
            "type": parameter_to_API_type(auth_type),
            "uiEndpoint": rhacs_url if rhacs_url else module.host_url.netloc,
            "enabled": True,
            "traits": {"mutabilityMode": "ALLOW_MUTATE"},
        }

        if auth_type == "auth0":
            tenant_url = auth_conf["conf"].get("tenant_url")
            client_id = auth_conf["conf"].get("client_id")

            missing_args = []
            if not tenant_url:
                missing_args.append("tenant_url")
            if not client_id:
                missing_args.append("client_id")
            if missing_args:
                module.fail_json(
                    msg="missing required `auth0' arguments: {args}".format(
                        args=", ".join(missing_args)
                    )
                )

            new_fields["config"] = {"client_id": client_id, "issuer": tenant_url}

        elif auth_type == "google":
            audience = auth_conf["conf"].get("audience")

            if not audience:
                module.fail_json(msg="missing required `google' argument: audience")

            new_fields["config"] = {"audience": audience}

        elif auth_type == "oidc":
            mode = auth_conf["conf"].get("mode")
            issuer = auth_conf["conf"].get("issuer")
            client_id = auth_conf["conf"].get("client_id")
            client_secret = auth_conf["conf"].get("client_secret")
            use_client_secret = auth_conf["conf"].get("use_client_secret")
            offline_access_scope = auth_conf["conf"].get("offline_access_scope")
            attributes = auth_conf["conf"].get("attributes")
            claim_mappings = auth_conf["conf"].get("claim_mappings")

            # Default values
            if not mode:
                mode = "post"
            if use_client_secret is None:
                use_client_secret = True
            if offline_access_scope is None:
                offline_access_scope = True
            if attributes is None:
                attributes = []
            if claim_mappings is None:
                claim_mappings = []

            if use_client_secret is True and mode == "fragment":
                use_client_secret = False

            missing_args = []
            if not issuer:
                missing_args.append("issuer")
            if not client_id:
                missing_args.append("client_id")
            if use_client_secret is True and not client_secret:
                missing_args.append("client_secret")
            if missing_args:
                module.fail_json(
                    msg="missing required `oidc' arguments: {args}".format(
                        args=", ".join(missing_args)
                    )
                )
            if use_client_secret is False and mode == "query":
                module.fail_json(
                    msg=(
                        "when `mode=query' in the `oidc' section, "
                        "`use_client_secret' must be true, and `client_secret' "
                        "must be set"
                    )
                )

            new_fields["config"] = {
                "mode": mode,
                "do_not_use_client_secret": str(not use_client_secret).lower(),
                "disable_offline_access_scope": str(not offline_access_scope).lower(),
                "issuer": issuer,
                "client_id": client_id,
            }
            if use_client_secret is True:
                new_fields["config"]["client_secret"] = client_secret
            attrs = []
            for attr in attributes:
                attrs.append({"attributeKey": attr["key"], "attributeValue": attr["value"]})
            new_fields["requiredAttributes"] = attrs
            new_fields["claimMappings"] = {}
            for claim in claim_mappings:
                new_fields["claimMappings"][claim["key"]] = claim["value"]

        elif auth_type == "openshift":
            new_fields["config"] = {}

        elif auth_type == "saml":
            mode = auth_conf["conf"].get("mode", "dynamic")
            service_provider_issuer = auth_conf["conf"].get("service_provider_issuer")
            metadata_url = auth_conf["conf"].get("metadata_url")
            idp_issuer = auth_conf["conf"].get("idp_issuer")
            idp_sso_url = auth_conf["conf"].get("idp_sso_url")
            idp_nameid_format = auth_conf["conf"].get("idp_nameid_format")
            idp_certificate = auth_conf["conf"].get("idp_certificate")

            missing_args = []
            if not service_provider_issuer:
                missing_args.append("service_provider_issuer")
            if mode == "dynamic":
                if not metadata_url:
                    missing_args.append("metadata_url")
            else:
                if not idp_issuer:
                    missing_args.append("idp_issuer")
                if not idp_sso_url:
                    missing_args.append("idp_sso_url")
                if not idp_certificate:
                    missing_args.append("idp_certificate")
            if missing_args:
                module.fail_json(
                    msg="missing required `saml' arguments: {args}".format(
                        args=", ".join(missing_args)
                    )
                )

            new_fields["config"] = {"sp_issuer": service_provider_issuer}
            if mode == "dynamic":
                new_fields["config"]["idp_metadata_url"] = metadata_url
            else:
                new_fields["config"]["idp_cert_pem"] = idp_certificate
                new_fields["config"]["idp_issuer"] = idp_issuer
                new_fields["config"]["idp_sso_url"] = idp_sso_url
                if idp_nameid_format:
                    new_fields["config"]["idp_nameid_format"] = idp_nameid_format

        else:  # auth_type == "userpki":
            ca_certificate = auth_conf["conf"].get("ca_certificate")

            if not ca_certificate:
                module.fail_json(msg="missing required `userpki' argument: ca_certificate")

            new_fields["config"] = {"keys": ca_certificate}

        resp = module.create(
            "authentication provider", name, "/v1/authProviders", new_fields, auto_exit=False
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    if new_config:
        # If both the source (name) and destination (new_name) configurations
        # exist, then update the destination configuration, and then delete
        # the source configuration
        if new_config.get("type") != config.get("type"):
            module.fail_json(
                msg=(
                    "cannot rename the `{s_name}' {s_type} configuration "
                    "to `{d_name}' because a configuration with this name "
                    "but a different type ({d_type}) already exists"
                ).format(
                    s_name=name,
                    s_type=API_type_to_parameter(config.get("type")),
                    d_name=new_name,
                    d_type=API_type_to_parameter(new_config.get("type")),
                )
            )
        id_to_delete = config.get("id")
        name_to_delete = name
        id_to_update = new_config.get("id")
        name = new_name
    else:
        id_to_delete = None
        id_to_update = config.get("id")
        name = new_name if new_name else name

    if parameter_to_API_type(auth_type) != config.get("type"):
        module.fail_json(
            msg=(
                "cannot change the `type' parameter of an existing "
                "authentication provider: current type is {t}, "
                "requested type is {rt}"
            ).format(t=API_type_to_parameter(config.get("type")), rt=auth_type)
        )

    # Build the data to send to the API to update the configuration
    data = copy.deepcopy(config)
    data.pop("id", None)
    data.pop("lastUpdated", None)
    data.pop("loginUrl", None)
    data["name"] = name
    conf = config.get("config", {})

    # Compare the object with the requested configuration to verify whether
    # an update is required
    if auth_conf["conf"] is None:
        if not new_name and (not rhacs_url or rhacs_url == data.get("uiEndpoint")):
            module.exit_json(changed=False, id=id_to_update)

    elif auth_type == "auth0":
        tenant_url = auth_conf["conf"].get("tenant_url")
        client_id = auth_conf["conf"].get("client_id")

        if (
            not new_name
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (tenant_url is None or tenant_url == conf.get("issuer"))
            and (client_id is None or client_id == conf.get("client_id"))
        ):
            module.exit_json(changed=False, id=id_to_update)

        if tenant_url is not None:
            data["config"]["issuer"] = tenant_url
        if client_id is not None:
            data["config"]["client_id"] = client_id

    elif auth_type == "google":
        audience = auth_conf["conf"].get("audience")

        if (
            not new_name
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (audience is None or audience == conf.get("audience"))
        ):
            module.exit_json(changed=False, id=id_to_update)

        if audience is not None:
            data["config"]["audience"] = audience

    elif auth_type == "oidc":
        mode = auth_conf["conf"].get("mode")
        issuer = auth_conf["conf"].get("issuer")
        client_id = auth_conf["conf"].get("client_id")
        client_secret = auth_conf["conf"].get("client_secret")
        use_client_secret = auth_conf["conf"].get("use_client_secret")
        offline_access_scope = auth_conf["conf"].get("offline_access_scope")
        attributes = auth_conf["conf"].get("attributes")
        claim_mappings = auth_conf["conf"].get("claim_mappings")

        if offline_access_scope is not None:
            disable_offline_access_scope = str(not offline_access_scope).lower()

        if use_client_secret is True:
            if mode == "fragment":
                use_client_secret = False
            elif not client_secret:
                module.fail_json(msg="missing required `oidc' argument: client_secret")
        if use_client_secret is False and mode == "query":
            module.fail_json(
                msg=(
                    "when `mode=query' in the `oidc' section, "
                    "`use_client_secret' must be true, and `client_secret' "
                    "must be set"
                )
            )

        if (
            not new_name
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and not client_secret
            and (
                use_client_secret is None
                or (use_client_secret is False and not conf.get("client_secret"))
            )
            and (mode is None or mode == conf.get("mode"))
            and (issuer is None or issuer == conf.get("issuer"))
            and (client_id is None or client_id == conf.get("client_id"))
            and (
                offline_access_scope is None
                or disable_offline_access_scope == conf.get("disable_offline_access_scope")
            )
        ):
            # Convert the attributes into sets for comparisons
            if attributes is not None:
                curr_attrs = set(
                    [
                        (attr.get("attributeKey"), attr.get("attributeValue"))
                        for attr in config.get("requiredAttributes", [])
                    ]
                )
                req_attrs = set([(attr.get("key"), attr.get("value")) for attr in attributes])
            if claim_mappings is not None:
                curr_maps = set(list(config.get("claimMappings", {}).items()))
                req_maps = set(
                    [(attr.get("key"), attr.get("value")) for attr in claim_mappings]
                )

            if (attributes is None or curr_attrs == req_attrs) and (
                claim_mappings is None or curr_maps == req_maps
            ):
                module.exit_json(changed=False, id=id_to_update)

        if mode is not None:
            data["config"]["mode"] = mode
        if issuer is not None:
            data["config"]["issuer"] = issuer
        if client_id is not None:
            data["config"]["client_id"] = client_id
        if offline_access_scope is not None:
            data["config"]["disable_offline_access_scope"] = disable_offline_access_scope
        if use_client_secret is not None:
            data["config"]["do_not_use_client_secret"] = str(not use_client_secret).lower()
        if client_secret:
            data["config"]["client_secret"] = client_secret
            data["config"]["do_not_use_client_secret"] = "false"
        else:
            data["config"].pop("client_secret", None)
        if attributes is not None:
            attrs = []
            for attr in attributes:
                attrs.append({"attributeKey": attr["key"], "attributeValue": attr["value"]})
            data["requiredAttributes"] = attrs
        if claim_mappings is not None:
            data["claimMappings"] = {}
            for claim in claim_mappings:
                data["claimMappings"][claim["key"]] = claim["value"]

    elif auth_type == "openshift":
        if not new_name and (not rhacs_url or rhacs_url == data.get("uiEndpoint")):
            module.exit_json(changed=False, id=id_to_update)

    elif auth_type == "saml":
        mode = auth_conf["conf"].get("mode")
        service_provider_issuer = auth_conf["conf"].get("service_provider_issuer")
        metadata_url = auth_conf["conf"].get("metadata_url")
        idp_issuer = auth_conf["conf"].get("idp_issuer")
        idp_sso_url = auth_conf["conf"].get("idp_sso_url")
        idp_nameid_format = auth_conf["conf"].get("idp_nameid_format")
        idp_certificate = auth_conf["conf"].get("idp_certificate")

        if (
            not new_name
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (
                service_provider_issuer is None
                or service_provider_issuer == conf.get("sp_issuer")
            )
            and (metadata_url is None or metadata_url == conf.get("idp_metadata_url"))
            and (idp_issuer is None or idp_issuer == conf.get("idp_issuer"))
            and (idp_sso_url is None or idp_sso_url == conf.get("idp_sso_url"))
            and (
                idp_nameid_format is None
                or idp_nameid_format == conf.get("idp_nameid_format")
            )
            and (idp_certificate is None or idp_certificate == conf.get("idp_cert_pem"))
        ):
            module.exit_json(changed=False, id=id_to_update)

        if service_provider_issuer is not None:
            data["config"]["sp_issuer"] = service_provider_issuer
        if mode is None:
            if data["config"].get("idp_metadata_url"):
                mode == "dynamic"
            else:
                mode == "static"
        if mode == "dynamic":
            if metadata_url is not None:
                data["config"]["idp_metadata_url"] = metadata_url
            data["config"].pop("idp_issuer", None)
            data["config"].pop("idp_sso_url", None)
            data["config"].pop("idp_nameid_format", None)
            data["config"].pop("idp_cert_pem", None)
        else:  # mode == "static":
            if idp_issuer is not None:
                data["config"]["idp_issuer"] = idp_issuer
            if idp_sso_url is not None:
                data["config"]["idp_sso_url"] = idp_sso_url
            if idp_nameid_format is not None:
                data["config"]["idp_nameid_format"] = idp_nameid_format
            if idp_certificate is not None:
                data["config"]["idp_cert_pem"] = idp_certificate
            data["config"].pop("idp_metadata_url", None)

    else:  # auth_type == "userpki":
        ca_certificate = auth_conf["conf"].get("ca_certificate")

        if (
            not new_name
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (ca_certificate is None or ca_certificate == conf.get("keys"))
        ):
            module.exit_json(changed=False, id=id_to_update)

        if ca_certificate is not None:
            data["config"]["keys"] = ca_certificate

    if rhacs_url:
        data["uiEndpoint"] = rhacs_url

    # In case a rename operation occurred (when new_name is set), and the
    # source and destination objects both existed, then delete the source
    # object
    if id_to_delete:
        module.delete(
            config,
            "authentication provider",
            name_to_delete,
            "/v1/authProviders/{id}".format(id=id_to_delete),
            auto_exit=False,
        )

    # Because a provider cannot be updated after it has been used, delete the
    # provider and then re-create it.
    module.delete(
        config,
        "authentication provider",
        name,
        "/v1/authProviders/{id}".format(id=id_to_update),
        auto_exit=False,
    )
    resp = module.create(
        "authentication provider", name, "/v1/authProviders", data, auto_exit=False
    )
    module.exit_json(changed=True, id=resp.get("id", ""))


if __name__ == "__main__":
    main()
