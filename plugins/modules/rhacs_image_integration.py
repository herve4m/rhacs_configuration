#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_image_integration
short_description: Manage image vulnerability scanner and registry integration
description:
  - Create, delete, and update Red Hat Advanced Cluster Security for Kubernetes
    (RHACS) integration with image vulnerability scanners and container
    registries.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description: Name of the image integration configuration.
    required: true
    type: str
  new_name:
    description:
      - New name for the integration configuration.
      - Setting this option changes the name of the configuration, which
        current name is provided in the O(name) parameter.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  type:
    description:
      - Type of the image vulnerability scanner or the registry.
      - You cannot change the type of an integration after creation.
      - Each type of integration requires a set of parameters grouped in
        a dedicated section.
        For example, you configure the RHACS integration with Amazon Elastic
        Container Registry (ECR) by setting the O(type) parameter to V(ecr),
        and by providing the configuration for ECR in the O(ecr) section.
    required: true
    type: str
    choices:
      - docker
      - stackrox
      - clairify
      - rhel
      - quay
      - ecr
      - google
      - artifactregistry
      - azure
      - artifactory
      - clair
      - nexus
      - ibm
  run_test:
    description:
      - Whether to test the validity of the configuration before creating the
        integration resource in RHACS.
    type: bool
    default: false
  docker:
    description:
      - Configuration for the integration with Docker-compatible container
        registries, such as the Red Hat Ecosystem Catalog, Azure Container
        Registry, JFrog Artifactory, or Sonatype Nexus Repository.
      - Required when you set the O(type) parameter to V(docker), V(rhel),
        V(azure), V(artifactory), or V(nexus).
    type: dict
    aliases:
      - rhel
      - azure
      - artifactory
      - nexus
    suboptions:
      endpoint:
        description:
          - URL to connect to the registry.
          - The parameter is required when creating the integration.
          - If you do not provide the value in the task, then the module uses
            the value of the E(DOCKER_HOST) environment variable.
        type: str
        aliases:
          - docker_url
          - docker_host
      validate_certs:
        description:
          - Whether to allow insecure connections to the remote registry.
          - If V(false), then the module does not validate TLS certificates.
          - If you do not provide the value in the task, then the module uses
            the value of the E(DOCKER_TLS_VERIFY) environment variable.
          - V(true) by default.
        type: bool
        aliases:
          - tls_verify
      username:
        description:
          - The username to use for authenticating with the remote registry.
          - If you do not set the O(docker.username) parameter, then RHACS uses
            an anonymous access to the remote registry.
          - If you define the O(docker.username) parameter, then you must also
            define the O(docker.password) parameter.
        type: str
      password:
        description:
          - The password to use for authenticating with the remote registry.
          - If you define the O(docker.password) parameter, then you must also
            define the O(docker.username) parameter.
        type: str
  clairify:
    description:
      - Configuration for the integration with StackRox Scanner.
      - Required when you set the O(type) parameter to V(clairify) or to
        V(stackrox).
    type: dict
    aliases:
      - stackrox
    suboptions:
      endpoint:
        description:
          - URL to connect to the scanner.
          - The parameter is required when creating the integration.
        type: str
      grpc_endpoint:
        description:
          - URL to connect to the gRPC endpoint that RHACS uses for node
            scanning.
        type: str
      concurrent_scans:
        description:
          - Number of image scans that RHACS can initiate at the same time.
          - If V(0), then RHACS uses the default number of concurrent scans.
          - V(0) by default.
        type: int
      category:
        description:
          - The O(clairify.category) parameter specifies if the StackRox
            Scanner must be used for scanning container images (V(SCANNER)),
            cluster nodes (V(NODE_SCANNER)), or both (V(BOTH)).
          - V(BOTH) by default.
        type: str
        choices:
          - NODE_SCANNER
          - SCANNER
          - BOTH
  quay:
    description:
      - Configuration for the integration with Quay container registry.
      - Required when O(type=quay).
    type: dict
    suboptions:
      quay_host:
        description:
          - URL to connect to the registry, such as V(quay.io).
          - The parameter is required when creating the integration.
          - If you do not provide the value in the task, then the module uses
            the value of the E(QUAY_HOST) environment variable.
        type: str
      validate_certs:
        description:
          - Whether to allow insecure connections to the remote registry.
          - If V(false), then the module does not validate TLS certificates.
          - If you do not provide the value in the task, then the module uses
            the value of the E(QUAY_VERIFY_SSL) environment variable.
          - V(true) by default.
        type: bool
        aliases:
          - tls_verify
      username:
        description:
          - The Quay robot account username to use for authenticating with the
            Quay container registry.
          - For accessing public repositories, omit the O(quay.username)
            parameter.
          - If you define the O(quay.username) parameter, then you must also
            define the O(quay.password) parameter.
          - If you do not provide the value in the task, then the module uses
            the value of the E(QUAY_USERNAME) environment variable.
        type: str
        aliases:
          - quay_username
      password:
        description:
          - The Quay robot account password to use for authenticating with the
            Quay container registry.
          - If you define the O(quay.password) parameter, then you must also
            define the O(quay.username) parameter.
          - If you do not provide the value in the task, then the module uses
            the value of the E(QUAY_PASSWORD) environment variable.
        type: str
        aliases:
          - quay_password
      oauth_token:
        description:
          - OAuth access token to use for authenticating with the Quay
            container registry for scanning images.
          - The O(quay.oauth_token) parameter is required when you set the
            O(quay.category) parameter to V(SCANNER) or V(BOTH).
          - If you do not provide the value in the task, then the module uses
            the value of the E(QUAY_TOKEN) environment variable.
        type: str
        aliases:
          - quay_token
      category:
        description:
          - The O(quay.category) parameter specifies if Quay must
            be used as a container registry (V(REGISTRY)), for scanning
            container images (V(SCANNER)), or for both (V(BOTH)).
          - You cannot use the O(quay.username) and O(quay.password) parameters
            for authentication when Quay is used for scanning images
            (O(quay.category=SCANNER) or O(quay.category=BOTH)). Instead,
            use an OAuth access token by setting the O(quay.oauth_token)
            parameter.
          - V(BOTH) by default.
        type: str
        choices:
          - REGISTRY
          - SCANNER
          - BOTH
  ecr:
    description:
      - Configuration for the integration with Amazon Elastic Container
        Registry (ECR).
      - Required when O(type=ecr).
    type: dict
    suboptions:
      aws_id:
        description: AWS account number (12 digits).
        type: str
      use_iam:
        description:
          - Assume the container instance IAM role to access the AWS API.
          - If V(false), then the O(ecr.access_key) and O(ecr.secret_key)
            parameters are required.
          - V(true) by default.
        type: bool
      access_key:
        description:
          - AWS access key ID.
          - Required only when O(ecr.use_iam=false).
          - You can also use the E(AWS_ACCESS_KEY_ID) or E(AWS_ACCESS_KEY)
            environment variables in decreasing order of preference.
          - If you define the O(ecr.access_key) parameter, then you must also
            define the O(ecr.secret_key) parameter.
        type: str
        aliases:
          - aws_access_key_id
          - aws_access_key
      secret_key:
        description:
          - AWS secret access key.
          - Required only when O(ecr.use_iam=false).
          - You can also use the E(AWS_SECRET_ACCESS_KEY) or E(AWS_SECRET_KEY)
            environment variables in decreasing order of preference.
          - If you define the O(ecr.secret_key) parameter, then you must also
            define the O(ecr.access_key) parameter.
        type: str
        aliases:
          - aws_secret_access_key
          - aws_secret_key
      endpoint_url:
        description:
          - URL to connect to instead of the default AWS endpoints.
          - If you define the O(ecr.endpoint_url) parameter, then the
            O(ecr.use_assume_role) parameter must be V(false).
          - You can also use the E(AWS_URL) or E(ECR_URL)
            environment variables in decreasing order of preference.
        type: str
        aliases:
          - aws_endpoint_url
      region:
        description:
          - The AWS region to use.
          - You can also use the E(AWS_REGION) or E(AWS_DEFAULT_REGION)
            environment variables in decreasing order of preference.
        type: str
        aliases:
          - aws_region
      use_assume_role:
        description:
          - Assume the IAM role specified in the O(ecr.assume_role_id) or
            O(ecr.assume_role_external_id) parameters.
          - If V(true), then the O(ecr.assume_role_id) or
            O(ecr.assume_role_external_id) parameters are required.
          - If V(true), then you must not set the O(ecr.endpoint_url) parameter.
          - V(false) by default.
        type: bool
      assume_role_id:
        description:
          - Identifier of the role to assume when the O(ecr.use_assume_role)
            parameter is V(true).
        type: str
      assume_role_external_id:
        description:
          - External identifier of the role to assume when
            O(ecr.use_assume_role=true).
        type: str
  google:
    description:
      - Configuration for the integration with Google Container Registry.
      - Required when O(type=google).
    type: dict
    suboptions:
      endpoint:
        description:
          - URL to connect to the registry, such as V(gcr.io).
          - The parameter is required when creating the integration.
        type: str
      project:
        description: Name of the Google Cloud Platform project.
        type: str
      use_workload_id:
        description:
          - Use the workload identity for accessing the Google Cloud API.
          - If you set the O(google.category) parameter to V(SCANNER) or
            V(BOTH), then you must set the O(google.use_workload_id) parameter
            to V(false).
          - If O(google.use_workload_id=false), then you must set the
            O(google.service_account_key) parameter.
          - V(true) by default.
        type: bool
      service_account_key:
        description:
          - Contents of your service account key file, in JSON format, for
            accessing the Google Cloud API.
          - You can use the P(ansible.builtin.file#lookup) lookup plugin
            to read the file from the system.
          - Required only when O(google.use_workload_id=false).
        type: jsonarg
      category:
        description:
          - The O(google.category) parameter specifies if Google Container
            Registry must be used as a container registry (V(REGISTRY)), for
            scanning container images (V(SCANNER)), or for both (V(BOTH)).
          - V(BOTH) by default.
        type: str
        choices:
          - REGISTRY
          - SCANNER
          - BOTH
  artifactregistry:
    description:
      - Configuration for the integration with Google Cloud Artifact Registry.
      - Required when O(type=artifactregistry).
    type: dict
    suboptions:
      endpoint:
        description:
          - URL to connect to the registry, such as V(us-west1-docker.pkg.dev).
          - The parameter is required when creating the integration.
        type: str
      project:
        description: Name of the Google Cloud project.
        type: str
      use_workload_id:
        description:
          - Use the workload identity for accessing the Google Cloud API.
          - If O(artifactregistry.use_workload_id=false), then you must set the
            O(artifactregistry.service_account_key) parameter.
          - V(true) by default.
        type: bool
      service_account_key:
        description:
          - Contents of your service account key file, in JSON format, for
            accessing the Google Cloud API.
          - You can use the P(ansible.builtin.file#lookup) lookup plugin
            to read the file from the system.
          - Required only when O(artifactregistry.use_workload_id=false).
        type: jsonarg
  clair:
    description:
      - Configuration for the integration with the Clair V4 image
        vulnerability scanner.
      - Required when O(type=clair).
    type: dict
    suboptions:
      endpoint:
        description:
          - URL to connect to the scanner.
          - The parameter is required when creating the integration.
        type: str
      validate_certs:
        description:
          - Whether to allow insecure connections to the scanner.
          - If V(false), then the module does not validate TLS certificates.
          - V(false) by default.
        type: bool
        aliases:
          - tls_verify
  ibm:
    description:
      - Configuration for the integration with IBM Cloud Container Registry.
      - Required when O(type=ibm).
    type: dict
    suboptions:
      endpoint:
        description:
          - URL to connect to the registry.
          - The parameter is required when creating the integration.
        type: str
      api_key:
        description:
          - The IBM Cloud API key to authenticate with the IBM Cloud platform.
          - If you do not provide the value in the task, then the module uses
            the value of the E(IC_API_KEY) environment variable.
        type: str
        aliases:
          - ibmcloud_api_key
  state:
    description:
      - If V(absent), then the module deletes the integration configuration.
      - The module does not fail if the configuration does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the integration configuration
        if it does not already exist.
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
- name: Ensure the Quay container registry image integration exists
  herve4m.rhacs_configuration.rhacs_image_integration:
    name: Quay Production
    type: quay
    run_test: false
    quay:
      category: REGISTRY
      quay_host: quay.example.com
      username: rhacsint
      password: My53cr3Tpa55
      validate_certs: false
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the Google Artifact Registry image integration exists
  herve4m.rhacs_configuration.rhacs_image_integration:
    name: Artifact Registry
    type: artifactregistry
    run_test: true
    artifactregistry:
      endpoint: us-central1-docker.pkg.dev
      project: org-project
      use_workload_id: false
      service_account_key: "{{ lookup('ansible.builtin.file', 'key.json') }}"
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the Docker image integration exists
  herve4m.rhacs_configuration.rhacs_image_integration:
    name: Docker development
    type: docker
    run_test: true
    docker:
      endpoint: docker-dev.example.com
      username: rhacsint
      password: My53cr3Tpa55
      validate_certs: true
  state: present
  rhacs_host: central.example.com
  rhacs_username: admin
  rhacs_password: vs9mrD55NP

- name: Ensure the docker image integration does not exist
  herve4m.rhacs_configuration.rhacs_image_integration:
    name: Docker development
    type: docker
  state: absent
  rhacs_host: central.example.com
  rhacs_username: admin
  rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the integration configuration.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

import copy

from ansible.module_utils.basic import env_fallback
from ..module_utils.api_module import APIModule


def parameter_to_API_type(registry_type):
    if registry_type == "clair":
        return "clairV4"
    if registry_type == "stackrox":
        return "clairify"
    return registry_type


def API_type_to_parameter(registry_type):
    if registry_type == "clairV4":
        return "clair"
    return registry_type


def main():

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        type=dict(
            required=True,
            choices=[
                "docker",
                "stackrox",
                "clairify",
                "rhel",
                "quay",
                "ecr",
                "google",
                "artifactregistry",
                "azure",
                "artifactory",
                "clair",
                "nexus",
                "ibm",
            ],
        ),
        run_test=dict(type="bool", default=False),
        docker=dict(
            aliases=["rhel", "azure", "artifactory", "nexus"],
            type="dict",
            options=dict(
                endpoint=dict(
                    aliases=["docker_url", "docker_host"],
                    fallback=(env_fallback, ["DOCKER_HOST"]),
                ),
                username=dict(),
                password=dict(no_log=True),
                validate_certs=dict(
                    type="bool",
                    aliases=["tls_verify"],
                    fallback=(env_fallback, ["DOCKER_TLS_VERIFY"]),
                ),
            ),
            required_together=[("username", "password")],
        ),
        clairify=dict(
            aliases=["stackrox"],
            type="dict",
            options=dict(
                endpoint=dict(),
                grpc_endpoint=dict(),
                concurrent_scans=dict(type="int"),
                category=dict(choices=["NODE_SCANNER", "SCANNER", "BOTH"]),
            ),
        ),
        quay=dict(
            type="dict",
            options=dict(
                quay_host=dict(
                    fallback=(env_fallback, ["QUAY_HOST"]),
                ),
                oauth_token=dict(
                    no_log=True,
                    aliases=["quay_token"],
                    fallback=(env_fallback, ["QUAY_TOKEN"]),
                ),
                validate_certs=dict(
                    type="bool",
                    aliases=["tls_verify"],
                    fallback=(env_fallback, ["QUAY_VERIFY_SSL"]),
                ),
                username=dict(
                    aliases=["quay_username"], fallback=(env_fallback, ["QUAY_USERNAME"])
                ),
                password=dict(
                    no_log=True,
                    aliases=["quay_password"],
                    fallback=(env_fallback, ["QUAY_PASSWORD"]),
                ),
                category=dict(choices=["REGISTRY", "SCANNER", "BOTH"]),
            ),
            required_together=[("username", "password")],
        ),
        ecr=dict(
            type="dict",
            options=dict(
                aws_id=dict(),
                use_iam=dict(type="bool"),
                access_key=dict(
                    aliases=["aws_access_key_id", "aws_access_key"],
                    fallback=(env_fallback, ["AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY"]),
                    no_log=True,
                ),
                secret_key=dict(
                    aliases=["aws_secret_access_key", "aws_secret_key"],
                    fallback=(env_fallback, ["AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"]),
                    no_log=True,
                ),
                region=dict(
                    aliases=["aws_region"],
                    fallback=(env_fallback, ["AWS_REGION", "AWS_DEFAULT_REGION"]),
                ),
                endpoint_url=dict(
                    aliases=["aws_endpoint_url"],
                    fallback=(env_fallback, ["AWS_URL", "ECR_URL"]),
                ),
                use_assume_role=dict(type="bool"),
                assume_role_id=dict(),
                assume_role_external_id=dict(),
            ),
            required_together=[("access_key", "secret_key")],
        ),
        google=dict(
            type="dict",
            options=dict(
                endpoint=dict(),
                use_workload_id=dict(type="bool"),
                service_account_key=dict(no_log=True, type="jsonarg"),
                project=dict(),
                category=dict(choices=["REGISTRY", "SCANNER", "BOTH"]),
            ),
        ),
        artifactregistry=dict(
            type="dict",
            options=dict(
                endpoint=dict(),
                use_workload_id=dict(type="bool"),
                service_account_key=dict(no_log=True, type="jsonarg"),
                project=dict(),
            ),
        ),
        clair=dict(
            type="dict",
            options=dict(
                endpoint=dict(), validate_certs=dict(type="bool", aliases=["tls_verify"])
            ),
        ),
        ibm=dict(
            type="dict",
            options=dict(
                endpoint=dict(),
                api_key=dict(
                    no_log=True,
                    aliases=["ibmcloud_api_key"],
                    fallback=(env_fallback, ["IC_API_KEY"]),
                ),
            ),
        ),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    new_name = module.params.get("new_name")
    registry_type = module.params.get("type")
    run_test = module.params.get("run_test")
    docker = module.params.get("docker")
    clairify = module.params.get("clairify")
    quay = module.params.get("quay")
    ecr = module.params.get("ecr")
    google = module.params.get("google")
    artifactregistry = module.params.get("artifactregistry")
    clair = module.params.get("clair")
    ibm = module.params.get("ibm")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the image integration configuration
    #
    # GET /v1/imageintegrations
    # {
    #     "integrations": [
    #         {
    #             "id": "05fea766-e2f8-44b3-9959-eaa61a4f7466",
    #             "name": "Public GCR",
    #             "type": "docker",
    #             "categories": [
    #                 "REGISTRY"
    #             ],
    #             "docker": {
    #                 "endpoint": "gcr.io",
    #                 "username": "",
    #                 "password": "******",
    #                 "insecure": false
    #             },
    #             "autogenerated": false,
    #             "clusterId": "",
    #             "skipTestIntegration": false,
    #             "source": null
    #         },
    #         {
    #             "id": "5febb194-a21d-4109-9fad-6880dd632adc",
    #             "name": "Public Amazon ECR",
    #             "type": "docker",
    #             "categories": [
    #                 "REGISTRY"
    #             ],
    #             "docker": {
    #                 "endpoint": "public.ecr.aws",
    #                 "username": "",
    #                 "password": "******",
    #                 "insecure": false
    #             },
    #             "autogenerated": false,
    #             "clusterId": "",
    #             "skipTestIntegration": false,
    #             "source": null
    #         },
    #         ...
    #     ]
    # }

    c = module.get_object_path("/v1/imageintegrations")
    integrations = c.get("integrations", [])

    # Retrieve the integration configurations for the two given names
    config = module.get_item_from_resource_list(name, integrations)
    new_config = module.get_item_from_resource_list(new_name, integrations)

    # Remove the configuration
    if state == "absent":
        id = config.get("id", "") if config else ""
        module.delete(
            config,
            "image integration configuration",
            name,
            "/v1/imageintegrations/{id}".format(id=id),
        )

    if not config and new_config:
        config = new_config
        name = new_name
        new_config = new_name = None

    if registry_type in ("stackrox", "clairify"):
        reg_conf = {
            "conf": clairify,
            "current_conf": config.get("clairify", {}) if config else {},
            "conf_name": "clairify",
        }
    elif registry_type == "quay":
        reg_conf = {
            "conf": quay,
            "current_conf": config.get("quay", {}) if config else {},
            "conf_name": "quay",
        }
    elif registry_type == "ecr":
        reg_conf = {
            "conf": ecr,
            "current_conf": config.get("ecr", {}) if config else {},
            "conf_name": "ecr",
        }
    elif registry_type == "google":
        reg_conf = {
            "conf": google,
            "current_conf": config.get("google", {}) if config else {},
            "conf_name": "google",
        }
    elif registry_type == "artifactregistry":
        reg_conf = {
            "conf": artifactregistry,
            "current_conf": config.get("google", {}) if config else {},
            "conf_name": "artifactregistry",
        }
    elif registry_type == "clair":
        reg_conf = {
            "conf": clair,
            "current_conf": config.get("clairV4", {}) if config else {},
            "conf_name": "clair",
        }
    elif registry_type == "ibm":
        reg_conf = {
            "conf": ibm,
            "current_conf": config.get("ibm", {}) if config else {},
            "conf_name": "ibm",
        }
    else:  # registry_type in ("docker", "rhel", "azure", "artifactory", "nexus"):
        reg_conf = {
            "conf": docker,
            "current_conf": config.get("docker", {}) if config else {},
            "conf_name": "docker",
        }

    # Create the image integration configuration
    if not config and not new_config:
        name = new_name if new_name else name

        # Verify that the user provided the registry configuration parameters
        if reg_conf["conf"] is None:
            module.fail_json(
                msg="type is {t} but the `{reg}' parameter is missing".format(
                    t=registry_type, reg=reg_conf["conf_name"]
                )
            )
        # Build the data to send to the API to create the configuration
        new_fields = {
            "name": name,
            "type": parameter_to_API_type(registry_type),
            "autogenerated": False,
            "clusterId": "",
            "skipTestIntegration": not run_test if run_test is not None else True,
        }

        if reg_conf["conf_name"] == "clairify":
            endpoint = reg_conf["conf"].get("endpoint")
            grpc_endpoint = reg_conf["conf"].get("grpc_endpoint")
            concurrent_scans = reg_conf["conf"].get("concurrent_scans")
            category = reg_conf["conf"].get("category")

            if endpoint is None:
                module.fail_json(
                    msg="missing required `{reg}' argument: endpoint".format(
                        reg=reg_conf["conf_name"]
                    )
                )
            if concurrent_scans is not None and concurrent_scans < 0:
                module.fail_json(
                    msg=(
                        "the `concurrent_scans' parameter must be 0 or " "greater: {scan}"
                    ).format(scan=concurrent_scans)
                )

            new_fields["clairify"] = {
                "endpoint": endpoint,
                "grpcEndpoint": grpc_endpoint if grpc_endpoint else "",
                "numConcurrentScans": concurrent_scans if concurrent_scans else 0,
            }
            if category == "SCANNER":
                new_fields["categories"] = ["SCANNER"]
            elif category == "NODE_SCANNER":
                new_fields["categories"] = ["NODE_SCANNER"]
            else:
                new_fields["categories"] = ["SCANNER", "NODE_SCANNER"]

        elif reg_conf["conf_name"] == "quay":
            quay_host = reg_conf["conf"].get("quay_host")
            username = reg_conf["conf"].get("username")
            password = reg_conf["conf"].get("password")
            validate_certs = reg_conf["conf"].get("validate_certs")
            oauth_token = reg_conf["conf"].get("oauth_token")
            category = reg_conf["conf"].get("category")

            if quay_host is None:
                module.fail_json(
                    msg="missing required `{reg}' argument: quay_host".format(
                        reg=reg_conf["conf_name"]
                    )
                )
            if category == "SCANNER" and username:
                module.fail_json(
                    msg=(
                        "you cannot use `username'/`password' when " "`category' is `SCANNER'"
                    )
                )
            if category == "BOTH" and username and not oauth_token:
                module.fail_json(
                    msg=(
                        "you cannot use `username'/`password' without "
                        "`oauth_token' when `category' is `BOTH'"
                    )
                )

            new_fields["quay"] = {
                "endpoint": quay_host,
                "oauthToken": oauth_token if oauth_token else "",
                "insecure": not validate_certs if validate_certs is not None else False,
            }
            if username:
                new_fields["quay"]["registryRobotCredentials"] = {
                    "username": username,
                    "password": password,
                }
            else:
                new_fields["quay"]["registryRobotCredentials"] = None
            if category is None:
                if username:
                    new_fields["categories"] = ["REGISTRY"]
                else:
                    new_fields["categories"] = ["SCANNER", "REGISTRY"]
            elif category == "SCANNER":
                new_fields["categories"] = ["SCANNER"]
            elif category == "REGISTRY":
                new_fields["categories"] = ["REGISTRY"]
            else:
                new_fields["categories"] = ["SCANNER", "REGISTRY"]

        elif reg_conf["conf_name"] == "ecr":
            aws_id = reg_conf["conf"].get("aws_id")
            endpoint_url = reg_conf["conf"].get("endpoint_url")
            region = reg_conf["conf"].get("region")
            use_iam = reg_conf["conf"].get("use_iam")
            access_key = reg_conf["conf"].get("access_key")
            secret_key = reg_conf["conf"].get("secret_key")
            use_assume_role = reg_conf["conf"].get("use_assume_role")
            assume_role_id = reg_conf["conf"].get("assume_role_id")
            assume_role_external_id = reg_conf["conf"].get("assume_role_external_id")

            missing_args = []
            if aws_id is None:
                missing_args.append("aws_id")
            if region is None:
                missing_args.append("region")
            if use_iam is False and not access_key:
                missing_args.append("access_key")
            if use_assume_role is True and (
                not assume_role_id or not assume_role_external_id
            ):
                missing_args.append("assume_role_id or assume_role_external_id")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )
            if endpoint_url and use_assume_role is True:
                module.fail_json(
                    msg=(
                        "in `{reg}', when `endpoint_url' is set, "
                        "`use_assume_role' must be false"
                    ).format(reg=reg_conf["conf_name"])
                )

            new_fields["ecr"] = {
                "registryId": aws_id,
                "accessKeyId": access_key if access_key else "",
                "secretAccessKey": secret_key if secret_key else "",
                "region": region,
                "useIam": use_iam if use_iam is not None else True,
                "endpoint": endpoint_url if endpoint_url else "",
                "useAssumeRole": use_assume_role if use_assume_role is not None else False,
                "assumeRoleId": assume_role_id if assume_role_id else "",
                "assumeRoleExternalId": (
                    assume_role_external_id if assume_role_external_id else ""
                ),
                "authorizationData": None,
            }
            new_fields["categories"] = ["REGISTRY"]

        elif reg_conf["conf_name"] == "google":
            endpoint = reg_conf["conf"].get("endpoint")
            use_workload_id = reg_conf["conf"].get("use_workload_id")
            service_account_key = reg_conf["conf"].get("service_account_key")
            project = reg_conf["conf"].get("project")
            category = reg_conf["conf"].get("category")

            missing_args = []
            if endpoint is None:
                missing_args.append("endpoint")
            if project is None:
                missing_args.append("project")
            if use_workload_id is False and not service_account_key:
                missing_args.append("service_account_key")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )
            if category in ("SCANNER", "BOTH"):
                if use_workload_id is None or use_workload_id is True:
                    module.fail_json(
                        msg=(
                            "the `SCANNER' and `BOTH' categories "
                            "cannot be used when `use_workload_id' is true"
                        )
                    )
                use_workload_id = False
            elif use_workload_id is None:
                use_workload_id = False if service_account_key else True

            new_fields["google"] = {
                "endpoint": endpoint,
                "project": project,
                "wifEnabled": use_workload_id,
                "serviceAccount": (
                    service_account_key
                    if service_account_key and use_workload_id is False
                    else ""
                ),
            }
            if category is None:
                if use_workload_id:
                    new_fields["categories"] = ["REGISTRY"]
                else:
                    new_fields["categories"] = ["SCANNER", "REGISTRY"]
            elif category == "SCANNER":
                new_fields["categories"] = ["SCANNER"]
            elif category == "REGISTRY":
                new_fields["categories"] = ["REGISTRY"]
            else:
                new_fields["categories"] = ["SCANNER", "REGISTRY"]

        elif reg_conf["conf_name"] == "artifactregistry":
            endpoint = reg_conf["conf"].get("endpoint")
            use_workload_id = reg_conf["conf"].get("use_workload_id")
            service_account_key = reg_conf["conf"].get("service_account_key")
            project = reg_conf["conf"].get("project")

            missing_args = []
            if endpoint is None:
                missing_args.append("endpoint")
            if project is None:
                missing_args.append("project")
            if use_workload_id is False and not service_account_key:
                missing_args.append("service_account_key")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )
            if use_workload_id is None:
                use_workload_id = False if service_account_key else True

            new_fields["google"] = {
                "endpoint": endpoint,
                "project": project,
                "wifEnabled": use_workload_id,
                "serviceAccount": (
                    service_account_key
                    if service_account_key and use_workload_id is False
                    else ""
                ),
            }
            new_fields["categories"] = ["REGISTRY"]
        elif reg_conf["conf_name"] == "clair":
            endpoint = reg_conf["conf"].get("endpoint")
            validate_certs = reg_conf["conf"].get("validate_certs")

            if endpoint is None:
                module.fail_json(
                    msg="missing required `{reg}' argument: endpoint".format(
                        reg=reg_conf["conf_name"]
                    )
                )

            new_fields["clairV4"] = {
                "endpoint": endpoint,
                "insecure": not validate_certs if validate_certs is not None else False,
            }
            new_fields["categories"] = ["SCANNER"]
        elif reg_conf["conf_name"] == "ibm":
            endpoint = reg_conf["conf"].get("endpoint")
            api_key = reg_conf["conf"].get("api_key")

            missing_args = []
            if endpoint is None:
                missing_args.append("endpoint")
            if api_key is None:
                missing_args.append("api_key")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )

            new_fields["ibm"] = {
                "endpoint": endpoint,
                "apiKey": api_key,
            }
            new_fields["categories"] = ["REGISTRY"]
        else:  # reg_conf["conf_name"] == "docker":
            endpoint = reg_conf["conf"].get("endpoint")
            username = reg_conf["conf"].get("username")
            password = reg_conf["conf"].get("password")
            validate_certs = reg_conf["conf"].get("validate_certs")

            missing_args = []
            if endpoint is None:
                missing_args.append("endpoint")
            if username is None:
                missing_args.append("username")
            if password is None:
                missing_args.append("password")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )

            new_fields["docker"] = {
                "endpoint": endpoint,
                "username": username,
                "password": password,
                "insecure": not validate_certs if validate_certs is not None else False,
            }
            new_fields["categories"] = ["REGISTRY"]

        resp = module.create(
            "image integration configuration",
            name,
            "/v1/imageintegrations",
            new_fields,
            auto_exit=False,
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

    if parameter_to_API_type(registry_type) != config.get("type"):
        module.fail_json(
            msg=(
                "cannot change the `type' parameter of an existing "
                "image integration configuration: current type is {t}, "
                "requested type is {rt}"
            ).format(t=API_type_to_parameter(config.get("type")), rt=registry_type)
        )

    # Build the data to send to the API to update the configuration
    new_fields = {
        "config": copy.deepcopy(config),
        "updatePassword": False,
    }
    new_fields["config"]["name"] = name
    new_fields["config"]["id"] = id_to_update
    new_fields["config"]["skipTestIntegration"] = (
        not run_test if run_test is not None else True
    )

    # Compare the object with the requested configuration to verify whether
    # an update is required
    if reg_conf["conf"] is None:
        if not new_name:
            module.exit_json(changed=False, id=id_to_update)

    elif reg_conf["conf_name"] == "clairify":
        endpoint = reg_conf["conf"].get("endpoint")
        grpc_endpoint = reg_conf["conf"].get("grpc_endpoint")
        concurrent_scans = reg_conf["conf"].get("concurrent_scans")
        category = reg_conf["conf"].get("category")

        if (
            not new_name
            and (endpoint is None or endpoint == reg_conf["current_conf"].get("endpoint"))
            and (
                grpc_endpoint is None
                or grpc_endpoint == reg_conf["current_conf"].get("grpcEndpoint")
            )
            and (
                concurrent_scans is None
                or concurrent_scans == reg_conf["current_conf"].get("numConcurrentScans")
            )
        ):
            if category is None:
                module.exit_json(changed=False, id=id_to_update)
            if category == "BOTH":
                req_cat = set(["NODE_SCANNER", "SCANNER"])
            else:
                req_cat = set([category])
            if req_cat == set(config.get("categories", [])):
                module.exit_json(changed=False, id=id_to_update)

        if endpoint is not None:
            new_fields["config"]["clairify"]["endpoint"] = endpoint
        if grpc_endpoint is not None:
            new_fields["config"]["clairify"]["grpcEndpoint"] = grpc_endpoint
        if concurrent_scans is not None:
            if concurrent_scans < 0:
                module.fail_json(
                    msg=(
                        "the `concurrent_scans' parameter must be 0 or " "greater: {scan}"
                    ).format(scan=concurrent_scans)
                )
            new_fields["config"]["clairify"]["numConcurrentScans"] = concurrent_scans
        if category is not None:
            if category == "BOTH":
                new_fields["config"]["categories"] = ["NODE_SCANNER", "SCANNER"]
            else:
                new_fields["config"]["categories"] = [category]

    elif reg_conf["conf_name"] == "quay":
        quay_host = reg_conf["conf"].get("quay_host")
        username = reg_conf["conf"].get("username")
        password = reg_conf["conf"].get("password")
        validate_certs = reg_conf["conf"].get("validate_certs")
        oauth_token = reg_conf["conf"].get("oauth_token")
        category = reg_conf["conf"].get("category")

        if (
            not new_name
            and not password
            and not oauth_token
            and (quay_host is None or quay_host == reg_conf["current_conf"].get("endpoint"))
            and (
                username is None
                or username
                == reg_conf["current_conf"]
                .get("registryRobotCredentials", {})
                .get("username")
            )
            and (
                validate_certs is None
                or validate_certs != reg_conf["current_conf"].get("insecure")
            )
        ):
            if category is None:
                module.exit_json(changed=False, id=id_to_update)
            if category == "BOTH":
                req_cat = set(["REGISTRY", "SCANNER"])
            else:
                req_cat = set([category])
            if req_cat == set(config.get("categories", [])):
                module.exit_json(changed=False, id=id_to_update)

        if category == "SCANNER":
            if username:
                module.fail_json(
                    msg="you cannot use `username'/`password' when `category' is `SCANNER'"
                )
            new_fields["config"]["quay"]["registryRobotCredentials"] = None
            new_fields["updatePassword"] = True
        if category == "BOTH" and username and not oauth_token:
            module.fail_json(
                msg=(
                    "you cannot use `username'/`password' without "
                    "`oauth_token' when `category' is `BOTH'"
                )
            )

        if quay_host is not None:
            new_fields["config"]["quay"]["endpoint"] = quay_host
        if oauth_token:
            new_fields["config"]["quay"]["oauthToken"] = oauth_token
            new_fields["updatePassword"] = True
        else:
            new_fields["config"]["quay"]["oauthToken"] = ""
        if validate_certs is not None:
            new_fields["config"]["quay"]["insecure"] = not validate_certs
        if username is not None:
            new_fields["config"]["quay"]["registryRobotCredentials"] = {
                "username": username,
                "password": "",
            }
        if password:
            new_fields["config"]["quay"]["registryRobotCredentials"]["password"] = password
            new_fields["updatePassword"] = True
        elif new_fields["config"]["quay"]["registryRobotCredentials"]:
            new_fields["config"]["quay"]["registryRobotCredentials"]["password"] = ""
        if category is not None:
            if category == "BOTH":
                new_fields["config"]["categories"] = ["REGISTRY", "SCANNER"]
            else:
                new_fields["config"]["categories"] = [category]

    elif reg_conf["conf_name"] == "ecr":
        aws_id = reg_conf["conf"].get("aws_id")
        endpoint_url = reg_conf["conf"].get("endpoint_url")
        region = reg_conf["conf"].get("region")
        use_iam = reg_conf["conf"].get("use_iam")
        access_key = reg_conf["conf"].get("access_key")
        secret_key = reg_conf["conf"].get("secret_key")
        use_assume_role = reg_conf["conf"].get("use_assume_role")
        assume_role_id = reg_conf["conf"].get("assume_role_id")
        assume_role_external_id = reg_conf["conf"].get("assume_role_external_id")

        if (
            not new_name
            and not access_key
            and not secret_key
            and (aws_id is None or aws_id == reg_conf["current_conf"].get("registryId"))
            and (
                endpoint_url is None
                or endpoint_url == reg_conf["current_conf"].get("endpoint")
            )
            and (region is None or region == reg_conf["current_conf"].get("region"))
            and (use_iam is None or use_iam == reg_conf["current_conf"].get("useIam"))
            and (
                use_assume_role is None
                or use_assume_role == reg_conf["current_conf"].get("useAssumeRole")
            )
            and (
                assume_role_id is None
                or assume_role_id == reg_conf["current_conf"].get("assumeRoleId")
            )
            and (
                assume_role_external_id is None
                or assume_role_external_id
                == reg_conf["current_conf"].get("assumeRoleExternalId")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)
        if use_assume_role is True and (
            endpoint_url
            or (endpoint_url is None and reg_conf["current_conf"].get("endpoint"))
        ):
            module.fail_json(
                msg=(
                    "in `{reg}', when `endpoint_url' is set, "
                    "`use_assume_role' must be false"
                ).format(reg=reg_conf["conf_name"])
            )

        if aws_id is not None:
            new_fields["config"]["ecr"]["registryId"] = aws_id
        if endpoint_url is not None and endpoint_url != reg_conf["conf"].get("endpoint"):
            new_fields["config"]["ecr"]["endpoint"] = endpoint_url
            new_fields["updatePassword"] = True
        if region is not None:
            new_fields["config"]["ecr"]["region"] = region
        if use_iam is not None:
            new_fields["config"]["ecr"]["useIam"] = use_iam
        if access_key:
            new_fields["config"]["ecr"]["accessKeyId"] = access_key
            new_fields["updatePassword"] = True
        else:
            new_fields["config"]["ecr"]["accessKeyId"] = ""
        if secret_key:
            new_fields["config"]["ecr"]["secretAccessKey"] = secret_key
            new_fields["updatePassword"] = True
        else:
            new_fields["config"]["ecr"]["secretAccessKey"] = ""
        if use_assume_role is not None:
            new_fields["config"]["ecr"]["useAssumeRole"] = use_assume_role
        if assume_role_id is not None:
            new_fields["config"]["ecr"]["assumeRoleId"] = assume_role_id
        if assume_role_external_id is not None:
            new_fields["config"]["ecr"]["assumeRoleExternalId"] = assume_role_external_id

    elif reg_conf["conf_name"] == "google":
        endpoint = reg_conf["conf"].get("endpoint")
        use_workload_id = reg_conf["conf"].get("use_workload_id")
        service_account_key = reg_conf["conf"].get("service_account_key")
        project = reg_conf["conf"].get("project")
        category = reg_conf["conf"].get("category")

        if (
            not new_name
            and not service_account_key
            and (endpoint is None or endpoint == reg_conf["current_conf"].get("endpoint"))
            and (
                use_workload_id is None
                or use_workload_id == reg_conf["current_conf"].get("wifEnabled")
            )
            and (project is None or project == reg_conf["current_conf"].get("project"))
        ):
            if category is None:
                module.exit_json(changed=False, id=id_to_update)
            if category == "BOTH":
                req_cat = set(["REGISTRY", "SCANNER"])
            else:
                req_cat = set([category])
            if req_cat == set(config.get("categories", [])):
                module.exit_json(changed=False, id=id_to_update)
        if category in ("SCANNER", "BOTH") and (
            use_workload_id is True
            or (
                use_workload_id is None and reg_conf["current_conf"].get("wifEnabled") is True
            )
        ):
            module.fail_json(
                msg=(
                    "the `SCANNER' and `BOTH' categories "
                    "cannot be used when `use_workload_id' is true"
                )
            )

        if endpoint is not None and endpoint != reg_conf["conf"].get("endpoint"):
            if (
                use_workload_id is False
                or (
                    use_workload_id is None
                    and reg_conf["current_conf"].get("wifEnabled") is False
                )
            ) and service_account_key is None:
                module.fail_json(
                    msg=(
                        "to define a new `endpoint', you must set the "
                        "`service_account_key' parameter"
                    )
                )
            new_fields["config"]["google"]["endpoint"] = endpoint
            new_fields["updatePassword"] = True
        if use_workload_id is not None:
            new_fields["config"]["google"]["wifEnabled"] = use_workload_id
        if service_account_key:
            new_fields["config"]["google"]["serviceAccount"] = service_account_key
            new_fields["updatePassword"] = True
        else:
            new_fields["config"]["google"]["serviceAccount"] = ""
        if project is not None:
            new_fields["config"]["google"]["project"] = project
        if category is not None:
            if category == "BOTH":
                new_fields["config"]["categories"] = ["REGISTRY", "SCANNER"]
            else:
                new_fields["config"]["categories"] = [category]

    elif reg_conf["conf_name"] == "artifactregistry":
        endpoint = reg_conf["conf"].get("endpoint")
        use_workload_id = reg_conf["conf"].get("use_workload_id")
        service_account_key = reg_conf["conf"].get("service_account_key")
        project = reg_conf["conf"].get("project")

        if (
            not new_name
            and not service_account_key
            and (endpoint is None or endpoint == reg_conf["current_conf"].get("endpoint"))
            and (
                use_workload_id is None
                or use_workload_id == reg_conf["current_conf"].get("wifEnabled")
            )
            and (project is None or project == reg_conf["current_conf"].get("project"))
        ):
            module.exit_json(changed=False, id=id_to_update)

        if endpoint is not None and endpoint != reg_conf["conf"].get("endpoint"):
            if (
                use_workload_id is False
                or (
                    use_workload_id is None
                    and reg_conf["current_conf"].get("wifEnabled") is False
                )
            ) and service_account_key is None:
                module.fail_json(
                    msg=(
                        "to define a new `endpoint', you must set the "
                        "`service_account_key' parameter"
                    )
                )
            new_fields["config"]["google"]["endpoint"] = endpoint
            new_fields["updatePassword"] = True
        if use_workload_id is not None:
            new_fields["config"]["google"]["wifEnabled"] = use_workload_id
        if service_account_key:
            new_fields["config"]["google"]["serviceAccount"] = service_account_key
            new_fields["updatePassword"] = True
        else:
            new_fields["config"]["google"]["serviceAccount"] = ""
        if project is not None:
            new_fields["config"]["google"]["project"] = project

    elif reg_conf["conf_name"] == "clair":
        endpoint = reg_conf["conf"].get("endpoint")
        validate_certs = reg_conf["conf"].get("validate_certs")

        if (
            not new_name
            and (endpoint is None or endpoint == reg_conf["current_conf"].get("endpoint"))
            and (
                validate_certs is None
                or validate_certs != reg_conf["current_conf"].get("insecure")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        if endpoint is not None:
            new_fields["config"]["clairV4"]["endpoint"] = endpoint
        if validate_certs is not None:
            new_fields["config"]["clairV4"]["insecure"] = not validate_certs

    elif reg_conf["conf_name"] == "ibm":
        endpoint = reg_conf["conf"].get("endpoint")
        api_key = reg_conf["conf"].get("api_key")

        if (
            not new_name
            and not api_key
            and (endpoint is None or endpoint == reg_conf["current_conf"].get("endpoint"))
        ):
            module.exit_json(changed=False, id=id_to_update)

        if endpoint is not None and endpoint != reg_conf["current_conf"].get("endpoint"):
            if not api_key:
                module.fail_json(
                    msg=(
                        "to define a new `endpoint', you must also "
                        "set the `api_key' parameter"
                    )
                )
            new_fields["config"]["ibm"]["endpoint"] = endpoint
            new_fields["updatePassword"] = True
        if api_key:
            new_fields["config"]["ibm"]["apiKey"] = api_key
            new_fields["updatePassword"] = True
        else:
            new_fields["config"]["ibm"]["apiKey"] = ""

    else:  # reg_conf["conf_name"] == "docker":
        endpoint = reg_conf["conf"].get("endpoint")
        username = reg_conf["conf"].get("username")
        password = reg_conf["conf"].get("password")
        validate_certs = reg_conf["conf"].get("validate_certs")

        if (
            not new_name
            and not password
            and (endpoint is None or endpoint == reg_conf["current_conf"].get("endpoint"))
            and (username is None or username == reg_conf["current_conf"].get("username"))
            and (
                validate_certs is None
                or validate_certs != reg_conf["current_conf"].get("insecure")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        if endpoint is not None:
            new_fields["config"]["docker"]["endpoint"] = endpoint
        if username is not None:
            new_fields["config"]["docker"]["username"] = username
        if password:
            new_fields["config"]["docker"]["password"] = password
            new_fields["updatePassword"] = True
        else:
            new_fields["config"]["docker"]["password"] = ""
        if validate_certs is not None:
            new_fields["config"]["docker"]["insecure"] = not validate_certs

    module.patch(
        "image integration configuration",
        name,
        "/v1/imageintegrations/{id}".format(id=id_to_update),
        new_fields,
    )
    # In case a rename operation occurred (when new_name is set), and the
    # source and destination objects both existed, then delete the source
    # object
    if id_to_delete:
        module.delete(
            config,
            "image integration configuration",
            name_to_delete,
            "/v1/imageintegrations/{id}".format(id=id_to_delete),
            auto_exit=False,
        )
    module.exit_json(changed=True, id=id_to_update)


if __name__ == "__main__":
    main()
