#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_notifier_integration
short_description: Manage notification methods
description:
  - Create, delete, and update Red Hat Advanced Cluster Security for Kubernetes
    (RHACS) notification methods.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description: Name of the notification method configuration.
    required: true
    type: str
  new_name:
    description:
      - New name for the notification method configuration.
      - Setting this option changes the name of the configuration, which
        current name is provided in the O(name) parameter.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  type:
    description:
      - Type of the notification method.
      - You cannot change the type after creating the configuration.
      - Each notification method requires a set of parameters grouped in
        a dedicated section.
        For example, you configure the Slack method by setting the O(type)
        parameter to V(slack), and by providing the configuration for Slack in
        the O(slack) section.
    required: true
    type: str
    choices:
      - slack
      - generic
      - jira
      - email
      - google
      - splunk
      - pagerduty
      - sumologic
      - teams
      - aws
      - syslog
      - sentinel
  rhacs_url:
    description:
      - URL of the RHACS web interface.
      - The value of O(rhacs_host) by default.
    type: str
  slack:
    description:
      - Configuration for the Slack notification method.
      - Required when O(type=slack).
    type: dict
    suboptions:
      webhook:
        description:
          - URL of the default Slack webhook, such as
            C(https://hooks.slack.com/services/T00000000/B00000000/XXXX...XXXX)
          - You can overwrite the default webhook by specifying a custom
            webhook in your Kubernetes workloads in an annotation which name
            is defined by the O(slack.annotation_key) parameter.
          - The parameter is required when creating the configuration.
        type: str
      annotation_key:
        description:
          - Name of the annotation that you add to your Kubernetes workloads to
            specify a custom Slack channel webhook.
        type: str
  generic:
    description:
      - Configuration for the generic webhook notification method.
      - Required when O(type=generic).
    type: dict
    suboptions:
      webhook:
        description:
          - Webhook URL.
          - The parameter is required when creating the notification method.
        type: str
      audit_logging:
        description:
          - Whether to receive alerts about all the changes made in RHACS.
          - V(false) by default.
        type: bool
      validate_certs:
        description:
          - Whether to allow insecure connections.
          - If V(false), then the module does not validate TLS certificates.
          - V(true) by default.
        type: bool
        aliases:
          - tls_verify
      ca_cert:
        description:
          - CA certificate for webhook receivers that use an untrusted
            certificate.
          - You can use the P(ansible.builtin.file#lookup) lookup plugin
            to read the file from the system.
          - Instead of providing this CA certificate, you can disable
            certificate validations by setting O(generic.validate_certs=false),
            which is not recommended.
        type: str
      username:
        description:
          - The username to use for basic HTTP authentication.
          - If you define the O(generic.username) parameter, then you must also
            define the O(generic.password) parameter.
        type: str
      password:
        description:
          - The password to use for basic HTTP authentication.
          - If you define the O(generic.password) parameter, then you must also
            define the O(generic.username) parameter.
        type: str
      headers:
        description:
          - "Custom HTTP headers, such as
            C(Authorization: Bearer <access_token>)."
        type: list
        elements: dict
        suboptions:
          key:
            description: Header name, such as V(Authorization).
            type: str
            required: true
          value:
            description: Header value, such as V(Bearer <access_token>).
            type: str
            required: true
      extra_fields:
        description:
          - Include additional key-value pairs in the JSON object that
            RHACS sends to the webhook.
        type: list
        elements: dict
        suboptions:
          key:
            description: Key name.
            type: str
            required: true
          value:
            description: Value to send to the webhook.
            type: str
            required: true
  jira:
    description:
      - Configuration for the Jira notification method.
      - Required when O(type=jira).
    type: dict
    suboptions:
      username:
        description:
          - The username to use for authenticating with Jira.
          - If you define the O(jira.username) parameter, then you must also
            define the O(jira.password) parameter.
          - The parameter is required when creating the notification method.
        type: str
      password:
        description:
          - The password or token to use for authenticating with Jira.
          - If you define the O(jira.password) parameter, then you must also
            define the O(jira.username) parameter.
          - The parameter is required when creating the notification method.
        type: str
      issue_type:
        description:
          - Jira issue type.
          - The parameter is required when creating the notification method.
        type: str
        choices:
          - Epic
          - Story
          - Task
          - Sub-task
          - Bug
      url:
        description:
          - Jira server URL.
          - The parameter is required when creating the notification method.
        type: str
      default_fields_JSON:
        description:
          - If your Jira project defines mandatory custom fields, enter these
            fields as JSON values in the O(jira.default_fields_JSON) parameter.
        type: str
      project:
        description:
          - Default Jira project.
          - You can also define a project per Kubernetes workloads by using an
            annotation. You define the name of the annotation by using the
            O(jira.annotation_key) parameter.
          - The parameter is required when creating the notification method.
        type: str
      annotation_key:
        description:
          - Name of the annotation that you add to your Kubernetes workloads to
            specify a custom Jira project.
        type: str
      mapping_critical:
        description: Custom priority for critical events.
        type: str
      mapping_high:
        description: Custom priority for high severity events.
        type: str
      mapping_medium:
        description: Custom priority for medium severity events.
        type: str
      mapping_low:
        description: Custom priority for low severity events.
        type: str
  email:
    description:
      - Configuration for the email notification method.
      - Required when O(type=email).
    type: dict
    suboptions:
      username:
        description:
          - The username to use for authenticating with the email server.
          - If you define the O(email.username) parameter, then you must also
            define the O(email.password) parameter.
        type: str
      password:
        description:
          - The password to use for authenticating with the email server.
          - If you define the O(email.password) parameter, then you must also
            define the O(email.username) parameter.
        type: str
      server:
        description:
          - Address of the email server, including the port number, such as
            C(smtp.example.com:465).
          - The parameter is required when creating the notification method.
        type: str
      from_header:
        description:
          - Name to appear in the FROM header of email notifications, such as
            C(Security Alerts).
        type: str
      sender:
        description:
          - Email address to appear in the SENDER header of email notifications.
          - The parameter is required when creating the notification method.
        type: str
      recipient:
        description:
          - Email address that receives the email notifications.
          - You can also define a recipient email address per Kubernetes
            workloads by using an annotation. You define the name of the
            annotation by using the O(email.annotation_key) parameter.
          - The parameter is required when creating the notification method.
        type: str
      annotation_key:
        description:
          - Name of the annotation that you add to your Kubernetes workloads to
            specify a custom recipient email address.
        type: str
      validate_certs:
        description:
          - Whether to allow insecure connections to the email server.
          - If V(false), then the module does not validate TLS certificates.
          - To use StartTLS (O(email.starttls=PLAIN) or
            O(email.starttls=LOGIN)), set the O(email.validate_certs) parameter
            to V(false).
          - V(true) by default.
        type: bool
        aliases:
          - tls_verify
      starttls:
        description:
          - Enable or disable StartTLS, and specify the method to use for
            sending the credentials to the email server.
          - V(DISABLED) by default.
        type: str
        choices:
          - DISABLED
          - PLAIN
          - LOGIN
      unauthenticated:
        description:
          - Whether to allow unauthenticated SMTP connections to the email
            server.
          - If V(false), then you must provide the O(email.username) and
            O(email.password) parameters.
          - V(false) by default.
        type: bool
  google:
    description:
      - Configuration for the Google Cloud Security Command Center (Cloud SCC)
        notification method.
      - Required when O(type=google).
    type: dict
    suboptions:
      source_id:
        description:
          - Cloud SCC source ID, such as C(organizations/123/sources/456).
          - The parameter is required when creating the notification method.
        type: str
      use_workload_id:
        description:
          - Use the workload identity for accessing the Google Cloud API.
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
  splunk:
    description:
      - Configuration for the Splunk notification method.
      - Required when O(type=splunk).
    type: dict
    suboptions:
      url:
        description:
          - Splunk HTTP event collector URL. You must specify the port number
            if it is not 443 for HTTPS or 80 for HTTP. You must also add the
            C(/services/collector/event) path at the end of the URL, such as
            C(https://<splunk-server-path>:8088/services/collector/event).
          - If you do not provide the value in the task, then the module uses
            the value of the E(SPLUNK_URL) environment variable.
          - The parameter is required when creating the notification method.
        type: str
      token:
        description:
          - Splunk HTTP event collector token.
          - The parameter is required when creating the notification method.
        type: str
      validate_certs:
        description:
          - Whether to allow insecure connections.
          - If V(false), then the module does not validate TLS certificates.
          - If you do not provide the value in the task, then the module uses
            the value of the E(SPLUNK_VALIDATE_CERTS) environment variable.
          - V(true) by default.
        type: bool
        aliases:
          - tls_verify
      truncate:
        description:
          - Splunk HTTP event collector message length limit in bytes.
          - V(10000) by default.
        type: int
      audit_logging:
        description:
          - Whether to receive alerts about all the changes made in RHACS.
          - V(false) by default.
        type: bool
      source_type_alert:
        description:
          - Specify a custom source type for alert events.
          - V(stackrox-alert) by default.
        type: str
      source_type_audit:
        description:
          - Specify a custom source type for audit events.
          - V(stackrox-audit-message) by default.
        type: str
  pagerduty:
    description:
      - Configuration for the PagerDuty notification method.
      - Required when O(type=pagerduty).
    type: dict
    suboptions:
      api_key:
        description:
          - PagerDuty integration key.
          - The parameter is required when creating the notification method.
        type: str
  sumologic:
    description:
      - Configuration for the Sumo Logic notification method.
      - Required when O(type=sumologic).
    type: dict
    suboptions:
      url:
        description:
          - HTTP collector source address, such as
            C(https://endpoint.sumologic.com/receiver/v1/http/<token>)
          - If you do not provide the value in the task, then the module uses
            the value of the E(SUMOLOGIC_URL) environment variable.
          - The parameter is required when creating the notification method.
        type: str
      validate_certs:
        description:
          - Whether to allow insecure connections.
          - If V(false), then the module does not validate TLS certificates.
          - V(true) by default.
        type: bool
        aliases:
          - tls_verify
  teams:
    description:
      - Configuration for the Microsoft Teams notification method.
      - Required when O(type=teams).
    type: dict
    suboptions:
      url:
        description:
          - Default Microsoft Teams webhook, such as
            C(https://outlook.office365.com/webhook/EXAMPLE).
          - You can also define a different webhook per Kubernetes
            workloads by using an annotation. You define the name of the
            annotation by using the O(teams.annotation_key) parameter.
          - The parameter is required when creating the notification method.
        type: str
      annotation_key:
        description:
          - Name of the annotation that you add to your Kubernetes workloads to
            specify the Microsoft Teams webhook.
        type: str
  aws:
    description:
      - Configuration for the AWS Security Hub notification method.
      - Required when O(type=aws).
    type: dict
    suboptions:
      aws_id:
        description:
          - AWS account number (12 digits).
          - The parameter is required when creating the notification method.
        type: str
      use_iam:
        description:
          - Assume the container instance IAM role to access the AWS API.
          - If V(false), then the O(aws.access_key) and O(aws.secret_key)
            parameters are required.
          - V(true) by default.
        type: bool
      access_key:
        description:
          - AWS access key ID.
          - Required only when O(aws.use_iam=false).
          - You can also use the E(AWS_ACCESS_KEY_ID) or E(AWS_ACCESS_KEY)
            environment variables in decreasing order of preference.
          - If you define the O(aws.access_key) parameter, then you must also
            define the O(aws.secret_key) parameter.
        type: str
        aliases:
          - aws_access_key_id
          - aws_access_key
      secret_key:
        description:
          - AWS secret access key.
          - Required only when O(aws.use_iam=false).
          - You can also use the E(AWS_SECRET_ACCESS_KEY) or E(AWS_SECRET_KEY)
            environment variables in decreasing order of preference.
          - If you define the O(aws.secret_key) parameter, then you must also
            define the O(aws.access_key) parameter.
        type: str
        aliases:
          - aws_secret_access_key
          - aws_secret_key
      region:
        description:
          - The AWS region to use.
          - You can also use the E(AWS_REGION) or E(AWS_DEFAULT_REGION)
            environment variables in decreasing order of preference.
          - The parameter is required when creating the notification method.
        type: str
        aliases:
          - aws_region
  syslog:
    description:
      - Configuration for the notification method that uses the syslog protocol.
      - Required when O(type=syslog).
    type: dict
    suboptions:
      host:
        description:
          - Address of the receiving host.
          - If you do not provide the value in the task, then the module uses
            the value of the E(SYSLOG_SERVER) environment variable.
          - The parameter is required when creating the notification method.
        type: str
        aliases:
          - server
      port:
        description:
          - Network port number of the receiving host.
          - If you do not provide the value in the task, then the module uses
            the value of the E(SYSLOG_PORT) environment variable.
          - V(514) by default.
        type: int
      facility:
        description:
          - Logging facility.
          - If you do not provide the value in the task, then the module uses
            the value of the E(SYSLOG_FACILITY) environment variable.
          - The parameter is required when creating the notification method.
        type: str
        choices:
          - LOCAL0
          - LOCAL1
          - LOCAL2
          - LOCAL3
          - LOCAL4
          - LOCAL5
          - LOCAL6
          - LOCAL7
      use_tls:
        description:
          - Whether to use TLS for communicating with the syslog server.
          - V(false) by default.
        type: bool
      validate_certs:
        description:
          - Whether to allow insecure connections.
          - If V(false), then the module does not validate TLS certificates.
          - V(true) by default.
        type: bool
        aliases:
          - tls_verify
      message_format:
        description:
          - "Specify the format of the messages to send: Common Event Format
            (CEF) or legacy."
          - The parameter is required when creating the notification method.
        type: str
        choices:
          - CEF
          - LEGACY
      extra_fields:
        description:
          - Include additional key-value pairs in the data that RHACS sends to
            the syslog server.
        type: list
        elements: dict
        suboptions:
          key:
            description: Key name.
            type: str
            required: true
          value:
            description: Value to send to syslog.
            type: str
            required: true
  sentinel:
    description:
      - Configuration for the Microsoft Sentinel notification method.
      - Required when O(type=sentinel).
      - The Microsoft Sentinel notification method is only supported with
        StackRox version 4.6 or later.
    type: dict
    suboptions:
      url:
        description:
          - Log ingestion endpoint such as
            C(https://example-sentinel-ou812.eastus-1.ingest.monitor.azure.com).
          - The parameter is required when creating the notification method.
        type: str
      tenant_id:
        description:
          - Directory tenant identifier, such as
            C(1234abce-1234-abcd-1234-abcd1234abcd).
          - The parameter is required when creating the notification method.
        type: str
      client_id:
        description:
          - Application client identifier, such as
            C(abcd1234-abcd-1234-abcd-1234abce1234).
          - The parameter is required when creating the notification method.
        type: str
      secret:
        description:
          - Authentication secret.
          - Mutually exclusive with O(client_cert).
          - One of O(secret) or O(client_cert) is required when creating the
            notification method.
        type: str
      client_cert:
        description:
          - Client certificate for authentication.
          - Mutually exclusive with O(secret).
          - One of O(client_cert) or O(secret) is required when creating the
            notification method.
        type: dict
        suboptions:
          certificate:
            description:
              - Client certificate for authenticating with Microsoft Sentinel.
              - You can use the P(ansible.builtin.file#lookup) lookup plugin
                to read the file from the system.
            required: true
            type: str
          private_key:
            description:
              - Client private key for authenticating with Microsoft Sentinel.
              - You can use the P(ansible.builtin.file#lookup) lookup plugin
                to read the file from the system.
            required: true
            type: str
      alert_data_collection_rule:
        description:
          - Alert data collection rule configuration.
        type: dict
        suboptions:
          rule_stream_name:
            description:
              - Alert data collection rule stream name, such as
                C(your-custom-sentinel-stream-0123456789).
            type: str
          rule_id:
            description:
              - Alert data collection rule identifier, such as
                C(dcr-1234567890abcdef1234567890abcedf).
            type: str
          enabled:
            description:
              - Whether to enable the alert data collection rule configuration.
              - V(false) by default.
            type: bool
      audit_data_collection_rule:
        description:
          - Audit data collection rule configuration.
        type: dict
        suboptions:
          rule_stream_name:
            description:
              - Audit data collection rule stream name, such as
                C(your-custom-sentinel-stream-0123456789).
            type: str
          rule_id:
            description:
              - Audit data collection rule identifier, such as
                C(dcr-1234567890abcdef1234567890abcedf).
            type: str
          enabled:
            description:
              - Whether to enable the audit data collection rule configuration.
              - V(false) by default.
            type: bool
  state:
    description:
      - If V(absent), then the module deletes the notification method
        configuration.
      - The module does not fail if the configuration does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the notification method
        configuration if it does not already exist.
      - If the configuration already exists, then the module updates its state.
    type: str
    default: present
    choices: [absent, present]
notes:
  - The Microsoft Sentinel notification method is only supported with
    StackRox version 4.6 or later.
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
- name: Ensure the email notification method exists
  herve4m.rhacs_configuration.rhacs_notifier_integration:
    name: email notifications
    type: email
    email:
      server: smtp.example.com:465
      username: rhacs
      password: My53cr3Tpa55
      from_header: Security Alerts
      sender: rhacs@example.com
      recipient: security@example.com
      annotation_key: email
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the Google Cloud Security Command Center configuration exists
  herve4m.rhacs_configuration.rhacs_notifier_integration:
    name: Cloud SCC notifications
    type: google
    run_test: true
    google:
      source_id: organizations/123/sources/456
      use_workload_id: false
      service_account_key: "{{ lookup('ansible.builtin.file', 'key.json') }}"
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the Splunk notification method exists
  herve4m.rhacs_configuration.rhacs_notifier_integration:
    name: Splunk notifications
    type: splunk
    splunk:
      url: https://splunk.example.com:8088/services/collector/event
      token: B5A79AAD-D822-46CC-80D1-819F80D7BFB0
      audit_logging: true
      validate_certs: false
  state: present
  rhacs_host: central.example.com
  rhacs_username: admin
  rhacs_password: vs9mrD55NP

- name: Ensure the Splunk notification method does not exist
  herve4m.rhacs_configuration.rhacs_notifier_integration:
    name: Splunk notifications
    type: splunk
  state: absent
  rhacs_host: central.example.com
  rhacs_username: admin
  rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the notification method configuration.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

import re
import copy

from ansible.module_utils.basic import env_fallback
from ..module_utils.api_module import APIModule


def parameter_to_API_type(notify_type):
    if notify_type == "aws":
        return "awsSecurityHub"
    if notify_type == "google":
        return "cscc"
    if notify_type == "sentinel":
        return "microsoftSentinel"
    return notify_type


def API_type_to_parameter(notify_type):
    if notify_type == "awsSecurityHub":
        return "aws"
    if notify_type == "cscc":
        return "google"
    if notify_type == "microsoftSentinel":
        return "sentinel"
    return notify_type


def main():

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        type=dict(
            required=True,
            choices=[
                "slack",
                "generic",
                "jira",
                "email",
                "google",
                "splunk",
                "pagerduty",
                "sumologic",
                "teams",
                "aws",
                "syslog",
                "sentinel",
            ],
        ),
        rhacs_url=dict(),
        slack=dict(
            type="dict",
            options=dict(webhook=dict(), annotation_key=dict(no_log=False)),
        ),
        generic=dict(
            type="dict",
            options=dict(
                webhook=dict(),
                audit_logging=dict(type="bool"),
                validate_certs=dict(
                    type="bool",
                    aliases=["tls_verify"],
                ),
                ca_cert=dict(),
                username=dict(),
                password=dict(no_log=True),
                headers=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        key=dict(required=True, no_log=False),
                        value=dict(required=True),
                    ),
                ),
                extra_fields=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        key=dict(required=True, no_log=False),
                        value=dict(required=True),
                    ),
                ),
            ),
            required_together=[("username", "password")],
        ),
        jira=dict(
            type="dict",
            options=dict(
                username=dict(),
                password=dict(no_log=True),
                issue_type=dict(choices=["Epic", "Story", "Task", "Sub-task", "Bug"]),
                url=dict(),
                mapping_critical=dict(),
                mapping_high=dict(),
                mapping_medium=dict(),
                mapping_low=dict(),
                default_fields_JSON=dict(),
                project=dict(),
                annotation_key=dict(no_log=False),
            ),
            required_together=[("username", "password")],
        ),
        email=dict(
            type="dict",
            options=dict(
                username=dict(),
                password=dict(no_log=True),
                server=dict(),
                from_header=dict(),
                sender=dict(),
                recipient=dict(),
                validate_certs=dict(
                    type="bool",
                    aliases=["tls_verify"],
                ),
                starttls=dict(choices=["DISABLED", "PLAIN", "LOGIN"]),
                unauthenticated=dict(type="bool"),
                annotation_key=dict(no_log=False),
            ),
            required_together=[("username", "password")],
        ),
        google=dict(
            type="dict",
            options=dict(
                source_id=dict(),
                use_workload_id=dict(type="bool"),
                service_account_key=dict(no_log=True, type="jsonarg"),
            ),
        ),
        splunk=dict(
            type="dict",
            options=dict(
                url=dict(fallback=(env_fallback, ["SPLUNK_URL"])),
                token=dict(no_log=True),
                validate_certs=dict(
                    type="bool",
                    aliases=["tls_verify"],
                    fallback=(env_fallback, ["SPLUNK_VALIDATE_CERTS"]),
                ),
                truncate=dict(type="int"),
                audit_logging=dict(type="bool"),
                source_type_alert=dict(),
                source_type_audit=dict(),
            ),
        ),
        pagerduty=dict(
            type="dict",
            options=dict(api_key=dict(no_log=True)),
        ),
        sumologic=dict(
            type="dict",
            options=dict(
                url=dict(fallback=(env_fallback, ["SUMOLOGIC_URL"])),
                validate_certs=dict(
                    type="bool",
                    aliases=["tls_verify"],
                ),
            ),
        ),
        teams=dict(type="dict", options=dict(url=dict(), annotation_key=dict(no_log=False))),
        aws=dict(
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
                    fallback=(
                        env_fallback,
                        ["AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"],
                    ),
                    no_log=True,
                ),
                region=dict(
                    aliases=["aws_region"],
                    fallback=(env_fallback, ["AWS_REGION", "AWS_DEFAULT_REGION"]),
                ),
            ),
            required_together=[("access_key", "secret_key")],
        ),
        syslog=dict(
            type="dict",
            options=dict(
                host=dict(aliases=["server"], fallback=(env_fallback, ["SYSLOG_SERVER"])),
                port=dict(type="int", fallback=(env_fallback, ["SYSLOG_PORT"])),
                facility=dict(
                    choices=[
                        "LOCAL0",
                        "LOCAL1",
                        "LOCAL2",
                        "LOCAL3",
                        "LOCAL4",
                        "LOCAL5",
                        "LOCAL6",
                        "LOCAL7",
                    ],
                    fallback=(env_fallback, ["SYSLOG_FACILITY"]),
                ),
                use_tls=dict(type="bool"),
                validate_certs=dict(
                    type="bool",
                    aliases=["tls_verify"],
                ),
                message_format=dict(choices=["CEF", "LEGACY"]),
                extra_fields=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        key=dict(required=True, no_log=False),
                        value=dict(required=True),
                    ),
                ),
            ),
        ),
        sentinel=dict(
            type="dict",
            options=dict(
                url=dict(),
                tenant_id=dict(),
                client_id=dict(),
                secret=dict(no_log=True),
                client_cert=dict(
                    type="dict",
                    options=dict(
                        certificate=dict(required=True),
                        private_key=dict(required=True, no_log=True),
                    ),
                ),
                alert_data_collection_rule=dict(
                    type="dict",
                    options=dict(
                        rule_stream_name=dict(),
                        rule_id=dict(),
                        enabled=dict(type="bool"),
                    ),
                ),
                audit_data_collection_rule=dict(
                    type="dict",
                    options=dict(
                        rule_stream_name=dict(),
                        rule_id=dict(),
                        enabled=dict(type="bool"),
                    ),
                ),
            ),
            mutually_exclusive=[("secret", "client_cert")],
        ),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    new_name = module.params.get("new_name")
    notify_type = module.params.get("type")
    rhacs_url = module.params.get("rhacs_url")
    slack = module.params.get("slack")
    generic = module.params.get("generic")
    jira = module.params.get("jira")
    email = module.params.get("email")
    google = module.params.get("google")
    splunk = module.params.get("splunk")
    pagerduty = module.params.get("pagerduty")
    sumologic = module.params.get("sumologic")
    teams = module.params.get("teams")
    aws = module.params.get("aws")
    syslog = module.params.get("syslog")
    sentinel = module.params.get("sentinel")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the notifier method configuration
    #
    # GET /v1/notifiers
    # {
    #   "notifiers": [
    #     {
    #       "id": "0263296a-d1bd-42bf-b6b6-4dee998d8fcc",
    #       "name": "email1",
    #       "type": "email",
    #       "uiEndpoint": "https://central.example.com",
    #       "labelKey": "annotationkey",
    #       "labelDefault": "alerts@example.com",
    #       "email": {
    #         "server": "smtp.example.com:465",
    #         "sender": "sender@example.com",
    #         "username": "username",
    #         "password": "******",
    #         "disableTLS": true,
    #         "DEPRECATEDUseStartTLS": false,
    #         "from": "from",
    #         "startTLSAuthMethod": "LOGIN",
    #         "allowUnauthenticatedSmtp": false
    #       },
    #       "notifierSecret": "******",
    #       "traits": null
    #     },
    #     {
    #       "id": "0ab69cc7-301a-4e8f-8761-748b59e652c7",
    #       "name": "slack11",
    #       "type": "slack",
    #       "uiEndpoint": "https://central.example.com",
    #       "labelKey": "annotationkey",
    #       "labelDefault": "https://hooks.slack.com/services/EXAMPLE",
    #       "notifierSecret": "******",
    #       "traits": null
    #     },
    #     {
    #       "id": "d8f69af5-3b52-48e0-9e3f-b610ce7ba436",
    #       "name": "google cloud scc",
    #       "type": "cscc",
    #       "uiEndpoint": "https://central.example.com",
    #       "labelKey": "",
    #       "labelDefault": "",
    #       "cscc": {
    #         "serviceAccount": "******",
    #         "sourceId": "organizations/123/sources/456",
    #         "wifEnabled": true
    #       },
    #       "notifierSecret": "******",
    #       "traits": null
    #     },
    #     {
    #       "id": "a317e4b0-d4fd-49b8-891e-00eaf5cae08d",
    #       "name": "splunk1",
    #       "type": "splunk",
    #       "uiEndpoint": "https://central.example.com",
    #       "labelKey": "",
    #       "labelDefault": "",
    #       "splunk": {
    #         "httpToken": "******",
    #         "httpEndpoint": "collector.example.com",
    #         "insecure": true,
    #         "truncate": "10000",
    #         "auditLoggingEnabled": true,
    #         "sourceTypes": {
    #           "alert": "stackrox-alert",
    #           "audit": "stackrox-audit-message"
    #         }
    #       },
    #       "notifierSecret": "******",
    #       "traits": null
    #     },
    #         ...
    #     ]
    # }

    # Retrieve the configurations for the two given names
    config = module.get_notifier(name)
    new_config = module.get_notifier(new_name)

    # Remove the configuration
    if state == "absent":
        id = config.get("id", "") if config else ""
        module.delete(
            config,
            "notifier method configuration",
            name,
            "/v1/notifiers/{id}".format(id=id),
        )

    if not config and new_config:
        config = new_config
        name = new_name
        new_config = new_name = None

    if notify_type == "slack":
        reg_conf = {
            "conf": slack,
            "current_conf": config if config else {},
            "conf_name": "slack",
            "update_verb": "PUT",
        }
    elif notify_type == "syslog":
        reg_conf = {
            "conf": syslog,
            "current_conf": config.get("syslog", {}) if config else {},
            "conf_name": "syslog",
            "update_verb": "PUT",
        }
    elif notify_type == "jira":
        reg_conf = {
            "conf": jira,
            "current_conf": config.get("jira", {}) if config else {},
            "conf_name": "jira",
            "update_verb": "PATCH",
        }
    elif notify_type == "email":
        reg_conf = {
            "conf": email,
            "current_conf": config.get("email", {}) if config else {},
            "conf_name": "email",
            "update_verb": "PATCH",
        }
    elif notify_type == "google":
        reg_conf = {
            "conf": google,
            "current_conf": config.get("cscc", {}) if config else {},
            "conf_name": "google",
            "update_verb": "PATCH",
        }
    elif notify_type == "splunk":
        reg_conf = {
            "conf": splunk,
            "current_conf": config.get("splunk", {}) if config else {},
            "conf_name": "splunk",
            "update_verb": "PATCH",
        }
    elif notify_type == "pagerduty":
        reg_conf = {
            "conf": pagerduty,
            "current_conf": config.get("pagerduty", {}) if config else {},
            "conf_name": "pagerduty",
            "update_verb": "PATCH",
        }
    elif notify_type == "sumologic":
        reg_conf = {
            "conf": sumologic,
            "current_conf": config.get("sumologic", {}) if config else {},
            "conf_name": "sumologic",
            "update_verb": "PUT",
        }
    elif notify_type == "teams":
        reg_conf = {
            "conf": teams,
            "current_conf": config if config else {},
            "conf_name": "teams",
            "update_verb": "PUT",
        }
    elif notify_type == "aws":
        reg_conf = {
            "conf": aws,
            "current_conf": config.get("awsSecurityHub", {}) if config else {},
            "conf_name": "aws",
            "update_verb": "PATCH",
        }
    elif notify_type == "generic":
        reg_conf = {
            "conf": generic,
            "current_conf": config.get("generic", {}) if config else {},
            "conf_name": "generic",
            "update_verb": "PATCH",
        }
    else:  # notify_type == "sentinel":
        reg_conf = {
            "conf": sentinel,
            "current_conf": config.get("microsoftSentinel", {}) if config else {},
            "conf_name": "sentinel",
            "update_verb": "PATCH",
        }
    # Create the notifier method configuration
    if not config and not new_config:
        name = new_name if new_name else name

        # Verify that the user provided the registry configuration parameters
        if reg_conf["conf"] is None:
            module.fail_json(
                msg="type is {t} but the `{reg}' parameter is missing".format(
                    t=notify_type, reg=reg_conf["conf_name"]
                )
            )

        # Build the data to send to the API to create the configuration
        new_fields = {
            "name": name,
            "type": parameter_to_API_type(notify_type),
            "labelDefault": "",
            "labelKey": "",
            "uiEndpoint": rhacs_url if rhacs_url else module.host_url.geturl(),
        }

        if reg_conf["conf_name"] == "slack":
            webhook = reg_conf["conf"].get("webhook")
            annotation_key = reg_conf["conf"].get("annotation_key")

            if not webhook:
                module.fail_json(
                    msg="missing required `{reg}' argument: webhook".format(
                        reg=reg_conf["conf_name"]
                    )
                )
            new_fields["labelDefault"] = webhook
            new_fields["labelKey"] = annotation_key if annotation_key else ""

        elif reg_conf["conf_name"] == "syslog":
            host = reg_conf["conf"].get("host")
            port = reg_conf["conf"].get("port")
            facility = reg_conf["conf"].get("facility")
            use_tls = reg_conf["conf"].get("use_tls")
            validate_certs = reg_conf["conf"].get("validate_certs")
            message_format = reg_conf["conf"].get("message_format")
            extra_fields = reg_conf["conf"].get("extra_fields")

            missing_args = []
            if host is None:
                missing_args.append("host")
            if facility is None:
                missing_args.append("facility")
            if message_format is None:
                missing_args.append("message_format")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )

            new_fields["syslog"] = {
                "messageFormat": message_format,
                "localFacility": facility,
                "tcpConfig": {
                    "hostname": host,
                    "port": port if port else 514,
                    "useTls": use_tls if use_tls is not None else False,
                    "skipTlsVerify": (
                        not validate_certs if validate_certs is not None else False
                    ),
                },
                "extraFields": [],
            }
            if extra_fields:
                new_fields["syslog"]["extraFields"] = [
                    {"key": field["key"], "value": field["value"]} for field in extra_fields
                ]

        elif reg_conf["conf_name"] == "aws":
            aws_id = reg_conf["conf"].get("aws_id")
            region = reg_conf["conf"].get("region")
            use_iam = reg_conf["conf"].get("use_iam")
            access_key = reg_conf["conf"].get("access_key")
            secret_key = reg_conf["conf"].get("secret_key")

            missing_args = []
            if aws_id is None:
                missing_args.append("aws_id")
            if region is None:
                missing_args.append("region")
            if use_iam is False and not access_key:
                missing_args.append("access_key")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )
            if len(aws_id) != 12:
                module.fail_json(
                    msg=(
                        "the AWS account number (`aws_id') must be 12 "
                        "characters long: {val}"
                    ).format(val=aws_id)
                )
            if access_key:
                if use_iam is None:
                    use_iam = False
                elif use_iam is True:
                    access_key = secret_key = ""

            new_fields["awsSecurityHub"] = {
                "accountId": aws_id,
                "region": region,
                "credentials": {
                    "accessKeyId": access_key if access_key else "",
                    "secretAccessKey": secret_key if secret_key else "",
                    "stsEnabled": use_iam if use_iam is not None else True,
                },
            }

        elif reg_conf["conf_name"] == "google":
            source_id = reg_conf["conf"].get("source_id")
            use_workload_id = reg_conf["conf"].get("use_workload_id")
            service_account_key = reg_conf["conf"].get("service_account_key")

            missing_args = []
            if source_id is None:
                missing_args.append("source_id")
            if use_workload_id is False and not service_account_key:
                missing_args.append("service_account_key")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )
            if not re.match(r"organizations/\d+/sources/\d+$", source_id):
                module.fail_json(
                    msg=(
                        "the cloud SCC source ID (`source_id') must have the "
                        "format `organizations/<num>/sources/<num>': {val}"
                    ).format(val=source_id)
                )
            if service_account_key:
                if use_workload_id is None:
                    use_workload_id = False
                elif use_workload_id is True:
                    service_account_key = ""

            new_fields["cscc"] = {
                "serviceAccount": service_account_key if service_account_key else "",
                "sourceId": source_id,
                "wifEnabled": use_workload_id if use_workload_id is not None else True,
            }

        elif reg_conf["conf_name"] == "jira":
            username = reg_conf["conf"].get("username")
            password = reg_conf["conf"].get("password")
            issue_type = reg_conf["conf"].get("issue_type")
            url = reg_conf["conf"].get("url")
            mapping_critical = reg_conf["conf"].get("mapping_critical")
            mapping_high = reg_conf["conf"].get("mapping_high")
            mapping_medium = reg_conf["conf"].get("mapping_medium")
            mapping_low = reg_conf["conf"].get("mapping_low")
            default_fields_JSON = reg_conf["conf"].get("default_fields_JSON")
            project = reg_conf["conf"].get("project")
            annotation_key = reg_conf["conf"].get("annotation_key")

            missing_args = []
            if username is None:
                missing_args.append("username")
            if password is None:
                missing_args.append("password")
            if issue_type is None:
                missing_args.append("issue_type")
            if url is None:
                missing_args.append("url")
            if project is None:
                missing_args.append("project")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )

            new_fields["jira"] = {
                "username": username,
                "password": password,
                "issueType": issue_type,
                "url": url,
                "defaultFieldsJson": default_fields_JSON if default_fields_JSON else "",
                "disablePriority": True,
            }

            mappings = []
            if mapping_critical:
                new_fields["jira"]["disablePriority"] = False
                mappings.append(
                    {"severity": "CRITICAL_SEVERITY", "priorityName": mapping_critical}
                )
            else:
                mappings.append({"severity": "CRITICAL_SEVERITY", "priorityName": "Highest"})
            if mapping_high:
                new_fields["jira"]["disablePriority"] = False
                mappings.append({"severity": "HIGH_SEVERITY", "priorityName": mapping_high})
            else:
                mappings.append({"severity": "HIGH_SEVERITY", "priorityName": "High"})
            if mapping_medium:
                new_fields["jira"]["disablePriority"] = False
                mappings.append(
                    {"severity": "MEDIUM_SEVERITY", "priorityName": mapping_medium}
                )
            else:
                mappings.append({"severity": "MEDIUM_SEVERITY", "priorityName": "Medium"})
            if mapping_low:
                new_fields["jira"]["disablePriority"] = False
                mappings.append({"severity": "LOW_SEVERITY", "priorityName": mapping_low})
            else:
                mappings.append({"severity": "LOW_SEVERITY", "priorityName": "Low"})
            new_fields["jira"]["priorityMappings"] = mappings
            new_fields["labelDefault"] = project
            new_fields["labelKey"] = annotation_key if annotation_key else ""

        elif reg_conf["conf_name"] == "email":
            username = reg_conf["conf"].get("username")
            password = reg_conf["conf"].get("password")
            server = reg_conf["conf"].get("server")
            from_header = reg_conf["conf"].get("from_header")
            sender = reg_conf["conf"].get("sender")
            recipient = reg_conf["conf"].get("recipient")
            validate_certs = reg_conf["conf"].get("validate_certs")
            starttls = reg_conf["conf"].get("starttls")
            unauthenticated = reg_conf["conf"].get("unauthenticated")
            annotation_key = reg_conf["conf"].get("annotation_key")

            missing_args = []
            if server is None:
                missing_args.append("server")
            if unauthenticated is False and not username:
                missing_args.append("username")
                missing_args.append("password")
            if sender is None:
                missing_args.append("sender")
            if recipient is None:
                missing_args.append("recipient")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )
            if starttls in ("PLAIN", "LOGIN"):
                if validate_certs is True:
                    module.fail_json(
                        msg=(
                            "TLS certificate validation must be disabled "
                            "(`validate_certs: false') when using STARTTLS "
                            "(`starttls: PLAIN' or `starttls: LOGIN')"
                        )
                    )
                validate_certs = False

            new_fields["email"] = {
                "server": server,
                "username": username,
                "password": password,
                "from": from_header if from_header else "",
                "sender": sender,
                "allowUnauthenticatedSmtp": (
                    unauthenticated if unauthenticated is not None else False
                ),
                "disableTLS": (not validate_certs if validate_certs is not None else False),
                "startTLSAuthMethod": starttls if starttls else "DISABLED",
            }
            new_fields["labelDefault"] = recipient
            new_fields["labelKey"] = annotation_key if annotation_key else ""

        elif reg_conf["conf_name"] == "splunk":
            url = reg_conf["conf"].get("url")
            token = reg_conf["conf"].get("token")
            validate_certs = reg_conf["conf"].get("validate_certs")
            truncate = reg_conf["conf"].get("truncate")
            audit_logging = reg_conf["conf"].get("audit_logging")
            source_type_alert = reg_conf["conf"].get("source_type_alert")
            source_type_audit = reg_conf["conf"].get("source_type_audit")

            missing_args = []
            if url is None:
                missing_args.append("url")
            if token is None:
                missing_args.append("token")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )

            new_fields["splunk"] = {
                "httpEndpoint": url,
                "httpToken": token,
                "truncate": truncate if truncate else 10000,
                "insecure": not validate_certs if validate_certs is not None else False,
                "auditLoggingEnabled": (
                    audit_logging if audit_logging is not None else False
                ),
                "sourceTypes": {
                    "alert": (source_type_alert if source_type_alert else "stackrox-alert"),
                    "audit": (
                        source_type_audit if source_type_audit else "stackrox-audit-message"
                    ),
                },
            }

        elif reg_conf["conf_name"] == "pagerduty":
            api_key = reg_conf["conf"].get("api_key")

            if api_key is None:
                module.fail_json(
                    msg="missing required `{reg}' arguments: api_key".format(
                        reg=reg_conf["conf_name"]
                    )
                )

            new_fields["pagerduty"] = {"apiKey": api_key}

        elif reg_conf["conf_name"] == "sumologic":
            url = reg_conf["conf"].get("url")
            validate_certs = reg_conf["conf"].get("validate_certs")

            if url is None:
                module.fail_json(
                    msg="missing required `{reg}' arguments: url".format(
                        reg=reg_conf["conf_name"]
                    )
                )

            new_fields["sumologic"] = {
                "httpSourceAddress": url,
                "skipTLSVerify": (
                    not validate_certs if validate_certs is not None else False
                ),
            }

        elif reg_conf["conf_name"] == "teams":
            url = reg_conf["conf"].get("url")
            annotation_key = reg_conf["conf"].get("annotation_key")

            if url is None:
                module.fail_json(
                    msg="missing required `{reg}' arguments: url".format(
                        reg=reg_conf["conf_name"]
                    )
                )

            new_fields["labelDefault"] = url
            new_fields["labelKey"] = annotation_key if annotation_key else ""

        elif reg_conf["conf_name"] == "generic":
            webhook = reg_conf["conf"].get("webhook")
            audit_logging = reg_conf["conf"].get("audit_logging")
            validate_certs = reg_conf["conf"].get("validate_certs")
            ca_cert = reg_conf["conf"].get("ca_cert")
            username = reg_conf["conf"].get("username")
            password = reg_conf["conf"].get("password")
            headers = reg_conf["conf"].get("headers")
            extra_fields = reg_conf["conf"].get("extra_fields")

            if webhook is None:
                module.fail_json(
                    msg="missing required `{reg}' arguments: webhook".format(
                        reg=reg_conf["conf_name"]
                    )
                )

            new_fields["generic"] = {
                "endpoint": webhook,
                "skipTLSVerify": (
                    not validate_certs if validate_certs is not None else False
                ),
                "auditLoggingEnabled": (
                    audit_logging if audit_logging is not None else False
                ),
                "caCert": ca_cert if ca_cert else "",
                "username": username if username else "",
                "password": password if password else "",
                "headers": [],
                "extraFields": [],
            }
            if extra_fields:
                new_fields["generic"]["extraFields"] = [
                    {"key": field["key"], "value": field["value"]} for field in extra_fields
                ]
            if headers:
                new_fields["generic"]["headers"] = [
                    {"key": header["key"], "value": header["value"]} for header in headers
                ]
        else:  # reg_conf["conf_name"] == "sentinel":
            url = reg_conf["conf"].get("url")
            tenant_id = reg_conf["conf"].get("tenant_id")
            client_id = reg_conf["conf"].get("client_id")
            secret = reg_conf["conf"].get("secret")
            client_cert = reg_conf["conf"].get("client_cert")
            alert_data_collection_rule = reg_conf["conf"].get("alert_data_collection_rule")
            audit_data_collection_rule = reg_conf["conf"].get("audit_data_collection_rule")

            missing_args = []
            if url is None:
                missing_args.append("url")
            if tenant_id is None:
                missing_args.append("tenant_id")
            if client_id is None:
                missing_args.append("client_id")
            if secret is None and client_cert is None:
                missing_args.append("secret or client_cert")
            if missing_args:
                module.fail_json(
                    msg="missing required `{reg}' arguments: {args}".format(
                        reg=reg_conf["conf_name"], args=", ".join(missing_args)
                    )
                )
            if client_cert and (
                not client_cert.get("certificate") or not client_cert.get("private_key")
            ):
                module.fail_json(
                    msg=(
                        "empty required `{reg}.client_cert' arguments: "
                        "certificate or private_key"
                    ).format(reg=reg_conf["conf_name"])
                )
            if (
                alert_data_collection_rule
                and alert_data_collection_rule.get("enabled")
                and (
                    not alert_data_collection_rule.get("rule_stream_name")
                    or not alert_data_collection_rule.get("rule_id")
                )
            ):
                module.fail_json(
                    msg=(
                        "empty required `{reg}.alert_data_collection_rule' arguments: "
                        "rule_stream_name or rule_id"
                    ).format(reg=reg_conf["conf_name"])
                )
            if (
                audit_data_collection_rule
                and audit_data_collection_rule.get("enabled")
                and (
                    not audit_data_collection_rule.get("rule_stream_name")
                    or not audit_data_collection_rule.get("rule_id")
                )
            ):
                module.fail_json(
                    msg=(
                        "empty required `{reg}.audit_data_collection_rule' arguments: "
                        "rule_stream_name or rule_id"
                    ).format(reg=reg_conf["conf_name"])
                )

            new_fields["microsoftSentinel"] = {
                "logIngestionEndpoint": url,
                "directoryTenantId": tenant_id,
                "applicationClientId": client_id,
                "clientCertAuthConfig": {
                    "clientCert": client_cert.get("certificate", "") if client_cert else "",
                    "privateKey": client_cert.get("private_key", "") if client_cert else "",
                },
                "secret": secret if secret else "",
                "alertDcrConfig": {
                    "dataCollectionRuleId": (
                        alert_data_collection_rule.get("rule_id", "")
                        if alert_data_collection_rule
                        else ""
                    ),
                    "streamName": (
                        alert_data_collection_rule.get("rule_stream_name", "")
                        if alert_data_collection_rule
                        else ""
                    ),
                    "enabled": (
                        alert_data_collection_rule.get("enabled", False)
                        if alert_data_collection_rule
                        else False
                    ),
                },
                "auditLogDcrConfig": {
                    "dataCollectionRuleId": (
                        audit_data_collection_rule.get("rule_id", "")
                        if audit_data_collection_rule
                        else ""
                    ),
                    "streamName": (
                        audit_data_collection_rule.get("rule_stream_name", "")
                        if audit_data_collection_rule
                        else ""
                    ),
                    "enabled": (
                        audit_data_collection_rule.get("enabled", False)
                        if audit_data_collection_rule
                        else False
                    ),
                },
            }

        resp = module.create(
            "notifier method configuration",
            name,
            "/v1/notifiers",
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

    if parameter_to_API_type(notify_type) != config.get("type"):
        module.fail_json(
            msg=(
                "cannot change the `type' parameter of an existing "
                "notifier method configuration: current type is {t}, "
                "requested type is {rt}"
            ).format(t=API_type_to_parameter(config.get("type")), rt=notify_type)
        )

    # Build the data to send to the API to update the configuration
    data = copy.deepcopy(config)
    data["name"] = name
    data["id"] = id_to_update
    update_password = False

    # Compare the object with the requested configuration to verify whether
    # an update is required
    if reg_conf["conf"] is None:
        if not new_name and (not rhacs_url or rhacs_url == data.get("uiEndpoint")):
            module.exit_json(changed=False, id=id_to_update)

    elif reg_conf["conf_name"] == "slack":
        webhook = reg_conf["conf"].get("webhook")
        annotation_key = reg_conf["conf"].get("annotation_key")

        if (
            not new_name
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (webhook is None or webhook == reg_conf["current_conf"].get("labelDefault"))
            and (
                annotation_key is None
                or annotation_key == reg_conf["current_conf"].get("labelKey")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        if webhook is not None:
            data["labelDefault"] = webhook
        if annotation_key is not None:
            data["labelKey"] = annotation_key

    elif reg_conf["conf_name"] == "syslog":
        host = reg_conf["conf"].get("host")
        port = reg_conf["conf"].get("port")
        facility = reg_conf["conf"].get("facility")
        use_tls = reg_conf["conf"].get("use_tls")
        validate_certs = reg_conf["conf"].get("validate_certs")
        message_format = reg_conf["conf"].get("message_format")
        extra_fields = reg_conf["conf"].get("extra_fields")

        tcp_config = reg_conf["current_conf"].get("tcpConfig", {})
        if (
            not new_name
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (host is None or host == tcp_config.get("hostname"))
            and (port is None or port == int(tcp_config.get("port")))
            and (validate_certs is None or validate_certs != tcp_config.get("skipTlsVerify"))
            and (use_tls is None or use_tls == tcp_config.get("useTls"))
            and (
                message_format is None
                or message_format == reg_conf["current_conf"].get("messageFormat")
            )
        ):
            if extra_fields is None:
                module.exit_json(changed=False, id=id_to_update)
            current_extra = set(
                [
                    (m.get("key"), m.get("value"))
                    for m in reg_conf["current_conf"].get("extraFields", [])
                ]
            )
            requested_extra = set([(m.get("key"), m.get("value")) for m in extra_fields])
            if current_extra == requested_extra:
                module.exit_json(changed=False, id=id_to_update)

        if host is not None:
            data["syslog"]["tcpConfig"]["hostname"] = host
        if port is not None:
            data["syslog"]["tcpConfig"]["port"] = port
        if use_tls is not None:
            data["syslog"]["tcpConfig"]["useTls"] = use_tls
        if validate_certs is not None:
            data["syslog"]["tcpConfig"]["skipTlsVerify"] = not validate_certs
        if facility is not None:
            data["syslog"]["localFacility"] = facility
        if message_format is not None:
            data["syslog"]["messageFormat"] = message_format
        if extra_fields is not None:
            f = []
            for field in extra_fields:
                f.append({"key": field["key"], "value": field["value"]})
            data["syslog"]["extraFields"] = f

    elif reg_conf["conf_name"] == "aws":
        aws_id = reg_conf["conf"].get("aws_id")
        region = reg_conf["conf"].get("region")
        use_iam = reg_conf["conf"].get("use_iam")
        access_key = reg_conf["conf"].get("access_key")
        secret_key = reg_conf["conf"].get("secret_key")

        if (
            not new_name
            and not access_key
            and not secret_key
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (aws_id is None or aws_id == reg_conf["current_conf"].get("accountId"))
            and (region is None or region == reg_conf["current_conf"].get("region"))
            and (
                use_iam is None
                or use_iam
                == reg_conf["current_conf"].get("credentials", {}).get("stsEnabled")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        if aws_id is not None and len(aws_id) != 12:
            module.fail_json(
                msg=(
                    "the AWS account number (`aws_id') must be 12 " "characters long: {val}"
                ).format(val=aws_id)
            )

        if aws_id is not None:
            data["awsSecurityHub"]["accountId"] = aws_id
        if region is not None:
            data["awsSecurityHub"]["region"] = region
        if use_iam is not None:
            data["awsSecurityHub"]["credentials"]["stsEnabled"] = use_iam
        if access_key:
            data["awsSecurityHub"]["credentials"]["accessKeyId"] = access_key
            update_password = True
        if secret_key:
            data["awsSecurityHub"]["credentials"]["secretAccessKey"] = secret_key
            update_password = True

    elif reg_conf["conf_name"] == "google":
        source_id = reg_conf["conf"].get("source_id")
        use_workload_id = reg_conf["conf"].get("use_workload_id")
        service_account_key = reg_conf["conf"].get("service_account_key")

        if (
            not new_name
            and not service_account_key
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (source_id is None or source_id == reg_conf["current_conf"].get("sourceId"))
            and (
                use_workload_id is None
                or use_workload_id == reg_conf["current_conf"].get("wifEnabled")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        if source_id is not None and not re.match(
            r"organizations/\d+/sources/\d+$", source_id
        ):
            module.fail_json(
                msg=(
                    "the cloud SCC source ID (`source_id') must have the "
                    "format `organizations/<num>/sources/<num>': {val}"
                ).format(val=source_id)
            )

        if source_id is not None:
            data["cscc"]["sourceId"] = source_id
        if use_workload_id is not None:
            data["cscc"]["wifEnabled"] = use_workload_id
        if service_account_key:
            data["cscc"]["serviceAccount"] = service_account_key
            update_password = True

    elif reg_conf["conf_name"] == "jira":
        username = reg_conf["conf"].get("username")
        password = reg_conf["conf"].get("password")
        issue_type = reg_conf["conf"].get("issue_type")
        url = reg_conf["conf"].get("url")
        mapping_critical = reg_conf["conf"].get("mapping_critical")
        mapping_high = reg_conf["conf"].get("mapping_high")
        mapping_medium = reg_conf["conf"].get("mapping_medium")
        mapping_low = reg_conf["conf"].get("mapping_low")
        default_fields_JSON = reg_conf["conf"].get("default_fields_JSON")
        project = reg_conf["conf"].get("project")
        annotation_key = reg_conf["conf"].get("annotation_key")

        if (
            not new_name
            and not password
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (
                issue_type is None or issue_type == reg_conf["current_conf"].get("issueType")
            )
            and (url is None or url == reg_conf["current_conf"].get("url"))
            and (
                default_fields_JSON is None
                or default_fields_JSON == reg_conf["current_conf"].get("defaultFieldsJson")
            )
            and (project is None or project == new_fields["notifier"]["labelDefault"])
            and (
                annotation_key is None or annotation_key == new_fields["notifier"]["labelKey"]
            )
        ):
            for pri in reg_conf["current_conf"].get("priorityMappings", []):
                if (
                    pri.get("severity") == "CRITICAL_SEVERITY"
                    and mapping_critical is not None
                    and mapping_critical != pri.get("priorityName")
                ):
                    break
                elif (
                    pri.get("severity") == "HIGH_SEVERITY"
                    and mapping_high is not None
                    and mapping_high != pri.get("priorityName")
                ):
                    break
                elif (
                    pri.get("severity") == "MEDIUM_SEVERITY"
                    and mapping_medium is not None
                    and mapping_medium != pri.get("priorityName")
                ):
                    break
                elif (
                    pri.get("severity") == "LOW_SEVERITY"
                    and mapping_low is not None
                    and mapping_low != pri.get("priorityName")
                ):
                    break
            else:
                module.exit_json(changed=False, id=id_to_update)

        if username is not None:
            data["jira"]["username"] = username
        if password:
            data["jira"]["password"] = password
            update_password = True
        if issue_type is not None:
            data["jira"]["issueType"] = issue_type
        if url is not None and url != data["jira"]["url"]:
            data["jira"]["url"] = url
            update_password = True
        if default_fields_JSON is not None:
            data["jira"]["defaultFieldsJson"] = default_fields_JSON
        if project is not None:
            data["labelDefault"] = project
        if annotation_key is not None:
            data["labelKey"] = annotation_key

        mappings = []
        if mapping_critical:
            data["jira"]["disablePriority"] = False
            mappings.append(
                {"severity": "CRITICAL_SEVERITY", "priorityName": mapping_critical}
            )
        elif mapping_critical == "":
            mappings.append({"severity": "CRITICAL_SEVERITY", "priorityName": "Highest"})
        if mapping_high:
            data["jira"]["disablePriority"] = False
            mappings.append({"severity": "HIGH_SEVERITY", "priorityName": mapping_high})
        elif mapping_high == "":
            mappings.append({"severity": "HIGH_SEVERITY", "priorityName": "High"})
        if mapping_medium:
            data["jira"]["disablePriority"] = False
            mappings.append({"severity": "MEDIUM_SEVERITY", "priorityName": mapping_medium})
        elif mapping_medium == "":
            mappings.append({"severity": "MEDIUM_SEVERITY", "priorityName": "Medium"})
        if mapping_low:
            data["jira"]["disablePriority"] = False
            mappings.append({"severity": "LOW_SEVERITY", "priorityName": mapping_low})
        elif mapping_low == "":
            mappings.append({"severity": "LOW_SEVERITY", "priorityName": "Low"})
        data["jira"]["priorityMappings"] = mappings

    elif reg_conf["conf_name"] == "email":
        username = reg_conf["conf"].get("username")
        password = reg_conf["conf"].get("password")
        server = reg_conf["conf"].get("server")
        from_header = reg_conf["conf"].get("from_header")
        sender = reg_conf["conf"].get("sender")
        recipient = reg_conf["conf"].get("recipient")
        validate_certs = reg_conf["conf"].get("validate_certs")
        starttls = reg_conf["conf"].get("starttls")
        unauthenticated = reg_conf["conf"].get("unauthenticated")
        annotation_key = reg_conf["conf"].get("annotation_key")

        if (
            not new_name
            and not password
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (server is None or server == reg_conf["current_conf"].get("server"))
            and (from_header is None or from_header == reg_conf["current_conf"].get("from"))
            and (sender is None or sender == reg_conf["current_conf"].get("sender"))
            and (recipient is None or recipient == data["labelDefault"])
            and (annotation_key is None or annotation_key == data["labelKey"])
            and (
                validate_certs is None
                or validate_certs != reg_conf["current_conf"].get("disableTLS")
            )
            and (
                starttls is None
                or starttls == reg_conf["current_conf"].get("startTLSAuthMethod")
            )
            and (
                unauthenticated is None
                or unauthenticated == reg_conf["current_conf"].get("allowUnauthenticatedSmtp")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        data["email"].pop("DEPRECATEDUseStartTLS", None)
        if username is not None:
            data["email"]["username"] = username
        if password:
            data["email"]["password"] = password
            update_password = True
        if server is not None:
            data["email"]["server"] = server
        if from_header is not None:
            data["email"]["from"] = from_header
        if sender is not None:
            data["email"]["sender"] = sender
        if recipient is not None:
            data["labelDefault"] = recipient
        if annotation_key is not None:
            data["labelKey"] = annotation_key
        if validate_certs is not None:
            data["email"]["disableTLS"] = not validate_certs
        if starttls is not None:
            data["email"]["startTLSAuthMethod"] = starttls
        if unauthenticated is not None:
            data["email"]["allowUnauthenticatedSmtp"] = unauthenticated
        if (
            data["email"]["startTLSAuthMethod"] in ("PLAIN", "LOGIN")
            and data["email"]["disableTLS"] is False
        ):
            module.fail_json(
                msg=(
                    "TLS certificate validation must be disabled "
                    "(`validate_certs: false') when using STARTTLS "
                    "(`starttls: PLAIN' or `starttls: LOGIN')"
                )
            )

    elif reg_conf["conf_name"] == "splunk":
        url = reg_conf["conf"].get("url")
        token = reg_conf["conf"].get("token")
        validate_certs = reg_conf["conf"].get("validate_certs")
        truncate = reg_conf["conf"].get("truncate")
        audit_logging = reg_conf["conf"].get("audit_logging")
        source_type_alert = reg_conf["conf"].get("source_type_alert")
        source_type_audit = reg_conf["conf"].get("source_type_audit")

        if (
            not new_name
            and not token
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (url is None or url == reg_conf["current_conf"].get("httpEndpoint"))
            and (
                validate_certs is None
                or validate_certs != reg_conf["current_conf"].get("insecure")
            )
            and (
                truncate is None or truncate == int(reg_conf["current_conf"].get("truncate"))
            )
            and (
                audit_logging is None
                or audit_logging == reg_conf["current_conf"].get("auditLoggingEnabled")
            )
            and (
                source_type_alert is None
                or source_type_alert
                == reg_conf["current_conf"].get("sourceTypes", {}).get("alert")
            )
            and (
                source_type_audit is None
                or source_type_audit
                == reg_conf["current_conf"].get("sourceTypes", {}).get("audit")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        if url is not None and url != data["splunk"]["httpEndpoint"]:
            data["splunk"]["httpEndpoint"] = url
            update_password = True
        if token:
            data["splunk"]["httpToken"] = token
            update_password = True
        if validate_certs is not None:
            data["splunk"]["insecure"] = not validate_certs
        if truncate:
            data["splunk"]["truncate"] = truncate
        if audit_logging is not None:
            data["splunk"]["auditLoggingEnabled"] = audit_logging
        if source_type_alert is not None:
            data["splunk"]["sourceTypes"]["alert"] = source_type_alert
        if source_type_audit is not None:
            data["splunk"]["sourceTypes"]["audit"] = source_type_audit

    elif reg_conf["conf_name"] == "pagerduty":
        api_key = reg_conf["conf"].get("api_key")

        if (
            not new_name
            and not api_key
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
        ):
            module.exit_json(changed=False, id=id_to_update)
        if api_key:
            data["pagerduty"]["apiKey"] = api_key
            update_password = True

    elif reg_conf["conf_name"] == "sumologic":
        url = reg_conf["conf"].get("url")
        validate_certs = reg_conf["conf"].get("validate_certs")

        if (
            not new_name
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (url is None or url == reg_conf["current_conf"].get("httpSourceAddress"))
            and (
                validate_certs is None
                or validate_certs != reg_conf["current_conf"].get("skipTLSVerify")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        if url is not None:
            data["sumologic"]["httpSourceAddress"] = url
        if validate_certs is not None:
            data["sumologic"]["skipTLSVerify"] = not validate_certs

    elif reg_conf["conf_name"] == "teams":
        url = reg_conf["conf"].get("url")
        annotation_key = reg_conf["conf"].get("annotation_key")

        if (
            not new_name
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (url is None or url == reg_conf["current_conf"].get("labelDefault"))
            and (
                annotation_key is None
                or annotation_key == reg_conf["current_conf"].get("labelKey")
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        if url is not None:
            data["labelDefault"] = url
        if annotation_key is not None:
            data["labelKey"] = annotation_key

    elif reg_conf["conf_name"] == "generic":
        webhook = reg_conf["conf"].get("webhook")
        audit_logging = reg_conf["conf"].get("audit_logging")
        validate_certs = reg_conf["conf"].get("validate_certs")
        ca_cert = reg_conf["conf"].get("ca_cert")
        username = reg_conf["conf"].get("username")
        password = reg_conf["conf"].get("password")
        headers = reg_conf["conf"].get("headers")
        extra_fields = reg_conf["conf"].get("extra_fields")

        if (
            not new_name
            and not password
            and (not rhacs_url or rhacs_url == data.get("uiEndpoint"))
            and (webhook is None or webhook == reg_conf["current_conf"].get("endpoint"))
            and (
                validate_certs is None
                or validate_certs != reg_conf["current_conf"].get("skipTLSVerify")
            )
            and (
                audit_logging is None
                or audit_logging == reg_conf["current_conf"].get("auditLoggingEnabled")
            )
            and (ca_cert is None or ca_cert == reg_conf["current_conf"].get("caCert"))
            and (username is None or username == reg_conf["current_conf"].get("username"))
        ):
            current_headers = set(
                [
                    (m.get("key"), m.get("value"))
                    for m in reg_conf["current_conf"].get("headers", [])
                ]
            )
            requested_headers = (
                set([(m.get("key"), m.get("value")) for m in headers]) if headers else set()
            )

            current_extras = set(
                [
                    (m.get("key"), m.get("value"))
                    for m in reg_conf["current_conf"].get("extraFields", [])
                ]
            )
            requested_extras = (
                set([(m.get("key"), m.get("value")) for m in extra_fields])
                if extra_fields
                else set()
            )

            if (headers is None or current_headers == requested_headers) and (
                extra_fields is None or current_extras == requested_extras
            ):
                module.exit_json(changed=False, id=id_to_update)

        if webhook is not None and webhook != data["generic"]["endpoint"]:
            data["generic"]["endpoint"] = webhook
            update_password = True
        if audit_logging is not None:
            data["generic"]["auditLoggingEnabled"] = audit_logging
        if validate_certs is not None:
            data["generic"]["skipTLSVerify"] = not validate_certs
        if ca_cert is not None:
            data["generic"]["caCert"] = ca_cert
        if username is not None:
            data["generic"]["username"] = username
        if password:
            data["generic"]["password"] = password
            update_password = True
        if headers is not None:
            data["generic"]["headers"] = [
                {"key": header["key"], "value": header["value"]} for header in headers
            ]
        if extra_fields is not None:
            data["generic"]["extraFields"] = [
                {"key": field["key"], "value": field["value"]} for field in extra_fields
            ]
    else:  # reg_conf["conf_name"] == "sentinel":
        url = reg_conf["conf"].get("url")
        tenant_id = reg_conf["conf"].get("tenant_id")
        client_id = reg_conf["conf"].get("client_id")
        secret = reg_conf["conf"].get("secret")
        client_cert = reg_conf["conf"].get("client_cert")
        alert_data_collection_rule = reg_conf["conf"].get("alert_data_collection_rule")
        audit_data_collection_rule = reg_conf["conf"].get("audit_data_collection_rule")

        if (
            not new_name
            and not secret
            and not client_cert
            and (url is None or url == reg_conf["current_conf"].get("logIngestionEndpoint"))
            and (
                tenant_id is None
                or tenant_id == reg_conf["current_conf"].get("directoryTenantId")
            )
            and (
                client_id is None
                or client_id == reg_conf["current_conf"].get("applicationClientId")
            )
            and (
                alert_data_collection_rule is None
                or (
                    (
                        alert_data_collection_rule.get("rule_stream_name") is None
                        or alert_data_collection_rule.get("rule_stream_name")
                        == reg_conf["current_conf"]
                        .get("alertDcrConfig", {})
                        .get("streamName")
                    )
                    and (
                        alert_data_collection_rule.get("rule_id") is None
                        or alert_data_collection_rule.get("rule_id")
                        == reg_conf["current_conf"]
                        .get("alertDcrConfig", {})
                        .get("dataCollectionRuleId")
                    )
                    and (
                        alert_data_collection_rule.get("enabled") is None
                        or alert_data_collection_rule.get("enabled")
                        == reg_conf["current_conf"].get("alertDcrConfig", {}).get("enabled")
                    )
                )
            )
            and (
                audit_data_collection_rule is None
                or (
                    (
                        audit_data_collection_rule.get("rule_stream_name") is None
                        or audit_data_collection_rule.get("rule_stream_name")
                        == reg_conf["current_conf"]
                        .get("auditLogDcrConfig", {})
                        .get("streamName")
                    )
                    and (
                        audit_data_collection_rule.get("rule_id") is None
                        or audit_data_collection_rule.get("rule_id")
                        == reg_conf["current_conf"]
                        .get("auditLogDcrConfig", {})
                        .get("dataCollectionRuleId")
                    )
                    and (
                        audit_data_collection_rule.get("enabled") is None
                        or audit_data_collection_rule.get("enabled")
                        == reg_conf["current_conf"]
                        .get("auditLogDcrConfig", {})
                        .get("enabled")
                    )
                )
            )
        ):
            module.exit_json(changed=False, id=id_to_update)

        if url is not None:
            data["microsoftSentinel"]["logIngestionEndpoint"] = url
        if tenant_id is not None:
            data["microsoftSentinel"]["directoryTenantId"] = tenant_id
        if client_id is not None:
            data["microsoftSentinel"]["applicationClientId"] = client_id
        if secret:
            data["microsoftSentinel"]["secret"] = secret
            data["microsoftSentinel"]["clientCertAuthConfig"] = {
                "clientCert": "",
                "privateKey": "",
            }
            update_password = True
        else:
            data["microsoftSentinel"]["secret"] = ""
        if client_cert:
            data["microsoftSentinel"]["clientCertAuthConfig"] = {
                "clientCert": client_cert.get("certificate", ""),
                "privateKey": client_cert.get("private_key", ""),
            }
            data["microsoftSentinel"]["secret"] = ""
            update_password = True
        else:
            data["microsoftSentinel"]["clientCertAuthConfig"] = {
                "clientCert": "",
                "privateKey": "",
            }
        if alert_data_collection_rule is not None:
            data["microsoftSentinel"]["alertDcrConfig"] = {
                "streamName": alert_data_collection_rule.get("rule_stream_name", ""),
                "dataCollectionRuleId": alert_data_collection_rule.get("rule_id", ""),
                "enabled": alert_data_collection_rule.get("enabled", False),
            }
        if audit_data_collection_rule is not None:
            data["microsoftSentinel"]["auditLogDcrConfig"] = {
                "streamName": audit_data_collection_rule.get("rule_stream_name", ""),
                "dataCollectionRuleId": audit_data_collection_rule.get("rule_id", ""),
                "enabled": audit_data_collection_rule.get("enabled", False),
            }

    if rhacs_url:
        data["uiEndpoint"] = rhacs_url

    if reg_conf["update_verb"] == "PATCH":
        module.patch(
            "notifier method configuration",
            name,
            "/v1/notifiers/{id}".format(id=id_to_update),
            {"notifier": data, "updatePassword": update_password},
        )
    else:
        module.unconditional_update(
            "notifier method configuration",
            name,
            "/v1/notifiers/{id}".format(id=id_to_update),
            data,
        )

    # In case a rename operation occurred (when new_name is set), and the
    # source and destination objects both existed, then delete the source
    # object
    if id_to_delete:
        module.delete(
            config,
            "notifier method configuration",
            name_to_delete,
            "/v1/notifiers/{id}".format(id=id_to_delete),
            auto_exit=False,
        )
    module.exit_json(changed=True, id=id_to_update)


if __name__ == "__main__":
    main()
