#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_config
short_description: Manage RHACS configuration
description:
  - Manage the Red Hat Advanced Cluster Security for Kubernetes configuration
    parameters.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  login:
    description: Add a custom text to the login page.
    type: dict
    suboptions:
      enabled:
        description: Whether to define a custom text.
        type: bool
      text:
        description: Text to add to the login page (2000 characters limit).
        type: str
  header:
    description: Configure the header section of the RHACS portal.
    type: dict
    suboptions:
      enabled:
        description: Whether to enable the customization of the header.
        type: bool
      text:
        description: Text to add to the header (2000 characters limit).
        type: str
      size:
        description: Text size.
        type: str
        choices:
          - UNSET
          - SMALL
          - MEDIUM
          - LARGE
      color:
        description: "Text color in the #RRGGBB format."
        type: str
      bg_color:
        description: "Background color in the #RRGGBB format."
        type: str
  footer:
    description: Configure the footer section of the RHACS portal.
    type: dict
    suboptions:
      enabled:
        description: Whether to enable the customization of the footer.
        type: bool
      text:
        description: Text to add to the footer (2000 characters limit).
        type: str
      size:
        description: Text size.
        type: str
        choices:
          - UNSET
          - SMALL
          - MEDIUM
          - LARGE
      color:
        description: "Text color in the #RRGGBB format."
        type: str
      bg_color:
        description: "Background color in the #RRGGBB format."
        type: str
  telemetry:
    description: Whether to enable the telemetry data collection by Red Hat.
    type: bool
  retention:
    description: Configure data retention parameters.
    type: dict
    suboptions:
      resolved_deploy:
        description: Retention in days of the resolved deploy-phase violations.
        type: int
      deleted_runtime:
        description:
          - Retention in days of the runtime violations for deleted
            deployments.
        type: int
      all_runtime:
        description: Retention in days for all the runtime violations.
        type: int
      attempted_deploy:
        description:
          - Retention in days of the attempted deploy-phase violations.
        type: int
      attempted_runtime:
        description: Retention in days of the attempted runtime violations.
        type: int
      image:
        description: Retention in days for the images no longer deployed.
        type: int
      expired_vuln_req:
        description: Retention in days of the expired vulnerability requests.
        type: int
      report_history:
        description: Vulnerability report job history retention in days.
        type: int
      report_downloadable:
        description:
          - Prepared downloadable vulnerability reports retention in days.
        type: int
      report_downloadable_size:
        description:
          - Size limit of the prepared downloadable vulnerability reports.
          - You specify the size in bytes, but you can also use the KB,
            MB, GB, or TB suffixes.
        type: bytes
      administration_events:
        description: Retention in days for the administration events.
        type: int
  decommissioned_clusters:
    description: Configure decommissioned clusters retention.
    type: dict
    suboptions:
      retention:
        description: Retention in days for decommissioned clusters.
        type: int
      ignore_labels:
        description: Ignore clusters which have the following labels.
        type: list
        elements: dict
        suboptions:
          label:
            description: Label name.
            type: str
            required: true
          value:
            description: Label value.
            type: str
            required: true
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
- name: Ensure the prepared downloadable vulnerability reports retention is set
  herve4m.rhacs_configuration.rhacs_config:
    retention:
      report_downloadable: 7
      report_downloadable_size: 500 MB
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the RHACS portal header and footer are configured
  herve4m.rhacs_configuration.rhacs_config:
    header:
      enabled: true
      color: "#EE0000"
      bg_color: "#C7C7C7"
      text: My Organization RHACS Portal
      size: MEDIUM
    footer:
      enabled: true
      color: "#0066CC"
      bg_color: "#C7C7C7"
      text: ""
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r""" # """

import re
import copy

from ..module_utils.api_module import APIModule


def verify_color(module, color, section_name, option_name):
    if color is None:
        return
    if not re.match(r"#[0-9A-F]{6}$", color, re.IGNORECASE):
        module.fail_json(
            msg=(
                "wrong color format (#RRGGBB) for the `{c}' parameter in "
                "the `{s}' section: {v}"
            ).format(c=option_name, s=section_name, v=color)
        )


def main():

    argument_spec = dict(
        login=dict(
            type="dict",
            options=dict(enabled=dict(type="bool"), text=dict()),
        ),
        header=dict(
            type="dict",
            options=dict(
                enabled=dict(type="bool"),
                text=dict(),
                size=dict(choices=["UNSET", "SMALL", "MEDIUM", "LARGE"]),
                color=dict(),
                bg_color=dict(),
            ),
        ),
        footer=dict(
            type="dict",
            options=dict(
                enabled=dict(type="bool"),
                text=dict(),
                size=dict(choices=["UNSET", "SMALL", "MEDIUM", "LARGE"]),
                color=dict(),
                bg_color=dict(),
            ),
        ),
        telemetry=dict(type="bool"),
        retention=dict(
            type="dict",
            options=dict(
                resolved_deploy=dict(type="int"),
                deleted_runtime=dict(type="int"),
                all_runtime=dict(type="int"),
                attempted_deploy=dict(type="int"),
                attempted_runtime=dict(type="int"),
                image=dict(type="int"),
                expired_vuln_req=dict(type="int"),
                report_history=dict(type="int"),
                report_downloadable=dict(type="int"),
                report_downloadable_size=dict(type="bytes"),
                administration_events=dict(type="int"),
            ),
        ),
        decommissioned_clusters=dict(
            type="dict",
            options=dict(
                retention=dict(type="int"),
                ignore_labels=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        label=dict(required=True),
                        value=dict(required=True),
                    ),
                ),
            ),
        ),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    login = module.params.get("login")
    header = module.params.get("header")
    footer = module.params.get("footer")
    telemetry = module.params.get("telemetry")
    retention = module.params.get("retention")
    decommissioned_clusters = module.params.get("decommissioned_clusters")

    # Retrieve the existing configuration
    #
    # GET /v1/config
    # {
    #     "publicConfig": {
    #         "loginNotice": {
    #             "enabled": false,
    #             "text": ""
    #         },
    #         "header": {
    #             "enabled": false,
    #             "text": "",
    #             "size": "UNSET",
    #             "color": "#000000",
    #             "backgroundColor": "#FFFFFF"
    #         },
    #         "footer": {
    #             "enabled": false,
    #             "text": "",
    #             "size": "UNSET",
    #             "color": "#000000",
    #             "backgroundColor": "#FFFFFF"
    #         },
    #         "telemetry": {
    #             "enabled": true,
    #             "lastSetTime": null
    #         }
    #     },
    #     "privateConfig": {
    #         "alertConfig": {
    #             "resolvedDeployRetentionDurationDays": 7,
    #             "deletedRuntimeRetentionDurationDays": 7,
    #             "allRuntimeRetentionDurationDays": 31,
    #             "attemptedDeployRetentionDurationDays": 7,
    #             "attemptedRuntimeRetentionDurationDays": 7
    #         },
    #         "imageRetentionDurationDays": 7,
    #         "expiredVulnReqRetentionDurationDays": 90,
    #         "decommissionedClusterRetention": {
    #             "retentionDurationDays": 0,
    #             "ignoreClusterLabels": {},
    #             "lastUpdated": "2024-10-02T06:28:41.630614378Z",
    #             "createdAt": "2024-10-02T06:28:41.630613992Z"
    #         },
    #         "reportRetentionConfig": {
    #             "historyRetentionDurationDays": 7,
    #             "downloadableReportRetentionDays": 7,
    #             "downloadableReportGlobalRetentionBytes": 524288000
    #         },
    #         "vulnerabilityExceptionConfig": {
    #             "expiryOptions": {
    #                 "dayOptions": [
    #                     {
    #                         "numDays": 14,
    #                         "enabled": true
    #                     },
    #                     {
    #                         "numDays": 30,
    #                         "enabled": true
    #                     },
    #                     {
    #                         "numDays": 60,
    #                         "enabled": true
    #                     },
    #                     {
    #                         "numDays": 90,
    #                         "enabled": true
    #                     }
    #                 ],
    #                 "fixableCveOptions": {
    #                     "allFixable": true,
    #                     "anyFixable": true
    #                 },
    #                 "customDate": false,
    #                 "indefinite": false
    #             }
    #         },
    #         "administrationEventsConfig": {
    #             "retentionDurationDays": 4
    #         }
    #     }
    # }

    c = module.get_object_path("/v1/config")

    new_fields = {"config": copy.deepcopy(c)}
    pub_conf = c.get("publicConfig")
    if pub_conf is None:
        pub_conf = {}
        new_fields["config"]["publicConfig"] = {
            "loginNotice": {},
            "header": {},
            "footer": {},
            "telemetry": {},
        }
    priv_conf = c.get("privateConfig")
    if priv_conf is None:
        priv_conf = {}

    changed = False

    if login is not None:
        enabled = login.get("enabled")
        text = login.get("text")

        conf = pub_conf.get("loginNotice", {})
        data = new_fields["config"]["publicConfig"]["loginNotice"]

        if enabled is not None and enabled != conf.get("enabled"):
            changed = True
            data["enabled"] = enabled
        if text is not None and text != conf.get("text"):
            if len(text) > 2000:
                module.fail_json(
                    msg=(
                        "the `text' parameter in the `login' section "
                        "cannot exceed 2000 characters"
                    )
                )
            changed = True
            data["text"] = text

    if header is not None:
        enabled = header.get("enabled")
        text = header.get("text")
        size = header.get("size")
        color = header.get("color")
        bg_color = header.get("bg_color")

        conf = pub_conf.get("header", {})
        data = new_fields["config"]["publicConfig"]["header"]

        if enabled is not None and enabled != conf.get("enabled"):
            changed = True
            data["enabled"] = enabled
        if text is not None and text != conf.get("text"):
            if len(text) > 2000:
                module.fail_json(
                    msg=(
                        "the `text' parameter in the `header' section "
                        "cannot exceed 2000 characters"
                    )
                )
            changed = True
            data["text"] = text
        if size is not None and size != conf.get("size"):
            changed = True
            data["size"] = size
        if color is not None and color != conf.get("color"):
            verify_color(module, color, "header", "color")
            changed = True
            data["color"] = color
        if bg_color is not None and bg_color != conf.get("backgroundColor"):
            verify_color(module, bg_color, "header", "bg_color")
            changed = True
            data["backgroundColor"] = bg_color

    if footer is not None:
        enabled = footer.get("enabled")
        text = footer.get("text")
        size = footer.get("size")
        color = footer.get("color")
        bg_color = footer.get("bg_color")

        conf = pub_conf.get("footer", {})
        data = new_fields["config"]["publicConfig"]["footer"]

        if enabled is not None and enabled != conf.get("enabled"):
            changed = True
            data["enabled"] = enabled
        if text is not None and text != conf.get("text"):
            if len(text) > 2000:
                module.fail_json(
                    msg=(
                        "the `text' parameter in the `footer' section "
                        "cannot exceed 2000 characters"
                    )
                )
            changed = True
            data["text"] = text
        if size is not None and size != conf.get("size"):
            changed = True
            data["size"] = size
        if color is not None and color != conf.get("color"):
            verify_color(module, color, "footer", "color")
            changed = True
            data["color"] = color
        if bg_color is not None and bg_color != conf.get("backgroundColor"):
            verify_color(module, bg_color, "footer", "bg_color")
            changed = True
            data["backgroundColor"] = bg_color

    if telemetry is not None and telemetry != pub_conf.get("telemetry", {}).get("enabled"):
        changed = True
        new_fields["config"]["publicConfig"]["telemetry"]["enabled"] = telemetry

    if retention is not None:
        resolved_deploy = retention.get("resolved_deploy")
        deleted_runtime = retention.get("deleted_runtime")
        all_runtime = retention.get("all_runtime")
        attempted_deploy = retention.get("attempted_deploy")
        attempted_runtime = retention.get("attempted_runtime")
        image = retention.get("image")
        expired_vuln_req = retention.get("expired_vuln_req")
        report_history = retention.get("report_history")
        report_downloadable = retention.get("report_downloadable")
        report_downloadable_size = retention.get("report_downloadable_size")
        administration_events = retention.get("administration_events")

        alert_conf = priv_conf.get("alertConfig", {})
        rep_conf = priv_conf.get("reportRetentionConfig", {})
        data = new_fields["config"]["privateConfig"]

        if resolved_deploy is not None and resolved_deploy != alert_conf.get(
            "resolvedDeployRetentionDurationDays"
        ):
            changed = True
            data["alertConfig"]["resolvedDeployRetentionDurationDays"] = resolved_deploy
        if deleted_runtime is not None and deleted_runtime != alert_conf.get(
            "deletedRuntimeRetentionDurationDays"
        ):
            changed = True
            data["alertConfig"]["deletedRuntimeRetentionDurationDays"] = deleted_runtime
        if all_runtime is not None and all_runtime != alert_conf.get(
            "allRuntimeRetentionDurationDays"
        ):
            changed = True
            data["alertConfig"]["allRuntimeRetentionDurationDays"] = all_runtime
        if attempted_deploy is not None and attempted_deploy != alert_conf.get(
            "attemptedDeployRetentionDurationDays"
        ):
            changed = True
            data["alertConfig"]["attemptedDeployRetentionDurationDays"] = attempted_deploy
        if attempted_runtime is not None and attempted_runtime != alert_conf.get(
            "attemptedRuntimeRetentionDurationDays"
        ):
            changed = True
            data["alertConfig"]["attemptedRuntimeRetentionDurationDays"] = attempted_runtime

        if image is not None and image != priv_conf.get("imageRetentionDurationDays"):
            changed = True
            data["imageRetentionDurationDays"] = image
        if expired_vuln_req is not None and expired_vuln_req != priv_conf.get(
            "expiredVulnReqRetentionDurationDays"
        ):
            changed = True
            data["expiredVulnReqRetentionDurationDays"] = expired_vuln_req

        if report_history is not None and report_history != rep_conf.get(
            "historyRetentionDurationDays"
        ):
            changed = True
            data["reportRetentionConfig"]["historyRetentionDurationDays"] = report_history
        if report_downloadable is not None and report_downloadable != rep_conf.get(
            "downloadableReportRetentionDays"
        ):
            changed = True
            data["reportRetentionConfig"][
                "downloadableReportRetentionDays"
            ] = report_downloadable
        if report_downloadable_size is not None and report_downloadable_size != rep_conf.get(
            "downloadableReportGlobalRetentionBytes"
        ):
            changed = True
            data["reportRetentionConfig"][
                "downloadableReportGlobalRetentionBytes"
            ] = report_downloadable_size

        if administration_events is not None and administration_events != priv_conf.get(
            "administrationEventsConfig", {}
        ).get("retentionDurationDays"):
            changed = True
            data["administrationEventsConfig"][
                "retentionDurationDays"
            ] = administration_events

    if decommissioned_clusters is not None:
        retention = decommissioned_clusters.get("retention")
        ignore_labels = decommissioned_clusters.get("ignore_labels")

        conf = priv_conf.get("decommissionedClusterRetention", {})
        data = new_fields["config"]["privateConfig"]["decommissionedClusterRetention"]

        if retention is not None and retention != conf.get("retentionDurationDays"):
            changed = True
            data["retentionDurationDays"] = retention
        if ignore_labels is not None:
            labels = {}
            for label in ignore_labels:
                labels[label["label"]] = label["value"]
            if labels != conf.get("ignoreClusterLabels", {}):
                changed = True
                data["ignoreClusterLabels"] = labels

    if changed is False:
        module.exit_json(changed=False)

    module.unconditional_update("configuration", "RHACS", "/v1/config", new_fields)
    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
