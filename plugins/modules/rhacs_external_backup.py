#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_external_backup
short_description: Manage external backup configurations
description:
  - Create, delete, and update external backup configurations to Amazon S3,
    Google Cloud Storage, or Amazon S3 compatible buckets.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description:
      - Name of the external backup configuration.
      - Several configurations can have the same name.
      - For a delete operation, the module removes all the configurations
        that match both the O(name) and O(type) parameters.
      - For update operations, the module updates only the first configuration
        returned by the RHACS API that matches both the O(name) and O(type)
        parameters.
    required: true
    type: str
  type:
    description:
      - Destination of the backups, Amazon S3 buckets (V(s3)), Google Cloud
        Storage buckets (V(gcs)), or Amazon S3 compatible buckets
        (V(s3compatible)).
      - For Amazon S3, you provide the configuration in the O(s3) parameter.
      - For Google Cloud Storage, you provide the configuration in the O(gcs)
        parameter.
      - For Amazon S3 compatible buckets, you provide the configuration in the
        O(s3compatible) parameter.
      - Amazon S3 compatible buckets are only supported with StackRox version
        4.6 or later.
    required: true
    type: str
    choices: [s3, gcs, s3compatible]
  backups_to_retain:
    description:
      - Number of backups to keep.
      - O(backups_to_retain) must be 1 or greater.
      - V(1) by default.
    type: int
  interval:
    description:
      - Backup frequency.
      - If you set the O(interval) parameter to V(WEEKLY), then you must
        indicate your chosen day for the backups in the O(week_day) parameter.
      - V(DAILY) by default.
    type: str
    choices: [DAILY, WEEKLY]
  week_day:
    description:
      - Name of the day for weekly backups when O(interval=WEEKLY).
      - V(Sunday) by default.
    type: str
    choices:
      - Monday
      - Tuesday
      - Wednesday
      - Thursday
      - Friday
      - Saturday
      - Sunday
  hour:
    description:
      - Hour in the 24-hour notation at which the backup should be initiated.
      - O(hour) must be between 0 and 23.
      - See the O(minute) parameter to specify the minute in the hour.
      - V(18) by default.
    type: int
  minute:
    description:
      - Minute in the hour at which the backup should be initiated.
      - O(minute) must be between 0 and 59.
      - V(0) by default.
    type: int
  s3:
    description: Amazon S3 bucket configuration when O(type=s3).
    type: dict
    suboptions:
      bucket:
        description: Name of the Amazon S3 bucket for storing the backups.
        type: str
      object_prefix:
        description:
          - Optional folder structure in the bucket to store the backups.
        type: str
      use_iam:
        description:
          - Assume the container instance IAM role to access the S3 API.
          - V(true) by default.
        type: bool
      access_key:
        description:
          - AWS access key ID.
          - Required only when O(s3.use_iam=false).
          - You can also use the E(AWS_ACCESS_KEY_ID) or E(AWS_ACCESS_KEY)
            environment variables in decreasing order of preference.
          - If you define the O(s3.access_key) parameter, then you must also
            define the O(s3.secret_key) parameter.
        type: str
        aliases:
          - aws_access_key_id
          - aws_access_key
      secret_key:
        description:
          - AWS secret access key.
          - Required only when O(s3.use_iam=false).
          - You can also use the E(AWS_SECRET_ACCESS_KEY) or E(AWS_SECRET_KEY)
            environment variables in decreasing order of preference.
          - If you define the O(s3.secret_key) parameter, then you must also
            define the O(s3.access_key) parameter.
        type: str
        aliases:
          - aws_secret_access_key
          - aws_secret_key
      endpoint_url:
        description:
          - URL to connect to instead of the default AWS endpoints.
          - You can also use the E(AWS_URL) or E(S3_URL)
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
  gcs:
    description: Google Cloud Storage bucket configuration when O(type=gcs).
    type: dict
    suboptions:
      bucket:
        description:
          - Name of the Cloud Storage bucket for storing the backups.
        type: str
      object_prefix:
        description:
          - Optional folder structure in the bucket to store the backups.
        type: str
      use_workload_id:
        description:
          - Use the workload identity for accessing the Google Cloud API.
          - V(true) by default.
        type: bool
      service_account_key:
        description:
          - Contents of your service account key file, in JSON format, for
            accessing the Google Cloud API.
          - You can use the P(ansible.builtin.file#lookup) lookup plugin
            to read the file from the system.
          - Required only when O(gcs.use_workload_id=false).
        type: jsonarg
  s3compatible:
    description:
      - Amazon S3 compatible bucket configuration when O(type=s3compatible).
    type: dict
    suboptions:
      bucket:
        description:
          - Name of the S3 bucket for storing the backups.
          - Required for new configurations.
        type: str
      object_prefix:
        description:
          - Optional folder structure in the bucket to store the backups.
        type: str
      access_key:
        description:
          - Access key ID.
          - You can also use the E(AWS_ACCESS_KEY_ID) or E(AWS_ACCESS_KEY)
            environment variables in decreasing order of preference.
          - If you define the O(s3compatible.access_key) parameter, then you
            must also define the O(s3compatible.secret_key) parameter.
          - Required for new configurations.
        type: str
        aliases:
          - aws_access_key_id
          - aws_access_key
      secret_key:
        description:
          - AWS secret access key.
          - You can also use the E(AWS_SECRET_ACCESS_KEY) or E(AWS_SECRET_KEY)
            environment variables in decreasing order of preference.
          - If you define the O(s3compatible.secret_key) parameter, then you
            must also define the O(s3compatible.access_key) parameter.
          - Required for new configurations.
        type: str
        aliases:
          - aws_secret_access_key
          - aws_secret_key
      endpoint_url:
        description:
          - URL of the Amazon S3 compatible service. If you left out the
            scheme, then it defaults to https.
          - You can also use the E(AWS_URL) or E(S3_URL)
            environment variables in decreasing order of preference.
          - Required for new configurations.
        type: str
        aliases:
          - aws_endpoint_url
      url_style:
        description:
          - Bucket URL addressing.
          - When V(path), buckets are addressed as
            C(https://<endpoint_url>/<bucket>).
          - When V(virtual_hosted), buckets are addressed as
            C(https: //<bucket>.<endpoint_url>).
          - V(path) by default.
        type: str
        choices: [path, virtual_hosted]
      region:
        description:
          - The Amazon S3 compatible region to use.
          - You can also use the E(AWS_REGION) or E(AWS_DEFAULT_REGION)
            environment variables in decreasing order of preference.
          - Required for new configurations.
        type: str
        aliases:
          - aws_region
  state:
    description:
      - If V(absent), then the module deletes all the configurations that match
        both the O(name) and O(type) parameters.
      - The module does not fail if the configuration does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the configuration if it does not
        already exist.
      - If the configuration already exists, then the module updates its state.
        Because several configurations can match the tuple O(name) and O(type),
        the module uses only the first configuration returned by the API.
    type: str
    default: present
    choices: [absent, present]
notes:
  - Although several external backup configurations can have the same name,
    you should choose a unique name for each configuration.
  - When several configurations have the same name, the module only considers
    the first configuration returned by the API for update operations.
  - Also, the module deletes all the configurations matching both the O(name)
    and O(type) parameters for delete operations.
  - Amazon S3 compatible (O(type=s3compatible)) requires StackRox version 4.6
    or later.
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
- name: Ensure the Amazon S3 bucket configuration for external backups exists
  herve4m.rhacs_configuration.rhacs_external_backup:
    name: weekly_S3_backups
    type: s3
    backups_to_retain: 3
    interval: WEEKLY
    week_day: Monday
    hour: 23
    minute: 42
    s3:
      bucket: rhacs-backups
      object_prefix: central1
      use_iam: false
      access_key: AKIAIOSFODNN7EXAMPLE
      secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      region: us-east-1
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the number of backups to keep is updated
  herve4m.rhacs_configuration.rhacs_external_backup:
    name: weekly_S3_backups
    type: s3
    backups_to_retain: 4
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the Amazon S3 bucket configuration does not exist
  herve4m.rhacs_configuration.rhacs_external_backup:
    name: weekly_S3_backups
    type: s3
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the Google Cloud Storage bucket conf for external backups exists
  herve4m.rhacs_configuration.rhacs_external_backup:
    name: daily_GCS_backups
    type: gcs
    backups_to_retain: 1
    interval: DAILY
    hour: 20
    minute: 30
    gcs:
      bucket: rhacs-backups
      object_prefix: central1
      use_workload_id: false
      service_account_key: "{{ lookup('ansible.builtin.file', 'key.json') }}"
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the Amazon S3 compatible bucket conf for external backups exists
  herve4m.rhacs_configuration.rhacs_external_backup:
    name: daily_S3_compatible_backups
    type: s3compatible
    backups_to_retain: 2
    interval: DAILY
    hour: 20
    minute: 30
    s3compatible:
      bucket: rhacs-backups
      object_prefix: central1
      endpoint_url: s3.pl-waw.scw.cloud
      access_key: AKIAIOSFODNN7EXAMPLE
      secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      region: pl-waw
      url_style: virtual_hosted
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the external backup configuration.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

import copy

from ansible.module_utils.basic import env_fallback
from ..module_utils.api_module import APIModule


def url_style_to_api(url_style):
    return (
        "S3_URL_STYLE_VIRTUAL_HOSTED"
        if url_style == "virtual_hosted"
        else "S3_URL_STYLE_PATH"
    )


def main():

    argument_spec = dict(
        name=dict(required=True),
        type=dict(required=True, choices=["s3", "gcs", "s3compatible"]),
        backups_to_retain=dict(type="int"),
        interval=dict(choices=["DAILY", "WEEKLY"]),
        hour=dict(type="int"),
        minute=dict(type="int"),
        week_day=dict(
            choices=[
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
                "Sunday",
            ]
        ),
        s3=dict(
            type="dict",
            options=dict(
                bucket=dict(),
                object_prefix=dict(),
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
                    fallback=(env_fallback, ["AWS_URL", "S3_URL"]),
                ),
            ),
            required_together=[("access_key", "secret_key")],
        ),
        gcs=dict(
            type="dict",
            options=dict(
                bucket=dict(),
                object_prefix=dict(),
                use_workload_id=dict(type="bool"),
                service_account_key=dict(no_log=True, type="jsonarg"),
            ),
        ),
        s3compatible=dict(
            type="dict",
            options=dict(
                bucket=dict(),
                object_prefix=dict(),
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
                    fallback=(env_fallback, ["AWS_URL", "S3_URL"]),
                ),
                url_style=dict(choices=["path", "virtual_hosted"]),
            ),
            required_together=[("access_key", "secret_key")],
        ),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    name = module.params.get("name")
    provider_type = module.params.get("type")
    backups_to_retain = module.params.get("backups_to_retain")
    interval = module.params.get("interval")
    hour = module.params.get("hour")
    minute = module.params.get("minute")
    week_day = module.params.get("week_day")
    s3 = module.params.get("s3")
    gcs = module.params.get("gcs")
    s3compatible = module.params.get("s3compatible")
    state = module.params.get("state")

    # Retrieve the existing external backup configurations
    #
    # GET /v1/externalbackups
    # {
    #   "externalBackups": [
    #     {
    #       "id": "407cae0f-c75e-40bb-990a-92d132aabe45",
    #       "name": "daily_GCS_backups",
    #       "type": "gcs",
    #       "schedule": {
    #         "intervalType": "DAILY",
    #         "hour": 18,
    #         "minute": 0
    #       },
    #       "backupsToKeep": 1,
    #       "gcs": {
    #         "bucket": "rhacs-backups",
    #         "serviceAccount": "******",
    #         "objectPrefix": "",
    #         "useWorkloadId": false
    #       }
    #     },
    #     {
    #       "id": "ff0b2128-27a4-4cd5-8e96-82152550ee61",
    #       "name": "weekly_S3_backups",
    #       "type": "s3",
    #       "schedule": {
    #         "intervalType": "WEEKLY",
    #         "hour": 23,
    #         "minute": 42,
    #         "weekly": {
    #           "day": 2
    #         }
    #       },
    #       "backupsToKeep": 3,
    #       "s3": {
    #         "bucket": "rhacs-backups2",
    #         "useIam": false,
    #         "accessKeyId": "******",
    #         "secretAccessKey": "******",
    #         "region": "us-east-1",
    #         "objectPrefix": "central1",
    #         "endpoint": ""
    #       }
    #     },
    #     {
    #         "id": "a93a093c-b234-47da-83c8-64e87dd76bf6",
    #         "name": "daily_S3_compatible_backups",
    #         "type": "s3compatible",
    #         "schedule": {
    #             "intervalType": "DAILY",
    #             "hour": 20,
    #             "minute": 30
    #         },
    #         "backupsToKeep": 2,
    #         "s3compatible": {
    #             "bucket": "rhacs-backups",
    #             "accessKeyId": "******",
    #             "secretAccessKey": "******",
    #             "region": "pl-waw",
    #             "objectPrefix": "",
    #             "endpoint": "s3.pl-waw.scw.cloud",
    #             "urlStyle": "S3_URL_STYLE_VIRTUAL_HOSTED"
    #         }
    #     }
    #   ]
    # }

    c = module.get_object_path("/v1/externalbackups")

    # Retrieve the configurations that match the name and type parameters.
    # Because the several configurations can have the same name, several
    # configurations can match.
    configs = []
    for config in c.get("externalBackups", []):
        if name == config.get("name") and provider_type == config.get("type"):
            configs.append(config)

    # Remove all the configurations that match both the name and the type
    if state == "absent":
        if not configs:
            module.exit_json(changed=False)
        for config in configs:
            id = config.get("id", "")
            module.delete(
                config,
                "external backup configuration",
                id,
                "/v1/externalbackups/{id}".format(id=id),
                auto_exit=False,
            )
        module.exit_json(changed=True)

    # Validate some of the parameters
    if hour and (hour < 0 or hour > 23):
        module.fail_json(
            msg="the `hour' parameter must be between 0 and 23: {hour}".format(hour=hour)
        )

    if minute and (minute < 0 or minute > 59):
        module.fail_json(
            msg="the `minute' parameter must be between 0 and 59: {minute}".format(
                minute=minute
            )
        )

    if week_day:
        wday = [
            "Sunday",
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
        ].index(week_day)
    else:
        wday = 0

    if backups_to_retain is not None and backups_to_retain < 1:
        module.fail_json(
            msg="the `backups_to_retain' parameter must be 1 or greater: {bck}".format(
                bck=backups_to_retain
            )
        )

    # If the configuration does not exist, then create it
    if not configs:

        # Build the data to send to the API to create the configuration
        interval = interval if interval else "DAILY"
        new_fields = {
            "name": name,
            "type": provider_type,
            "backupsToKeep": backups_to_retain if backups_to_retain else 1,
            "schedule": {
                "intervalType": interval,
                "hour": hour if hour is not None else 18,
                "minute": minute if minute is not None else 0,
            },
        }
        if interval == "WEEKLY":
            new_fields["schedule"]["weekly"] = {"day": wday}

        # Verify that the s3 or gcs configurations are provided, and then
        # complete the data to send to the API
        if provider_type == "s3":
            # Verify the S3 parameters
            if not s3:
                module.fail_json(msg="type is s3 but the `s3' parameter is missing")
            missing_args = []
            if not s3.get("bucket"):
                missing_args.append("bucket")
            if not s3.get("region"):
                missing_args.append("region")
            if s3.get("use_iam") is False:
                if not s3.get("access_key"):
                    missing_args.append("access_key")
                if not s3.get("secret_key"):
                    missing_args.append("secret_key")
            if missing_args:
                module.fail_json(
                    msg="missing required `s3' arguments: {args}".format(
                        args=", ".join(missing_args)
                    )
                )
            # Build the data structure
            s3_conf = {
                "bucket": s3["bucket"],
                "useIam": s3["use_iam"] if s3.get("use_iam") is not None else True,
                "region": s3["region"],
            }
            if s3.get("endpoint_url"):
                s3_conf["endpoint"] = s3["endpoint_url"]
            if s3.get("object_prefix"):
                s3_conf["objectPrefix"] = s3["object_prefix"]
            if s3.get("use_iam") is False:
                s3_conf["accessKeyId"] = s3["access_key"]
                s3_conf["secretAccessKey"] = s3["secret_key"]
            new_fields["s3"] = s3_conf
        elif provider_type == "gcs":
            # Verify the GCS parameters
            if not gcs:
                module.fail_json(msg="type is gcs but the `gcs' parameter is missing")
            missing_args = []
            if not gcs.get("bucket"):
                missing_args.append("bucket")
            if gcs.get("use_workload_id") is False and not gcs.get("service_account_key"):
                missing_args.append("service_account_key")
            if missing_args:
                module.fail_json(
                    msg="missing required `gcs' arguments: {args}".format(
                        args=", ".join(missing_args)
                    )
                )
            # Build the data structure
            gcs_conf = {
                "bucket": gcs["bucket"],
                "useWorkloadId": (
                    gcs["use_workload_id"] if gcs.get("use_workload_id") is not None else True
                ),
            }
            if gcs.get("object_prefix"):
                gcs_conf["objectPrefix"] = gcs["object_prefix"]
            if gcs.get("use_workload_id") is False:
                gcs_conf["serviceAccount"] = gcs["service_account_key"]
            new_fields["gcs"] = gcs_conf
        else:  # provider_type == "s3compatible"
            # Verify the S3 parameters
            if not s3compatible:
                module.fail_json(
                    msg="type is s3compatible but the `s3compatible' parameter is missing"
                )
            missing_args = []
            if not s3compatible.get("bucket"):
                missing_args.append("bucket")
            if not s3compatible.get("region"):
                missing_args.append("region")
            if not s3compatible.get("access_key"):
                missing_args.append("access_key")
            if not s3compatible.get("secret_key"):
                missing_args.append("secret_key")
            if not s3compatible.get("endpoint_url"):
                missing_args.append("endpoint_url")
            if missing_args:
                module.fail_json(
                    msg="missing required `s3compatible' arguments: {args}".format(
                        args=", ".join(missing_args)
                    )
                )
            # Build the data structure
            new_fields["s3compatible"] = {
                "bucket": s3compatible["bucket"],
                "region": s3compatible["region"],
                "endpoint": s3compatible["endpoint_url"],
                "accessKeyId": s3compatible["access_key"],
                "secretAccessKey": s3compatible["secret_key"],
                "urlStyle": url_style_to_api(s3compatible.get("url_style")),
            }

        resp = module.create(
            "external backup configuration",
            name,
            "/v1/externalbackups",
            new_fields,
            auto_exit=False,
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    # Compare the existing objects to the requested configuration to verify
    # if a change is required
    for config in configs:
        schedule = config.get("schedule", {})
        if (
            (backups_to_retain is None or backups_to_retain == config.get("backupsToKeep"))
            and (interval is None or interval == schedule.get("intervalType"))
            and (hour is None or hour == schedule.get("hour"))
            and (minute is None or minute == schedule.get("minute"))
        ):
            if (
                interval == "WEEKLY"
                and week_day is not None
                and wday != schedule.get("weekly", {}).get("day")
            ):
                continue
            s3_conf = config.get("s3", {})
            gcs_conf = config.get("gcs", {})
            s3compatible_conf = config.get("s3compatible", {})
            # Because the S3 access keys and the GCS service accounts are not
            # returned by the API, the module cannot compare them with the
            # provided parameters. If the user provides those secret parameters,
            # then the module will always perform an update.
            if provider_type == "s3":
                if not s3:
                    module.exit_json(changed=False, id=config.get("id"))
                if (
                    (s3.get("bucket") is None or s3["bucket"] == s3_conf.get("bucket"))
                    and (s3.get("region") is None or s3["region"] == s3_conf.get("region"))
                    and (
                        s3.get("object_prefix") is None
                        or s3["object_prefix"] == s3_conf.get("objectPrefix")
                    )
                    and (
                        s3.get("endpoint_url") is None
                        or s3["endpoint_url"] == s3_conf.get("endpoint")
                    )
                    and (
                        s3.get("use_iam") is None
                        or (s3["use_iam"] is True and s3_conf.get("useIam") is True)
                        or (
                            s3["use_iam"] is False
                            and s3_conf.get("useIam") is False
                            and s3.get("access_key") is None
                            and s3.get("secret_key") is None
                        )
                    )
                ):
                    module.exit_json(changed=False, id=config.get("id"))
            elif provider_type == "gcs":
                if not gcs:
                    module.exit_json(changed=False, id=config.get("id"))
                if (
                    (gcs.get("bucket") is None or gcs["bucket"] == gcs_conf.get("bucket"))
                    and (
                        gcs.get("object_prefix") is None
                        or gcs["object_prefix"] == gcs_conf.get("objectPrefix")
                    )
                    and (
                        gcs.get("use_workload_id") is None
                        or (
                            gcs["use_workload_id"] is True
                            and gcs_conf.get("useWorkloadId") is True
                        )
                        or (
                            gcs["use_workload_id"] is False
                            and gcs_conf.get("useWorkloadId") is False
                            and gcs.get("service_account_key") is None
                        )
                    )
                ):
                    module.exit_json(changed=False, id=config.get("id"))
            else:  # provider_type == "s3compatible"
                if not s3compatible:
                    module.exit_json(changed=False, id=config.get("id"))
                if (
                    (
                        s3compatible.get("bucket") is None
                        or s3compatible["bucket"] == s3compatible_conf.get("bucket")
                    )
                    and (
                        s3compatible.get("region") is None
                        or s3compatible["region"] == s3compatible_conf.get("region")
                    )
                    and (
                        s3compatible.get("object_prefix") is None
                        or s3compatible["object_prefix"]
                        == s3compatible_conf.get("objectPrefix")
                    )
                    and (
                        s3compatible.get("endpoint_url") is None
                        or s3compatible["endpoint_url"] == s3compatible_conf.get("endpoint")
                    )
                    and (
                        s3compatible.get("url_style") is None
                        or url_style_to_api(s3compatible.get("url_style"))
                        == s3compatible_conf.get("urlStyle")
                    )
                    and s3compatible.get("access_key") is None
                    and s3compatible.get("secret_key") is None
                ):
                    module.exit_json(changed=False, id=config.get("id"))

    # A change is required. Only the first existing configuration is used for
    # that update.
    config = configs[0]
    data = {"updatePassword": False}
    new_fields = copy.deepcopy(config)

    if backups_to_retain is not None:
        new_fields["backupsToKeep"] = backups_to_retain
    if interval is not None:
        new_fields["schedule"]["intervalType"] = interval
    if hour is not None:
        new_fields["schedule"]["hour"] = hour
    if minute is not None:
        new_fields["schedule"]["minute"] = minute
    if week_day is not None:
        new_fields["schedule"]["weekly"] = {"day": wday}
    if provider_type == "s3":
        # Verify that if "use_iam" is changed to false, then the user provided
        # the keys
        if (
            s3
            and s3.get("use_iam") is False
            and new_fields["s3"]["useIam"] is True
            and (not s3.get("access_key") or not s3.get("secret_key"))
        ):
            missing_args = []
            if not s3.get("access_key"):
                missing_args.append("access_key")
            if not s3.get("secret_key"):
                missing_args.append("secret_key")
            module.fail_json(
                msg="missing required `s3' arguments when `use_iam' is false: {args}".format(
                    args=", ".join(missing_args)
                )
            )

        # Remove the "****" value from the secret keys
        new_fields["s3"]["accessKeyId"] = ""
        new_fields["s3"]["secretAccessKey"] = ""
        if s3:
            if s3.get("bucket") is not None:
                new_fields["s3"]["bucket"] = s3["bucket"]
            if s3.get("region") is not None:
                new_fields["s3"]["region"] = s3["region"]
            if s3.get("object_prefix") is not None:
                new_fields["s3"]["objectPrefix"] = s3["object_prefix"]
            if s3.get("endpoint_url") is not None:
                new_fields["s3"]["endpoint"] = s3["endpoint_url"]
            if s3.get("use_iam") is not None:
                new_fields["s3"]["useIam"] = s3["use_iam"]
            if s3.get("use_iam") is False and s3.get("access_key") is not None:
                data["updatePassword"] = True
                new_fields["s3"]["accessKeyId"] = s3["access_key"]
                new_fields["s3"]["secretAccessKey"] = s3["secret_key"]
    elif provider_type == "gcs":
        # Verify that if "use_workload_id" is changed to false, then the user
        # provided the service account
        if (
            gcs
            and gcs.get("use_workload_id") is False
            and new_fields["gcs"]["useWorkloadId"] is True
            and not gcs.get("service_account_key")
        ):
            module.fail_json(
                msg=(
                    "missing required `gcs' argument when `use_workload_id' is false: "
                    "service_account_key"
                )
            )

        # Remove the "****" value from the service account
        new_fields["gcs"]["serviceAccount"] = ""
        if gcs:
            if gcs.get("bucket") is not None:
                new_fields["gcs"]["bucket"] = gcs["bucket"]
            if gcs.get("object_prefix") is not None:
                new_fields["gcs"]["objectPrefix"] = gcs["object_prefix"]
            if gcs.get("use_workload_id") is not None:
                if gcs["use_workload_id"] != new_fields["gcs"]["useWorkloadId"]:
                    data["updatePassword"] = True
                    new_fields["gcs"]["useWorkloadId"] = gcs["use_workload_id"]
            if (
                gcs.get("service_account_key") is not None
                and new_fields["gcs"]["useWorkloadId"] is False
            ):
                data["updatePassword"] = True
                new_fields["gcs"]["serviceAccount"] = gcs["service_account_key"]
    else:  # provider_type == "s3compatible"
        # Both access_key and secret_key must be provided (or none of them)
        if s3compatible.get("access_key") and not s3compatible.get("secret_key"):
            module.fail_json(
                msg=(
                    "missing required `s3compatible' argument when "
                    "`access_key' is set: secret_key"
                )
            )
        if s3compatible.get("secret_key") and not s3compatible.get("access_key"):
            module.fail_json(
                msg=(
                    "missing required `s3compatible' argument when "
                    "`secret_key' is set: access_key"
                )
            )

        # Remove the "****" value from the secret keys
        new_fields["s3compatible"]["accessKeyId"] = ""
        new_fields["s3compatible"]["secretAccessKey"] = ""
        if s3compatible:
            if s3compatible.get("bucket") is not None:
                new_fields["s3compatible"]["bucket"] = s3compatible["bucket"]
            if s3compatible.get("region") is not None:
                new_fields["s3compatible"]["region"] = s3compatible["region"]
            if s3compatible.get("object_prefix") is not None:
                new_fields["s3compatible"]["objectPrefix"] = s3compatible["object_prefix"]
            if s3compatible.get("endpoint_url") is not None:
                new_fields["s3compatible"]["endpoint"] = s3compatible["endpoint_url"]
            if s3compatible.get("url_style") is not None:
                new_fields["s3compatible"]["urlStyle"] = url_style_to_api(
                    s3compatible["url_style"]
                )
            if s3compatible.get("access_key") is not None:
                data["updatePassword"] = True
                new_fields["s3compatible"]["accessKeyId"] = s3compatible["access_key"]
                new_fields["s3compatible"]["secretAccessKey"] = s3compatible["secret_key"]

    data["externalBackup"] = new_fields
    id = config.get("id", "")
    module.patch(
        "external backup configuration", name, "/v1/externalbackups/{id}".format(id=id), data
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
