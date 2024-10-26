#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_compliance_schedule
short_description: Manage compliance schedule configurations
description:
  - Create, delete, and update compliance schedule configurations.
version_added: '1.1.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description:
      - Name of the compliance schedule configuration.
      - The name can contain only lowercase alphanumeric characters, hyphens
        C(-), and periods C(.), and must start and end with an alphanumeric
        character.
    required: true
    type: str
  new_name:
    description:
      - New name for the compliance schedule configuration.
      - Setting this option changes the name of the compliance schedule
        configuration, which current name is provided in the O(name) parameter.
      - The module returns an error if the destination configuration already
        exists.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  description:
    description:
      - Optional description for the compliance schedule configuration.
    type: str
  profiles:
    description:
      - List of compliance profiles to use for verifying the secured clusters.
      - The compliance profiles come from the compliance operator.
      - At least one profile is required when you create a compliance schedule
        configuration.
      - You can have only one compliance schedule that scans the same profile
        on the same cluster.
    type: list
    elements: str
  append_profiles:
    description:
      - If V(true), then the module adds the profiles listed in the
        O(profiles) list to the existing list.
      - If V(false), then the module replaces the current list of profiles
        with the list from the O(profiles) parameter.
    type: bool
    default: true
  interval:
    description:
      - Compliance scan frequency.
      - If you set the O(interval) parameter to V(WEEKLY), then provide
        your chosen week days for the scans in the O(week_days) parameter.
      - If you set the O(interval) parameter to V(MONTHLY), then provide
        your chosen days for the scans in the O(month_days) parameter.
      - V(DAILY) by default.
    type: str
    choices:
      - DAILY
      - WEEKLY
      - MONTHLY
  week_days:
    description:
      - Name of the days for weekly scans when O(interval=WEEKLY).
      - Mutually exclusive with O(month_days).
      - V([Sunday]) by default.
    type: list
    elements: str
    choices:
      - Monday
      - Tuesday
      - Wednesday
      - Thursday
      - Friday
      - Saturday
      - Sunday
  month_days:
    description:
      - Days of the month for monthly scans when O(interval=MONTHLY).
      - The days in O(month_days) must be between 1 and 31.
      - Mutually exclusive with O(week_days).
      - V([1]) by default.
    type: list
    elements: int
  hour:
    description:
      - Hour in the 24-hour notation at which the scan should start.
      - O(hour) must be between 0 and 23.
      - See the O(minute) parameter to specify the minute in the hour.
      - V(18) by default.
    type: int
  minute:
    description:
      - Minute in the hour at which the scan should start.
      - O(minute) must be between 0 and 59.
      - V(0) by default.
    type: int
  email_notifiers:
    description:
      - Optional email delivery destinations for sending the compliance scan
        reports.
    type: list
    elements: dict
    suboptions:
      notifier:
        description:
          - Name or identifier of the notification method to use for sending
            emails.
          - Only email notification methods can be used.
          - See the M(herve4m.rhacs_configuration.rhacs_notifier_integration)
            module to create and manage notification methods.
        type: str
        required: true
      to:
        description:
          - Email addresses of the recipients who should receive the compliance
            reports.
          - By default, the module uses the recipient email address that the
            notifier method defines.
        type: list
        elements: str
      subject:
        description:
          - Subject line for the emails.
          - If you omit the parameter, then a default subject is used.
        type: str
      body:
        description:
          - Text of the emails.
          - If you omit the parameter, then a default text is used.
        type: str
  clusters:
    description:
      - List of the clusters to scan for compliance.
      - You can specify the clusters by their names or their identifiers.
      - At least one cluster is required when you create a compliance schedule
        configuration.
    type: list
    elements: str
  append_clusters:
    description:
      - If V(true), then the module adds the clusters listed in the O(clusters)
        list to the existing list.
      - If V(false), then the module replaces the current list of clusters
        with the list from the O(clusters) parameter.
    type: bool
    default: true
  state:
    description:
      - If V(absent), then the module deletes the configuration.
      - The module does not fail if the configuration does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the configuration if it does not
        already exist.
      - If the configuration already exists, then the module updates its state,
        and renames the configuration if you provide the O(new_name) parameter.
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
- name: Ensure the weekly compliance scan is scheduled
  herve4m.rhacs_configuration.rhacs_compliance_schedule:
    name: weekly-scan
    description: Weekly compliance scan
    profiles:
      - ocp4-cis
      - ocp4-pci-dss
    interval: WEEKLY
    week_days:
      - Monday
    hour: 23
    minute: 42
    email_notifiers:
      - notifier: email notifications
        to:
          - security@example.com
          - secteam@example.com
        subject: RHACS compliance scan report
    clusters:
      - production
      - infra
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the public cluster is added to the compliance scan report
  herve4m.rhacs_configuration.rhacs_compliance_schedule:
    name: weekly-scan
    clusters:
      - public
    append_clusters: true
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the weekly compliance scan is renamed and sends monthly reports
  herve4m.rhacs_configuration.rhacs_compliance_schedule:
    name: weekly-scan
    new_name: monthly-reports
    description: Monthly compliance scan
    interval: MONTHLY
    month_days:
      - 1
      - 15
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the monthly compliance scan is removed
  herve4m.rhacs_configuration.rhacs_compliance_schedule:
    name: monthly-reports
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the compliance schedule configuration.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

import copy

from ..module_utils.api_module import APIModule

WEEK_DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]


def main():

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        description=dict(),
        profiles=dict(type="list", elements="str"),
        append_profiles=dict(type="bool", default=True),
        interval=dict(choices=["DAILY", "WEEKLY", "MONTHLY"]),
        hour=dict(type="int"),
        minute=dict(type="int"),
        week_days=dict(type="list", elements="str", choices=WEEK_DAYS),
        month_days=dict(type="list", elements="int"),
        email_notifiers=dict(
            type="list",
            elements="dict",
            options=dict(
                notifier=dict(required=True),
                to=dict(type="list", elements="str"),
                subject=dict(),
                body=dict(),
            ),
        ),
        clusters=dict(type="list", elements="str"),
        append_clusters=dict(type="bool", default=True),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(
        argument_spec=argument_spec,
        mutually_exclusive=[("week_days", "month_days")],
        supports_check_mode=True,
    )

    # Extract our parameters
    name = module.params.get("name")
    new_name = module.params.get("new_name")
    description = module.params.get("description")
    profiles = module.params.get("profiles")
    append_profiles = module.params.get("append_profiles")
    interval = module.params.get("interval")
    hour = module.params.get("hour")
    minute = module.params.get("minute")
    week_days = module.params.get("week_days")
    month_days = module.params.get("month_days")
    email_notifiers = module.params.get("email_notifiers")
    clusters = module.params.get("clusters")
    append_clusters = module.params.get("append_clusters")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the existing compliance schedules
    #
    # GET /v2/compliance/scan/configurations
    # {
    #     "configurations": [
    #         {
    #             "id": "511df30c-123f-4979-8abc-8eb7a3c9f3e3",
    #             "scanName": "Monthly scan",
    #             "scanConfig": {
    #                 "oneTimeScan": false,
    #                 "profiles": [
    #                     "ocp4-cis",
    #                     "ocp4-pci-dss-node-4-0"
    #                 ],
    #                 "scanSchedule": {
    #                     "intervalType": "MONTHLY",
    #                     "hour": 20,
    #                     "minute": 42,
    #                     "daysOfMonth": {
    #                         "days": [
    #                             1
    #                         ]
    #                     }
    #                 },
    #                 "description": "Perform a monthly scan",
    #                 "notifiers": []
    #             },
    #             "clusterStatus": [
    #                 {
    #                     "clusterId": "e3133d73-7f9a-438d-8099-b52ba68b33e7",
    #                     "errors": [
    #                         ""
    #                     ],
    #                     "clusterName": "managed-cluster",
    #                     "suiteStatus": {
    #                         "phase": "DONE",
    #                         "result": "NON-COMPLIANT",
    #                         "errorMessage": "",
    #                         "lastTransitionTime": "2024-10-18T13:52:13Z"
    #                     }
    #                 }
    #             ],
    #             "createdTime": "2024-10-18T13:51:00.219090285Z",
    #             "lastUpdatedTime": "2024-10-18T13:51:00.232759597Z",
    #             "modifiedBy": {
    #                 "id": "sso:4df1b98c-24ed-4073-a9ad-356aec6bb62d:admin",
    #                 "name": "admin"
    #             },
    #             "lastExecutedTime": "2024-10-18T13:52:13Z"
    #         },
    #         {
    #             "id": "d6a6b28e-9a64-41ef-b6f9-05bf57f1fefd",
    #             "scanName": "Weekly scan",
    #             "scanConfig": {
    #                 "oneTimeScan": false,
    #                 "profiles": [
    #                     "ocp4-cis-1-4"
    #                 ],
    #                 "scanSchedule": {
    #                     "intervalType": "WEEKLY",
    #                     "hour": 20,
    #                     "minute": 45,
    #                     "daysOfWeek": {
    #                         "days": [
    #                             0
    #                         ]
    #                     }
    #                 },
    #                 "description": "Perform a weekly scan",
    #                 "notifiers": [
    #                     {
    #                         "emailConfig": {
    #                             "notifierId": "657a...74f9",
    #                             "mailingLists": [
    #                                 "foo1@example.com"
    #                             ],
    #                             "customSubject": "This is the subje",
    #                             "customBody": "My body"
    #                         },
    #                         "notifierName": "email"
    #                     }
    #                 ]
    #             },
    #             "clusterStatus": [
    #                 {
    #                     "clusterId": "e3133d73-7f9a-438d-8099-b52ba68b33e7",
    #                     "errors": [
    #                         ""
    #                     ],
    #                     "clusterName": "managed-cluster",
    #                     "suiteStatus": {
    #                         "phase": "DONE",
    #                         "result": "NON-COMPLIANT",
    #                         "errorMessage": "",
    #                         "lastTransitionTime": "2024-10-18T14:02:33Z"
    #                     }
    #                 }
    #             ],
    #             "createdTime": "2024-10-18T14:01:24.365418945Z",
    #             "lastUpdatedTime": "2024-10-18T14:01:24.378753158Z",
    #             "modifiedBy": {
    #                 "id": "sso:4df1b98c-24ed-4073-a9ad-356aec6bb62d:admin",
    #                 "name": "admin"
    #             },
    #             "lastExecutedTime": "2024-10-18T14:02:33Z"
    #         }
    #     ],
    #     "totalCount": 2
    # }

    c = module.get_object_path(
        "/v2/compliance/scan/configurations", query_params={"pagination.limit": 10000}
    )
    schedules = c.get("configurations", [])

    # Retrieve the objects for the given names
    config = module.get_item_from_resource_list(name, schedules, "scanName")
    new_config = module.get_item_from_resource_list(new_name, schedules, "scanName")

    # Remove the object. For delete operations, the new_name parameter is
    # ignored.
    if state == "absent":
        module.delete(
            config,
            "compliance schedule",
            name,
            "/v2/compliance/scan/configurations/{id}".format(
                id=config.get("id", "") if config else ""
            ),
        )

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

    if week_days:
        wdays = set([WEEK_DAYS.index(d) for d in week_days])
    else:
        wdays = set([0])

    if month_days:
        mdays = set()
        for d in month_days:
            if d < 1 or d > 31:
                module.fail_json(
                    msg=(
                        "the days in the `month_days' parameter must be "
                        "between 1 and 31: {month_days}"
                    ).format(month_days=", ".join([str(i) for i in month_days]))
                )
            mdays.add(d)
    else:
        mdays = set([1])

    if clusters is not None:
        req_clusters = set([module.get_cluster_id(c) for c in clusters])
    else:
        req_clusters = set()

    if profiles is not None:
        req_profiles = set(profiles)
    else:
        req_profiles = set()

    notifiers = []
    req_notifiers = set()
    if email_notifiers is not None:
        for n in email_notifiers:
            obj = module.get_notifier(n["notifier"])
            if not obj:
                module.fail_json(
                    msg=(
                        "the notifier method (in `email_notifiers') does not exist: {name}"
                    ).format(name=n["notifier"])
                )
            if obj.get("type") != "email":
                module.fail_json(
                    msg=(
                        "the notifier method (in `email_notifiers') is not "
                        "an email notifier: {name}: {t}"
                    ).format(name=n["notifier"], t=obj.get("type"))
                )
            id = obj.get("id")
            notifier_name = obj.get("name")
            subject = n.get("subject") or ""
            body = n.get("body") or ""
            dest = n.get("to") or [obj.get("labelDefault", "")]
            notifiers.append(
                {
                    "emailConfig": {
                        "notifierId": id,
                        "mailingLists": dest,
                        "customSubject": subject,
                        "customBody": body,
                    },
                    "notifierName": notifier_name,
                }
            )
            req_notifiers.add((id, notifier_name, ",".join(sorted(dest)), subject, body))

    # Create the object
    if not config and not new_config:

        # Verify that the required parameters are provided
        missing_args = []
        if not profiles:
            missing_args.append("profiles")
        if not clusters:
            missing_args.append("clusters")
        if missing_args:
            module.fail_json(
                msg="missing or empty required arguments: {args}".format(
                    args=", ".join(missing_args)
                )
            )

        # Build the data to send to the API to create the configuration
        name = new_name if new_name else name
        interval = interval if interval else "DAILY"
        new_fields = {
            "scanName": name,
            "scanConfig": {
                "description": description if description else "",
                "oneTimeScan": False,
                "profiles": list(req_profiles),
                "scanSchedule": {
                    "hour": hour if hour is not None else 18,
                    "minute": minute if minute is not None else 0,
                    "intervalType": interval,
                },
                "notifiers": notifiers,
            },
            "clusters": list(req_clusters),
        }
        if interval == "WEEKLY":
            new_fields["scanConfig"]["scanSchedule"]["daysOfWeek"] = {"days": list(wdays)}
        elif interval == "MONTHLY":
            new_fields["scanConfig"]["scanSchedule"]["daysOfMonth"] = {"days": list(mdays)}

        resp = module.create(
            "compliance schedule",
            name,
            "/v2/compliance/scan/configurations",
            new_fields,
            auto_exit=False,
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    if not config and new_config:
        config = new_config
        name = new_name
        new_config = new_name = None

    # A compliance schedule with the new name already exists
    if new_config:
        module.fail_json(
            msg="the compliance schedule (`new_name') already exists: {name}".format(
                name=new_name
            )
        )

    # Verify whether a change is needed
    scan_config = config.get("scanConfig", {})
    scan_schedule = scan_config.get("scanSchedule", {})

    curr_clusters = set([c.get("clusterId") for c in config.get("clusterStatus", [])])
    clusters_to_add = req_clusters - curr_clusters

    curr_profiles = set(scan_config.get("profiles", []))
    profiles_to_add = req_profiles - curr_profiles

    curr_notifiers = set()
    for n in scan_config.get("notifiers", []):
        email_conf = n.get("emailConfig", {})
        curr_notifiers.add(
            (
                email_conf.get("notifierId"),
                n.get("notifierName"),
                ",".join(sorted(email_conf.get("mailingLists", []))),
                email_conf.get("customSubject", ""),
                email_conf.get("customBody", ""),
            )
        )

    curr_wdays = set(scan_schedule.get("daysOfWeek", {}).get("days", []))
    curr_mdays = set(scan_schedule.get("daysOfMonth", {}).get("days", []))

    if (
        not new_name
        and (description is None or description == scan_config.get("description"))
        and (interval is None or interval == scan_schedule.get("intervalType"))
        and (hour is None or hour == scan_schedule.get("hour"))
        and (minute is None or minute == scan_schedule.get("minute"))
        and (week_days is None or wdays == curr_wdays)
        and (month_days is None or mdays == curr_mdays)
        and (
            clusters is None
            or req_clusters == curr_clusters
            or (append_clusters is True and not clusters_to_add)
        )
        and (
            profiles is None
            or req_profiles == curr_profiles
            or (append_profiles is True and not profiles_to_add)
        )
        and (email_notifiers is None or req_notifiers == curr_notifiers)
    ):
        module.exit_json(changed=False, id=config.get("id", ""))

    id = config.get("id", "")
    name = new_name if new_name else name
    new_fields = {
        "id": id,
        "scanName": name,
        "scanConfig": copy.deepcopy(config.get("scanConfig", {})),
        "clusters": list(curr_clusters),
    }

    if description is not None:
        new_fields["scanConfig"]["description"] = description
    if interval is not None:
        new_fields["scanConfig"]["scanSchedule"]["intervalType"] = interval
        if interval == "WEEKLY":
            new_fields["scanConfig"]["scanSchedule"].pop("daysOfMonth", None)
            if "daysOfWeek" not in new_fields["scanConfig"]["scanSchedule"]:
                new_fields["scanConfig"]["scanSchedule"]["daysOfWeek"] = {"days": list(wdays)}
        elif interval == "MONTHLY":
            new_fields["scanConfig"]["scanSchedule"].pop("daysOfWeek", None)
            if "daysOfMonth" not in new_fields["scanConfig"]["scanSchedule"]:
                new_fields["scanConfig"]["scanSchedule"]["daysOfMonth"] = {
                    "days": list(mdays)
                }
        else:  # interval == "DAILY"
            new_fields["scanConfig"]["scanSchedule"].pop("daysOfMonth", None)
            new_fields["scanConfig"]["scanSchedule"].pop("daysOfWeek", None)
    if hour is not None:
        new_fields["scanConfig"]["scanSchedule"]["hour"] = hour
    if minute is not None:
        new_fields["scanConfig"]["scanSchedule"]["minute"] = minute
    if (
        week_days is not None
        and new_fields["scanConfig"]["scanSchedule"]["intervalType"] == "WEEKLY"
    ):
        new_fields["scanConfig"]["scanSchedule"]["daysOfWeek"] = {"days": list(wdays)}
    if (
        month_days is not None
        and new_fields["scanConfig"]["scanSchedule"]["intervalType"] == "MONTHLY"
    ):
        new_fields["scanConfig"]["scanSchedule"]["daysOfMonth"] = {"days": list(mdays)}
    if email_notifiers is not None:
        new_fields["scanConfig"]["notifiers"] = notifiers
    if profiles is not None:
        if append_profiles is True:
            new_fields["scanConfig"]["profiles"].extend(list(profiles_to_add))
        else:
            if not profiles:
                module.fail_json(msg="at least one profile (in `profiles') is required")
            new_fields["scanConfig"]["profiles"] = profiles
    if clusters is not None:
        if append_clusters is True:
            new_fields["clusters"].extend(list(clusters_to_add))
        else:
            if not clusters:
                module.fail_json(msg="at least one cluster (in `clusters') is required")
            new_fields["clusters"] = list(req_clusters)

    module.unconditional_update(
        "compliance schedule",
        name,
        "/v2/compliance/scan/configurations/{id}".format(id=id),
        new_fields,
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
