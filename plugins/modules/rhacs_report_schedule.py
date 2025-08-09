#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, 2025 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_report_schedule
short_description: Manage vulnerability reporting schedules
description:
  - Create, delete, and update vulnerability reporting schedules.
version_added: '1.1.0'
author: Hervé Quatremain (@herve4m)
options:
  name:
    description:
      - Name of the vulnerability reporting schedule.
      - Several schedules can have the same name.
      - For a delete operation, the module removes all the schedules matching
        the O(name) parameter.
      - For update operations, the module updates only the configuration that
        matches closely the provided parameters.
    required: true
    type: str
  new_name:
    description:
      - New name for the vulnerability reporting schedule.
      - Setting this option changes the name of the schedule, which current
        name is provided in the O(name) parameter.
      - The module returns an error if the destination schedule already exists.
      - The O(new_name) parameter is ignored when O(state=absent).
    type: str
  description:
    description:
      - Optional description for the vulnerability reporting schedule.
    type: str
  fixability:
    description:
      - Whether to include CVEs that are fixable, not fixable, or both.
      - V(BOTH) by default.
    type: str
    choices:
      - FIXABLE
      - NOT_FIXABLE
      - BOTH
  severities:
    description:
      - Severities of the CVEs to report.
      - V(IMPORTANT) and V(CRITICAL) by default.
    type: list
    elements: str
    choices:
      - UNKNOWN
      - LOW
      - MODERATE
      - IMPORTANT
      - CRITICAL
  image_types:
    description:
      - Whether to include CVEs from deployed images, watched images, or both.
      - V(DEPLOYED) and V(WATCHED) by default.
    type: list
    elements: str
    choices:
      - DEPLOYED
      - WATCHED
  include:
    description: Columns to include in the report.
    type: dict
    suboptions:
      nvd_cvss:
        description:
          - Whether to include the NVD CVSS column in the report configuration.
          - V(false) by default.
        type: bool
      epss_probability:
        description:
          - Whether to include the EPSS probability column in the report
            configuration.
          - V(false) by default.
        type: bool
      advisory:
        description:
          - Whether to include the advisory name and link column in the report
            configuration.
          - V(false) by default.
        type: bool
  since:
    description:
      - Include CVEs based on their discovery date.
      - If O(since=ALL_TIME), then the reports do not exclude CVEs based on
        their date.
      - If O(since=LAST_SENT), then the reports include only the CVEs
        discovered after the last report. When O(since=LAST_SENT), the
        O(email_notifiers) and O(interval) parameters are required.
      - If O(since=DATE), then the reports include the CVEs discovered after
        the date given in the O(date) parameter.
      - V(ALL_TIME) by default.
    type: str
    choices:
      - ALL_TIME
      - LAST_SENT
      - DATE
  date:
    description:
      - The date after which the CVEs must be reported. The O(date) parameter
        is used only when O(since=DATE).
      - The format for the O(date) parameter is C(YYYY-MM-DD), such
        as 2024-05-25.
    type: str
  collection:
    description:
      - Deployment collection to include in the reports.
      - You can specify the collection by its name or by its identifier.
      - See the M(herve4m.rhacs_configuration.rhacs_collection) module to
        create and manage deployment collections.
    type: str
  interval:
    description:
      - Reporting frequency.
      - If you set the O(interval) parameter to V(WEEKLY), then provide
        your chosen week days for the reports in the O(week_days) parameter.
      - If you set the O(interval) parameter to V(MONTHLY), then provide
        your chosen days for the reports in the O(month_days) parameter.
      - When O(interval=UNSET), then the reports are not scheduled.
      - V(UNSET) by default.
    type: str
    choices:
      - UNSET
      - WEEKLY
      - MONTHLY
  week_days:
    description:
      - Name of the days for weekly reports when O(interval=WEEKLY).
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
      - Days of the month for monthly reports when O(interval=MONTHLY).
      - The days in O(month_days) must be between 1 and 31.
      - Mutually exclusive with O(week_days).
      - V([1]) by default.
    type: list
    elements: int
  hour:
    description:
      - Hour in the 24-hour notation at which the report should be created.
      - O(hour) must be between 0 and 23.
      - See the O(minute) parameter to specify the minute in the hour.
      - V(18) by default.
    type: int
  minute:
    description:
      - Minute in the hour at which the report should be created.
      - O(minute) must be between 0 and 59.
      - V(0) by default.
    type: int
  email_notifiers:
    description:
      - Optional email delivery destinations for sending the vulnerability
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
          - Email addresses of the recipients who should receive the
            vulnerability reports.
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
  state:
    description:
      - If V(absent), then the module deletes all the schedules that match
        the O(name) parameter.
      - The module does not fail if the schedule does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the schedule if it does not
        already exist.
      - If the schedule exists, then the module updates its state, and renames
        the schedule if you provide the O(new_name) parameter.
    type: str
    default: present
    choices: [absent, present]
notes:
  - Although several vulnerability schedules can have the same name,
    you should choose a unique name for each schedule.
  - For update operations, when several schedules have the same name, the
    module selects the schedule that matches most of the provided parameters.
  - Also, the module deletes all the schedules matching the O(name) parameter
    for delete operations.
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
- name: Ensure the weekly vulnerability report is scheduled
  herve4m.rhacs_configuration.rhacs_report_schedule:
    name: Weekly report
    description: Bi-weekly vulnerability report of fixable CVEs
    fixability: FIXABLE
    severities:
      - IMPORTANT
      - CRITICAL
    image_types:
      - DEPLOYED
      - WATCHED
    include:
      nvd_cvss: true
      epss_probability: false
    collection: Sensitive data
    since: DATE
    date: "2024-05-25"
    interval: WEEKLY
    week_days:
      - Sunday
      - Wednesday
    email_notifiers:
      - notifier: email notifications
        to:
          - security@example.com
          - secteam@example.com
        subject: RHACS vulnerability report
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the weekly vulnerability report is renamed
  herve4m.rhacs_configuration.rhacs_report_schedule:
    name: Weekly report
    new_name: Bi-weekly report
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the bi-weekly vulnerability report is removed
  herve4m.rhacs_configuration.rhacs_report_schedule:
    name: Bi-weekly report
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r"""
id:
  description: Internal identifier of the vulnerability reporting schedule.
  type: str
  returned: always
  sample: b112af00-8256-43fe-82fd-ecafb62c5bea
"""

from datetime import datetime
import copy

from ..module_utils.api_module import APIModule

WEEK_DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]


def severity_to_API_type(severity):
    if not severity:
        return None
    if severity == "UNKNOWN":
        return "UNKNOWN_VULNERABILITY_SEVERITY"
    if severity == "LOW":
        return "LOW_VULNERABILITY_SEVERITY"
    if severity == "MODERATE":
        return "MODERATE_VULNERABILITY_SEVERITY"
    if severity == "IMPORTANT":
        return "IMPORTANT_VULNERABILITY_SEVERITY"
    # if severity == "CRITICAL":
    return "CRITICAL_VULNERABILITY_SEVERITY"


def main():

    argument_spec = dict(
        name=dict(required=True),
        new_name=dict(),
        description=dict(),
        fixability=dict(choices=["BOTH", "FIXABLE", "NOT_FIXABLE"]),
        severities=dict(
            type="list",
            elements="str",
            choices=["UNKNOWN", "LOW", "MODERATE", "IMPORTANT", "CRITICAL"],
        ),
        image_types=dict(type="list", elements="str", choices=["DEPLOYED", "WATCHED"]),
        include=dict(
            type="dict",
            options=dict(
                nvd_cvss=dict(type="bool"),
                epss_probability=dict(type="bool"),
                advisory=dict(type="bool"),
            ),
        ),
        since=dict(choices=["ALL_TIME", "LAST_SENT", "DATE"]),
        date=dict(),
        collection=dict(),
        interval=dict(choices=["UNSET", "WEEKLY", "MONTHLY"]),
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
    fixability = module.params.get("fixability")
    severities = module.params.get("severities")
    image_types = module.params.get("image_types")
    include = module.params.get("include")
    since = module.params.get("since")
    date = module.params.get("date")
    collection = module.params.get("collection")
    interval = module.params.get("interval")
    hour = module.params.get("hour")
    minute = module.params.get("minute")
    week_days = module.params.get("week_days")
    month_days = module.params.get("month_days")
    email_notifiers = module.params.get("email_notifiers")
    state = module.params.get("state")

    if new_name == name:
        new_name = None

    # Retrieve the existing vulnerability reporting schedules
    #
    # GET /v2/reports/configurations
    # {
    #     "reportConfigs": [
    #         {
    #             "id": "66211b6b-fcac-48e8-b583-78943b6862ef",
    #             "name": "myreport",
    #             "description": "my description",
    #             "type": "VULNERABILITY",
    #             "vulnReportFilters": {
    #                 "fixability": "FIXABLE",
    #                 "severities": [
    #                     "CRITICAL_VULNERABILITY_SEVERITY",
    #                     "IMPORTANT_VULNERABILITY_SEVERITY"
    #                 ],
    #                 "imageTypes": [
    #                     "DEPLOYED",
    #                     "WATCHED"
    #                 ],
    #                 "includeNvdCvss": true,
    #                 "includeEpssProbability": false,
    #                 "includeAdvisory": true
    #                 "sinceStartDate": "2024-10-16T00:00:00Z"
    #             },
    #             "schedule": {
    #                 "intervalType": "MONTHLY",
    #                 "hour": 0,
    #                 "minute": 0,
    #                 "daysOfMonth": {
    #                     "days": [
    #                         1
    #                     ]
    #                 }
    #             },
    #             "resourceScope": {
    #                 "collectionScope": {
    #                     "collectionId": "eebb...bb52",
    #                     "collectionName": "mycol"
    #                 }
    #             },
    #             "notifiers": [
    #                 {
    #                     "emailConfig": {
    #                         "notifierId": "657a...74f9",
    #                         "mailingLists": [
    #                             "foo@example.com"
    #                         ],
    #                         "customSubject": "",
    #                         "customBody": ""
    #                     },
    #                     "notifierName": "myemail"
    #                 }
    #             ]
    #         },
    #         {
    #             "id": "cdeaff52-e9ae-4b97-9de7-1cf926739166",
    #             "name": "myreport",
    #             "description": "My report",
    #             "type": "VULNERABILITY",
    #             "vulnReportFilters": {
    #                 "fixability": "FIXABLE",
    #                 "severities": [
    #                     "CRITICAL_VULNERABILITY_SEVERITY",
    #                     "IMPORTANT_VULNERABILITY_SEVERITY"
    #                 ],
    #                 "imageTypes": [
    #                     "DEPLOYED",
    #                     "WATCHED"
    #                 ],
    #                 "allVuln": true
    #             },
    #             "schedule": null,
    #             "resourceScope": {
    #                 "collectionScope": {
    #                     "collectionId": "eebb...bb52",
    #                     "collectionName": "mycol"
    #                 }
    #             },
    #             "notifiers": []
    #         }
    #     ]
    # }

    c = module.get_object_path(
        "/v2/reports/configurations", query_params={"pagination.limit": 10000}
    )
    reports = c.get("reportConfigs", [])

    # Retrieve the objects for the given names. Several configurations can
    # have the same name.
    configs = []
    new_configs = []
    for s in reports:
        s_name = s.get("name")
        if name == s_name:
            configs.append(s)
        elif new_name == s_name:
            new_configs.append(s)

    # Remove all the objects matching the given name. For delete operations,
    # the new_name parameter is ignored.
    if state == "absent":
        if not configs:
            module.exit_json(changed=False)
        for config in configs:
            id = config.get("id", "")
            module.delete(
                config,
                "vulnerability reporting schedule",
                "{name} ({id})".format(name=name, id=id),
                "/v2/reports/configurations/{id}".format(id=id),
                auto_exit=False,
            )
        module.exit_json(changed=True)

    # Validate and convert some of the parameters
    if severities:
        req_severities = set([severity_to_API_type(s) for s in severities])
    else:
        req_severities = set()

    if image_types:
        req_image_types = set(image_types)
    else:
        req_image_types = set(["DEPLOYED", "WATCHED"])

    if date:
        try:
            d = datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            module.fail_json(
                msg="the `date' parameter must have the `YYYY-MM-DD' format: {d}".format(
                    d=date
                )
            )
        start_date = d.isoformat() + "Z"
    else:
        start_date = datetime.now().strftime("%Y-%m-%dT00:00:00Z")

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

    if collection is not None:
        req_collection = module.get_collection(collection)
        if not req_collection:
            module.fail_json(
                msg=(
                    "the deployment collection (in `collection') does not exist: {name}"
                ).format(name=collection)
            )
    else:
        req_collection = None

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
    if not configs and not new_configs:
        # Verify that the collection parameter is provided
        if not collection:
            module.fail_json(msg="missing or empty required arguments: collection")

        # Build the data to send to the API to create the configuration
        name = new_name if new_name else name
        fixability = fixability if fixability else "BOTH"
        severity_list = (
            list(req_severities)
            if req_severities
            else ["CRITICAL_VULNERABILITY_SEVERITY", "IMPORTANT_VULNERABILITY_SEVERITY"]
        )
        since = since if since else "ALL_TIME"
        interval = interval if interval else "UNSET"
        if since == "LAST_SENT":
            if not notifiers:
                module.fail_json(
                    msg="when `since=LAST_SENT', the `email_notifiers' parameter is required"
                )
            if interval == "UNSET":
                module.fail_json(
                    msg=(
                        "when `since=LAST_SENT', the `interval' parameter is "
                        "required, and cannot be `UNSET'"
                    )
                )

        new_fields = {
            "name": name,
            "description": description if description else "",
            "type": "VULNERABILITY",
            "vulnReportFilters": {
                "fixability": fixability,
                "severities": severity_list,
                "imageTypes": list(req_image_types),
            },
            "resourceScope": {
                "collectionScope": {
                    "collectionId": req_collection.get("id", ""),
                    "collectionName": req_collection.get("name", ""),
                }
            },
            "notifiers": notifiers,
        }

        if include:
            if include.get("nvd_cvss") is not None:
                new_fields["vulnReportFilters"]["includeNvdCvss"] = include.get("nvd_cvss")
            if include.get("epss_probability") is not None:
                new_fields["vulnReportFilters"]["includeEpssProbability"] = include.get(
                    "epss_probability"
                )
            if include.get("advisory") is not None:
                new_fields["vulnReportFilters"]["includeAdvisory"] = include.get("advisory")

        if since == "ALL_TIME":
            new_fields["vulnReportFilters"]["allVuln"] = True
        elif since == "LAST_SENT":
            new_fields["vulnReportFilters"]["sinceLastSentScheduledReport"] = True
        else:  # since == "DATE"
            new_fields["vulnReportFilters"]["sinceStartDate"] = start_date

        if interval == "UNSET":
            new_fields["schedule"] = None
        else:
            new_fields["schedule"] = {
                "intervalType": interval,
                "hour": hour if hour is not None else 18,
                "minute": minute if minute is not None else 0,
            }
            if interval == "WEEKLY":
                new_fields["schedule"]["daysOfWeek"] = {"days": list(wdays)}
            else:  # interval == "MONTHLY":
                new_fields["schedule"]["daysOfMonth"] = {"days": list(mdays)}

        resp = module.create(
            "vulnerability reporting schedule",
            name,
            "/v2/reports/configurations",
            new_fields,
            auto_exit=False,
        )
        module.exit_json(changed=True, id=resp.get("id", ""))

    if not configs and new_configs:
        configs = new_configs
        name = new_name
        new_configs = new_name = None

    # A vulnerability reporting schedule with the new name already exists
    if new_configs:
        module.fail_json(
            msg=(
                "the vulnerability reporting schedule (`new_name') already exists: {name}"
            ).format(name=new_name)
        )

    # Verify whether a change is needed. Go through all the configurations
    # that match the given name, and select the one with the most matches.
    min_changes = 100
    for config in configs:
        vuln_report = config.get("vulnReportFilters", {})
        schedule = config.get("schedule")
        schedule = schedule if schedule else {}

        curr_severities = set(vuln_report.get("severities", []))
        curr_image_types = set(vuln_report.get("imageTypes", []))

        curr_notifiers = set()
        for n in config.get("notifiers", []):
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

        curr_wdays = set(schedule.get("daysOfWeek", {}).get("days", []))
        curr_mdays = set(schedule.get("daysOfMonth", {}).get("days", []))

        changes = 0
        if new_name:
            changes += 1
        if description is not None and description != config.get("description"):
            changes += 1
        if fixability and fixability != vuln_report.get("fixability"):
            changes += 1
        if severities and req_severities != curr_severities:
            changes += 1
        if image_types and req_image_types != curr_image_types:
            changes += 1
        if include:
            if include.get("nvd_cvss") is not None and include.get(
                "nvd_cvss"
            ) != vuln_report.get("includeNvdCvss"):
                changes += 1
            if include.get("epss_probability") is not None and include.get(
                "epss_probability"
            ) != vuln_report.get("includeEpssProbability"):
                changes += 1
            if include.get("advisory") is not None and include.get(
                "advisory"
            ) != vuln_report.get("includeAdvisory"):
                changes += 1
        if since == "ALL_TIME" and vuln_report.get("allVuln", False) is False:
            changes += 1
        if (
            since == "LAST_SENT"
            and vuln_report.get("sinceLastSentScheduledReport", False) is False
        ):
            changes += 1
        if (since == "DATE" or (since is None and date is not None)) and (
            not vuln_report.get("sinceStartDate")
            or (
                date is not None
                and start_date[0:10] != vuln_report.get("sinceStartDate")[0:10]
            )
        ):
            changes += 1
        if collection is not None and req_collection.get("id", "") != config.get(
            "resourceScope", {}
        ).get("collectionScope", {}).get("collectionId", ""):
            changes += 1
        if interval == "UNSET" and schedule:
            changes += 1
        if (interval == "WEEKLY" or (interval is None and week_days is not None)) and (
            not schedule.get("daysOfWeek") or (week_days is not None and wdays != curr_wdays)
        ):
            changes += 1
        if (interval == "MONTHLY" or (interval is None and month_days is not None)) and (
            not schedule.get("daysOfMonth")
            or (month_days is not None and mdays != curr_mdays)
        ):
            changes += 1
        if hour is not None and hour != schedule.get("hour"):
            changes += 1
        if minute is not None and minute != schedule.get("minute"):
            changes += 1
        if email_notifiers is not None and req_notifiers != curr_notifiers:
            changes += 1

        if changes == 0:
            module.exit_json(changed=False, id=config.get("id", ""))

        if changes < min_changes:
            min_changes = changes
            obj = config

    # Update the configuration
    id = obj.get("id", "")
    name = new_name if new_name else name
    new_fields = copy.deepcopy(obj)
    if new_name:
        new_fields["name"] = new_name
    if description is not None:
        new_fields["description"] = description
    if fixability:
        new_fields["vulnReportFilters"]["fixability"] = fixability
    if severities:
        new_fields["vulnReportFilters"]["severities"] = list(req_severities)
    if image_types:
        new_fields["vulnReportFilters"]["imageTypes"] = list(req_image_types)
    if include:
        if include.get("nvd_cvss") is not None:
            new_fields["vulnReportFilters"]["includeNvdCvss"] = include.get("nvd_cvss")
        if include.get("epss_probability") is not None:
            new_fields["vulnReportFilters"]["includeEpssProbability"] = include.get(
                "epss_probability"
            )
        if include.get("advisory") is not None:
            new_fields["vulnReportFilters"]["includeAdvisory"] = include.get("advisory")
    if since == "ALL_TIME":
        new_fields["vulnReportFilters"].pop("sinceLastSentScheduledReport", None)
        new_fields["vulnReportFilters"].pop("sinceStartDate", None)
        new_fields["vulnReportFilters"]["allVuln"] = True
    if since == "LAST_SENT":
        new_fields["vulnReportFilters"].pop("allVuln", None)
        new_fields["vulnReportFilters"].pop("sinceStartDate", None)
        new_fields["vulnReportFilters"]["sinceLastSentScheduledReport"] = True
    if since == "DATE" or (not since and date is not None):
        new_fields["vulnReportFilters"].pop("allVuln", None)
        new_fields["vulnReportFilters"].pop("sinceLastSentScheduledReport", None)
        if "sinceStartDate" not in new_fields["vulnReportFilters"] or date is not None:
            new_fields["vulnReportFilters"]["sinceStartDate"] = start_date
    if collection is not None:
        new_fields["resourceScope"] = {
            "collectionScope": {
                "collectionId": req_collection.get("id", ""),
                "collectionName": req_collection.get("name", ""),
            }
        }
    if interval == "UNSET":
        new_fields["schedule"] = None
    if interval == "WEEKLY" or (not interval and week_days is not None):
        if not new_fields["schedule"]:
            new_fields["schedule"] = {
                "intervalType": "WEEKLY",
                "hour": hour if hour is not None else 18,
                "minute": minute if minute is not None else 0,
                "daysOfWeek": {"days": list(wdays)},
            }
        else:
            new_fields["schedule"].pop("daysOfMonth", None)
            new_fields["schedule"]["intervalType"] = "WEEKLY"
            if "daysOfWeek" not in new_fields["schedule"] or week_days is not None:
                new_fields["schedule"]["daysOfWeek"] = {"days": list(wdays)}
    if interval == "MONTHLY" or (not interval and month_days is not None):
        if not new_fields["schedule"]:
            new_fields["schedule"] = {
                "intervalType": "MONTHLY",
                "hour": hour if hour is not None else 18,
                "minute": minute if minute is not None else 0,
                "daysOfMonth": {"days": list(mdays)},
            }
        else:
            new_fields["schedule"].pop("daysOfWeek", None)
            new_fields["schedule"]["intervalType"] = "MONTHLY"
            if "daysOfMonth" not in new_fields["schedule"] or month_days is not None:
                new_fields["schedule"]["daysOfMonth"] = {"days": list(mdays)}
    if hour is not None and new_fields["schedule"]:
        new_fields["schedule"]["hour"] = hour
    if minute is not None and new_fields["schedule"]:
        new_fields["schedule"]["minute"] = minute
    if email_notifiers is not None:
        new_fields["notifiers"] = notifiers

    module.unconditional_update(
        "vulnerability reporting schedule",
        new_fields["name"],
        "/v2/reports/configurations/{id}".format(id=id),
        new_fields,
    )
    module.exit_json(changed=True, id=id)


if __name__ == "__main__":
    main()
