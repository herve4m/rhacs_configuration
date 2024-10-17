#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_exception
short_description: Configure vulnerability exception expiration periods
description:
  - Configure the time periods available for vulnerability management
    exceptions.
  - These options are available when users request to defer a CVE.
version_added: '1.0.0'
author: Hervé Quatremain (@herve4m)
options:
  exception_times:
    description: List the time periods available to users when they defer CVEs.
    type: list
    elements: dict
    suboptions:
      expiration:
        description: Number of days.
        type: int
        required: true
      enabled:
        description:
          - Whether users can select this time period when they defer a CVE.
        type: bool
        required: true
  append:
    description:
      - If V(true), then the module adds the time periods listed in the
        O(exception_times) section to the configuration.
      - If V(false), then the module sets the time periods listed in the
        O(exception_times) section, removing all other time periods from the
        configuration.
    type: bool
    default: true
  fixable_cve:
    description: Expire the time periods when the deferred CVEs are fixable.
    type: dict
    suboptions:
      all:
        description:
          - Whether expire the time periods when all the CVEs are fixable.
        type: bool
      any:
        description:
          - Whether expire the time periods when any CVE is fixable.
        type: bool
  indefinite:
    description: Whether to allow users to defer CVEs indefinitely.
    type: bool
  custom_date:
    description:
      - Whether to allow users to specify an expiration date for deferred CVEs.
    type: bool
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
- name: Ensure the users can defer CVEs no more than 60 days
  herve4m.rhacs_configuration.rhacs_exception:
    exception_times:
      - expiration: 15
        enabled: true
      - expiration: 30
        enabled: true
      - expiration: 60
        enabled: true
      - expiration: 90
        enabled: false
    append: false
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the users can specify an expiration date when they defer CVEs
  herve4m.rhacs_configuration.rhacs_exception:
    custom_date: true
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r""" # """

import copy

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        exception_times=dict(
            type="list",
            elements="dict",
            options=dict(
                expiration=dict(type="int", required=True),
                enabled=dict(type="bool", required=True),
            ),
        ),
        append=dict(type="bool", default=True),
        fixable_cve=dict(
            type="dict",
            options=dict(all=dict(type="bool"), any=dict(type="bool")),
        ),
        indefinite=dict(type="bool"),
        custom_date=dict(type="bool"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    exception_times = module.params.get("exception_times")
    append = module.params.get("append")
    fixable_cve = module.params.get("fixable_cve")
    indefinite = module.params.get("indefinite")
    custom_date = module.params.get("custom_date")

    # Retrieve the existing configuration
    #
    # GET /v1/config/private/exception/vulnerabilities
    # {
    #   "config": {
    #     "expiryOptions": {
    #       "dayOptions": [
    #         {
    #           "numDays": 14,
    #           "enabled": true
    #         },
    #         {
    #           "numDays": 30,
    #           "enabled": true
    #         },
    #         {
    #           "numDays": 60,
    #           "enabled": true
    #         },
    #         {
    #           "numDays": 90,
    #           "enabled": true
    #         }
    #       ],
    #       "fixableCveOptions": {
    #         "allFixable": true,
    #         "anyFixable": true
    #       },
    #       "customDate": false,
    #       "indefinite": false
    #     }
    #   }
    # }

    c = module.get_object_path("/v1/config/private/exception/vulnerabilities")

    new_fields = copy.deepcopy(c)
    config = c.get("config", {}).get("expiryOptions", {})
    data = new_fields.get("config", {}).get("expiryOptions", {})
    changed = False

    if exception_times is not None:
        curr_set = {}
        for d in config.get("dayOptions"):
            curr_set[d["numDays"]] = d.get("enabled")
        req_set = {}
        for d in exception_times:
            req_set[d["expiration"]] = d.get("enabled")

        if curr_set != req_set:
            if append is False:
                changed = True
                data["dayOptions"] = [
                    {"numDays": day, "enabled": enabled}
                    for day, enabled in sorted(req_set.items())
                ]
            else:
                new_set = curr_set.copy()
                new_set.update(req_set)
                if new_set != curr_set:
                    changed = True
                    data["dayOptions"] = [
                        {"numDays": day, "enabled": enabled}
                        for day, enabled in sorted(new_set.items())
                    ]

    if fixable_cve is not None:
        all = fixable_cve.get("all")
        any = fixable_cve.get("any")

        conf = config.get("fixableCveOptions", {})

        if all is not None and all != conf.get("allFixable"):
            changed = True
            data["fixableCveOptions"]["allFixable"] = all
        if any is not None and any != conf.get("anyFixable"):
            changed = True
            data["fixableCveOptions"]["anyFixable"] = any

    if indefinite is not None and indefinite != config.get("indefinite"):
        changed = True
        data["indefinite"] = indefinite

    if custom_date is not None and custom_date != config.get("customDate"):
        changed = True
        data["customDate"] = custom_date

    if changed is False:
        module.exit_json(changed=False)

    module.unconditional_update(
        "exception configuration",
        "RHACS",
        "/v1/config/private/exception/vulnerabilities",
        new_fields,
    )
    module.exit_json(changed=True)


if __name__ == "__main__":
    main()
