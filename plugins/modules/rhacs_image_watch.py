#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024 Hervé Quatremain <herve.quatremain@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: rhacs_image_watch
short_description: Manage image watches
description: Add and remove image watches.
version_added: '1.3.0'
author: Hervé Quatremain (@herve4m)
options:
  image:
    description:
      - Image name to watch, such as
        C(registry.example.com/namespace/image-name:tag).
    required: true
    type: str
  state:
    description:
      - If V(absent), then the module removes the watch for the given image.
      - The module does not fail if the image watch does not exist, because
        the state is already as expected.
      - If V(present), then the module creates the image watch if it does
        not already exist.
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
- name: Ensure a watch exists for the MariaDB image
  herve4m.rhacs_configuration.rhacs_image_watch:
    image: quay.io/fedora/mariadb-105:fedora
    state: present
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP

- name: Ensure the watch is removed for the MariaDB image
  herve4m.rhacs_configuration.rhacs_image_watch:
    image: quay.io/fedora/mariadb-105:fedora
    state: absent
    rhacs_host: central.example.com
    rhacs_username: admin
    rhacs_password: vs9mrD55NP
"""

RETURN = r""" # """

from ..module_utils.api_module import APIModule


def main():

    argument_spec = dict(
        image=dict(required=True),
        state=dict(choices=["present", "absent"], default="present"),
    )

    # Create a module for ourselves
    module = APIModule(argument_spec=argument_spec, supports_check_mode=True)

    # Extract our parameters
    image = module.params.get("image")
    state = module.params.get("state")

    imgs = module.get_object_path("/v1/watchedimages")
    for img in imgs.get("watchedImages", []):
        if img.get("name") == image:
            break
    else:
        img = None

    # Remove the image watch
    if state == "absent":
        module.delete(img, "image watch", image, "/v1/watchedimages", {"name": image})

    if img:
        module.exit_json(changed=False)

    # Add the image watch
    module.create("image watch", image, "/v1/watchedimages", {"name": image})


if __name__ == "__main__":
    main()
