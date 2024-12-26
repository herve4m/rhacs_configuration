# Red Hat Advanced Cluster Security for Kubernetes (RHACS) Collection for Ansible

[![Sanity Test](https://github.com/herve4m/rhacs_configuration/actions/workflows/pre-commit-sanity.yml/badge.svg)](https://github.com/herve4m/rhacs_configuration/actions/workflows/pre-commit-sanity.yml)
[![Integration Test](https://github.com/herve4m/rhacs_configuration/actions/workflows/ansible-integration.yml/badge.svg)](https://github.com/herve4m/rhacs_configuration/actions/workflows/ansible-integration.yml)


The collection provides modules for configuring your Red Hat Advanced Cluster Security for Kubernetes (RHACS) and StackRox deployments.


## Included Content

After you install the collection, use the `ansible-doc` command to access the collection documentation.

### Modules

Run the `ansible-doc -l herve4m.rhacs_configuration` command to list the modules that the collection provides.
For accessing the documentation of a module, use the `ansible-doc herve4m.rhacs_configuration.<module-name>` command.

You can also access the documentation from [Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/herve4m/rhacs_configuration/docs/).

Name | Description
---: | :---
`rhacs_access_scope`              | Manage access scopes
`rhacs_api_token`                 | Create API tokens for accessing the RHACS API
`rhacs_auth_provider`             | Manage authentication providers
`rhacs_cloud_management_platform` | Manage RHACS integration with cloud platforms
`rhacs_collection`                | Manage deployment collections
`rhacs_compliance_schedule`       | Manage compliance schedule configurations
`rhacs_config`                    | Manage RHACS configuration
`rhacs_delegated_image_scan`      | Manage delegated image scanning configuration
`rhacs_exception`                 | Configure vulnerability exception expiration periods
`rhacs_external_backup`           | Manage external backup configurations
`rhacs_group`                     | Manage roles for authentication providers
`rhacs_image_integration`         | Manage image vulnerability scanner and registry integration
`rhacs_image_watch`               | Manage image watches
`rhacs_init_bundle`               | Manage cluster init bundles
`rhacs_machine_access`            | Manage machine access configurations
`rhacs_notifier_integration`      | Manage notification methods
`rhacs_permission_set`            | Manage permission sets
`rhacs_policy`                    | Manage security policies
`rhacs_policy_category`           | Manage policy categories
`rhacs_policy_clone`              | Clone security policies
`rhacs_policy_export`             | Export security policies
`rhacs_policy_import`             | Import security policies
`rhacs_policy_notifier`           | Associate notifiers to policies
`rhacs_policy_status`             | Enable or disable policies
`rhacs_report_schedule`           | Manage vulnerability reporting schedules
`rhacs_role`                      | Manage roles
`rhacs_signature`                 | Manage RHACS integration with Cosign signatures


## Installing the Collection

Before using the RHACS collection, install it by using the Ansible Galaxy command-line tool:

```bash
ansible-galaxy collection install herve4m.rhacs_configuration
```

As an alternative, you can declare the collection in a `collections/requirements.yml` file inside your Ansible project:

```yaml
---
collections:
  - name: herve4m.rhacs_configuration
```

Use the `ansible-galaxy collection install -r collections/requirements.yml` command to install the collection from this file.
If you manage your Ansible project in automation controller, then automation controller detects this `collections/requirements.yml` file, and automatically installs the collection.

You can also download the tar archive from [Ansible Galaxy](https://galaxy.ansible.com/herve4m/rhacs_configuration), and then manually install the collection.

See [Ansible -- Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.


## Using the Collection

The modules in the collection access RHACS through its REST API.
The modules can connect to the API by using a username and a password, or by using an API token.

There are two ways to get an API token:

* Use the RHACS portal.
* Use the `herve4m.rhacs_configuration.rhacs_api_token` Ansible module to create an API token by using a username and a password.
  The module creates and then returns the API token.

### Creating an API Token by Using the Portal

To create an API token, follow these steps:

1. Log in to the RHACS portal.
2. Go to `Platform Configuration > Integrations`.
3. Under the `Authentication Tokens` category, click `API Token`.
4. Click `Generate Token`.
5. Enter a name for the token and select a role.
   The `Admin` role grants sufficient permissions for all modules in the collections to perform their work.
6. Click `Generate`.
7. Copy the API token that the portal displays, and use it with the modules' `rhacs_token` parameter.
   You cannot view the API token again after you quit the web page.

### Getting an API Token by Using the rhacs_api_token Module

Instead of using the RHACS portal, you can use the `herve4m.rhacs_configuration.rhacs_api_token` Ansible module to create an API token.
The module requires a username and a password (or an existing API token) for accessing the RHACS API and for generating the API token.
The module returns the API token, which you can use with the other modules.

The following playbook example uses the `herve4m.rhacs_configuration.rhacs_api_token` module to create an API token:

```yaml
---
- name: Generate an API token, and then use it to create a policy category
  hosts: localhost

  tasks:
    # Create the API token by authenticating to the RHACS API with a username
    # and a password. This user must have sufficient permissions to create
    # API tokens.
    - name: Ensure the API token exists
      herve4m.rhacs_configuration.rhacs_api_token:
        name: API token for Ansible automation
        role: Admin
        state: present
        rhacs_host: https://central.example.com:8443
        rhacs_username: admin
        rhacs_password: S6tGwo13
      register: token_details

    - name: Display the generated API token
      ansible.builtin.debug:
        msg: "API token: {{ token_details['token'] }}"

    # Use the API token to continue configuring RHACS
    - name: Ensure the policy category exists
      herve4m.rhacs_configuration.rhacs_policy_category:
        name: OS Tools
        state: present
        rhacs_host: https://central.example.com:8443
        rhacs_token: "{{ token_details['token'] }}"
```

### Grouping Common Module Parameters

When your play calls multiple modules from the collection, you can group common module parameters in the `module_defaults` section, under the `group/herve4m.rhacs_configuration.rhacs` subsection.
For example, instead of repeating the `rhacs_host`, `rhacs_username`, and `rhacs_password` parameters in each task, you can declare these parameters at the top of your play:

```yaml
---
- name: Configure a notification method and an external backup configuration
  hosts: localhost

  module_defaults:
    group/herve4m.rhacs_configuration.rhacs:
      rhacs_host: https://central.example.com:8443
      rhacs_username: admin
      rhacs_password: S6tGwo13

  tasks:
    - name: Ensure the Slack notification method exists
      herve4m.rhacs_configuration.rhacs_notifier_integration:
        name: Slack notifications
        type: slack
        slack:
          webhook: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
          annotation_key: slack_webhook
        state: present

    - name: Ensure Amazon S3 bucket configuration for external backups exists
      herve4m.rhacs_configuration.rhacs_external_backup:
        name: weekly_S3_backups
        type: s3
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
```


## Contributing to the Collection

We welcome community contributions to this collection.
If you find problems, then please open an [issue](https://github.com/herve4m/rhacs_configuration/issues) or create a [pull request](https://github.com/herve4m/rhacs_configuration/pulls).

More information about contributing can be found in the [Contribution Guidelines](https://github.com/herve4m/rhacs_configuration/blob/main/CONTRIBUTING.md).


## Release Notes

See the [changelog](https://github.com/herve4m/rhacs_configuration/blob/main/CHANGELOG.rst).


## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to read the full text.
