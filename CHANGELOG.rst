=========================================================================
Red Hat Advanced Cluster Security for Kubernetes Collection Release Notes
=========================================================================

.. contents:: Topics

v1.3.0
======

New Modules
-----------

- herve4m.rhacs_configuration.rhacs_image_watch - Manage image watches.
- herve4m.rhacs_configuration.rhacs_policy - Manage security policies.

v1.2.1
======

Release Summary
---------------

Supporting new StackRox 4.6 features.

Minor Changes
-------------

- Update the ``herve4m.rhacs_configuration.rhacs_external_backup`` module to support S3 compatible storage.
- Update the ``herve4m.rhacs_configuration.rhacs_notifier_integration`` module to support Microsoft Sentinel as a notification method.

v1.1.1
======

Release Summary
---------------

Fixing bugs in the ``herve4m.rhacs_configuration.rhacs_auth_provider`` module.

Bugfixes
--------

- The ``uiEndpoint`` OpenID Connect parameter was wrongly set and prevented authentication.
- Updating a configuration failed because once the authentication provider is used, it cannot be modified. Now, for update operations, the configuration is deleted and then re-created.

v1.1.0
======

New Modules
-----------

- herve4m.rhacs_configuration.rhacs_compliance_schedule - Manage compliance schedule configurations.
- herve4m.rhacs_configuration.rhacs_report_schedule - Manage vulnerability reporting schedules.

v1.0.0
======

Release Summary
---------------

Initial public release of the ``herve4m.rhacs_configuration`` collection.
The changelog describes all changes made to the modules and plugins included in this collection.

New Modules
-----------

- herve4m.rhacs_configuration.rhacs_access_scope - Manage access scopes.
- herve4m.rhacs_configuration.rhacs_api_token - Create API tokens for accessing the RHACS API.
- herve4m.rhacs_configuration.rhacs_auth_provider - Manage authentication providers.
- herve4m.rhacs_configuration.rhacs_cloud_management_platform - Manage RHACS integration with cloud platforms.
- herve4m.rhacs_configuration.rhacs_collection - Manage deployment collections.
- herve4m.rhacs_configuration.rhacs_config - Manage RHACS configuration.
- herve4m.rhacs_configuration.rhacs_delegated_image_scan - Manage delegated image scanning configuration.
- herve4m.rhacs_configuration.rhacs_exception - Configure vulnerability exception expiration periods.
- herve4m.rhacs_configuration.rhacs_external_backup - Manage external backup configurations.
- herve4m.rhacs_configuration.rhacs_group - Manage roles for authentication providers.
- herve4m.rhacs_configuration.rhacs_image_integration - Manage image vulnerability scanner and registry integrations.
- herve4m.rhacs_configuration.rhacs_init_bundle - Manage cluster init bundles.
- herve4m.rhacs_configuration.rhacs_machine_access - Manage machine access configurations.
- herve4m.rhacs_configuration.rhacs_notifier_integration - Manage notification methods.
- herve4m.rhacs_configuration.rhacs_permission_set - Manage permission sets.
- herve4m.rhacs_configuration.rhacs_policy_category - Manage policy categories.
- herve4m.rhacs_configuration.rhacs_policy_clone - Clone security policies.
- herve4m.rhacs_configuration.rhacs_policy_export - Export security policies.
- herve4m.rhacs_configuration.rhacs_policy_import - Import security policies.
- herve4m.rhacs_configuration.rhacs_policy_notifier - Associate notifiers to policies.
- herve4m.rhacs_configuration.rhacs_policy_status - Enable or disable policies.
- herve4m.rhacs_configuration.rhacs_role - Manage roles.
- herve4m.rhacs_configuration.rhacs_signature - Manage RHACS integrations with Cosign signatures.
