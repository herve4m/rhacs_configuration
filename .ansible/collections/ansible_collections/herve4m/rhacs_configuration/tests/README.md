# Tests for the Red Hat Advanced Cluster Security for Kubernetes Collection

GitHub Actions trigger the tests in this directory.
The GitHub Actions workflow YAML files are defined in the [GitHub Actions workflow directory](https://github.com/herve4m/rhacs_configuration/tree/main/.github/workflows).

The workflow uses the `docker-compose.yml` file to deploy a testing RHACS environment, and then runs the `ansible-test integration` command to perform the integration tests.
Those tests consist of running the roles (playbooks) defined under the `integration/targets` directory.

## Running a Test Manually

If you want to run one of these playbooks manually against your RHACS installation, then prepare your environment as follows:

* Make a copy of the `sample_manual_test.yml` playbook model and then update your copy.
  Change the role to run and provide the connection parameters to your RHACS installation.
* Install the RHACS collection in your environment by using the `ansible-galaxy collection install` command.
* Run your copy of the playbook with the `ansible-playbook` command.
