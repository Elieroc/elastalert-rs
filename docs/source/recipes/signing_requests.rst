OpenSearch
**********

ElastAlert 3 supports Amazon OpenSearch. In general ElastAlert 3 will auto-detect
OpenSearch and make adjustments internally to handle the differences between 
OpenSearch and Elasticsearch.

.. admonition:: ElastAlert 3
   :class: ea3

   OpenSearch 2.x is supported (tested with 2.17): results are paged with scroll, and EQL / ES|QL filters are not
   available. Signing requests with AWS SigV4 (below) is **not supported**: ``aws_region`` and ``profile`` have no
   effect, so Amazon OpenSearch Service domains that require signed requests cannot be queried. Domains using basic
   authentication (fine-grained access control) work with ``es_username`` / ``es_password``.

.. _signingrequests:

Signing requests to Amazon OpenSearch Service
================================================

When using Amazon OpenSearch Service, you need to secure your service
from unauthorized access. Currently, there is no way to secure this using
network firewall rules, so the only way is via signing the requests using the
access key and secret key for a role or user with permissions on the
OpenSearch service.

You can sign requests to AWS using any of the standard AWS methods of providing
credentials.
- Environment Variables, ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY``
- AWS Config or Credential Files, ``~/.aws/config`` and ``~/.aws/credentials``
- AWS Instance Profiles, uses the EC2 Metadata service

Using an Instance Profile
-------------------------

Typically, you'll deploy ElastAlert 3 on a running EC2 instance on AWS. You can
assign a role  to this instance that gives it permissions to read from and write
to the Elasticsearch service. When using an Instance Profile, you will need to
specify the ``aws_region`` in the configuration file or set the
``AWS_DEFAULT_REGION`` environment variable.

Using AWS profiles
------------------

You can also create a user with permissions on the OpenSearch service and
tell ElastAlert 3 to authenticate itself using that user. First, create an AWS
profile in the machine where you'd like to run ElastAlert 3 for the user with
permissions.

You can use the environment variables ``AWS_DEFAULT_PROFILE`` and
``AWS_DEFAULT_REGION`` or add two options to the configuration file:
- ``aws_region``: The AWS region where you want to operate.
- ``profile``: The name of the AWS profile to use to sign the requests.
