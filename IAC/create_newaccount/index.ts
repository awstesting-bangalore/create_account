import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

import {
STSClient,
AssumeRoleCommand,
} from "@aws-sdk/client-sts";

import {
IAMClient,
GetRoleCommand,
UpdateAssumeRolePolicyCommand,
} from "@aws-sdk/client-iam";

import {
MEMBER_ACCOUNT_ROLE_NAME,
MANAGEMENT_ACCOUNT_ROLE_NAME,
buildAwsClients,
find_account_by_id,