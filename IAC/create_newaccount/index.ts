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
sleep,
buildCreateAccountBody,
parseBool,
sanitize_alias,
_starts_with_forbidden_prefix,
_is_valid_account_name_format,
_is_valid_email,
_normalize_simple_token,
getOrgSts,
getOrgAccountId,
getPulumiIacRoleArn,
type AccountPlanOutput,
} from "./common_helpers";

import {
detectDuplicates,
} from "./duplicate_detection";

/*



Create New AWS Account





Stage 1:





Validate inputs



Build AWS clients



Run duplicate detection once



Abort if duplicate exists



Create AWS Organizations account



Wait for account to become ACTIVE



Update OrganizationAccountAccessRole trust





Stage 2+:



managedAccountId is supplied by Workato.





Verify that account exists



Verify name/email



Verify ACTIVE



Declare the same Pulumi Account resource



Do not run duplicate detection



Do not repeat the one-time trust bootstrap



No DRY_RUN application mode exists.



Pulumi preview is still protected with

pulumi.runtime.isDryRun() before making the IAM trust mutation.



*/

export interface CreateNewAccountArgs {
accountName: string;
accountDL: string;
accountAlias?: string;
checkAliases?: boolean;

/*
 * Undefined during Stage 1.
 *
 * Populated after account creation and passed into
 * Stage 2+ by Workato.
 */
managedAccountId?: string;

}

export type ProgramResult = {
accountPlan: AccountPlanOutput;
account?: aws.organizations.Account;
confirmedActionsTaken?: pulumi.Output<string[]>;
};

export class CreateNewAccount
extends pulumi.ComponentResource {

public readonly checkAliases!: pulumi.Output<string>;
public readonly accountName!: pulumi.Output<string>;
public readonly accountDl!: pulumi.Output<string>;
public readonly accountAlias!: pulumi.Output<string>;
public readonly decision!: pulumi.Output<string>;
public readonly actionsTaken!: pulumi.Output<string[]>;
public readonly accountId!: pulumi.Output<string>;
public readonly reason!: pulumi.Output<string>;
public readonly duplicate!: pulumi.Output<string>;


constructor(
    name: string,
    args: CreateNewAccountArgs,
    opts?: pulumi.ComponentResourceOptions,
) {
    super(
        "aenetworks:aws:CreateNewAccount",
        name,
        {},
        opts,
    );


    const accountInput = {
        account_name:
            args.accountName,

        account_dl:
            args.accountDL,

        account_alias:
            args.accountAlias ??
            args.accountName,

        check_aliases:
            args.checkAliases ??
            true,

        managed_account_id:
            args.managedAccountId,
    };


    const programOut =
        pulumi.output(
            this.runProgram(
                accountInput,
            ),
        );


    const accountPlan =
        programOut.apply(
            (r) =>
                r.accountPlan,
        );


    this.checkAliases =
        accountPlan.apply(
            (p) =>
                p.check_aliases,
        );


    this.accountName =
        accountPlan.apply(
            (p) =>
                p.account_name ??
                "",
        );


    this.accountDl =
        accountPlan.apply(
            (p) =>
                p.account_dl ??
                "",
        );


    this.accountAlias =
        accountPlan.apply(
            (p) =>
                p.account_alias ??
                "",
        );


    this.decision =
        accountPlan.apply(
            (p) =>
                p.decision ??
                "",
        );


    this.actionsTaken =
        programOut.apply(
            (r) =>
                r.confirmedActionsTaken ??
                r.accountPlan
                    .actions_taken,
        );


    this.accountId =
        programOut.apply(
            (r) => {
                if (r.account) {
                    return r.account.id;
                }

                return (
                    r.accountPlan
                        .account_id ??
                    ""
                );
            },
        );


    this.reason =
        accountPlan.apply(
            (p) =>
                p.decision ===
                "abort"
                    ? p.reason ??
                      ""
                    : "",
        );


    this.duplicate =
        accountPlan.apply(
            (p) =>
                p.decision ===
                "abort"
                    ? p.duplicate
                    : "",
        );


    this.registerOutputs({
        checkAliases:
            this.checkAliases,

        accountName:
            this.accountName,

        accountDl:
            this.accountDl,

        accountAlias:
            this.accountAlias,

        decision:
            this.decision,

        actionsTaken:
            this.actionsTaken,

        accountId:
            this.accountId,

        reason:
            this.reason,

        duplicate:
            this.duplicate,
    });
}


/*
 * -------------------------------------------------------------------------
 * Retry helper
 * -------------------------------------------------------------------------
 */

private async retryWithBackoff<T>(
    fn: () => Promise<T>,
    opts: {
        attempts?: number;
        baseDelayMs?: number;
        label?: string;
    } = {},
): Promise<T> {

    const attempts =
        opts.attempts ??
        5;

    const baseDelayMs =
        opts.baseDelayMs ??
        2000;

    const label =
        opts.label ??
        "operation";


    let lastError: unknown;


    for (
        let attempt = 1;
        attempt <= attempts;
        attempt++
    ) {
        try {
            return await fn();
        } catch (err) {

            lastError =
                err;

            const name =
                (err as any)?.name ??
                "";

            const message =
                String(
                    (err as any)?.message ??
                    err ??
                    "",
                );


            const retryable =
                name ===
                    "AccessDenied" ||
                name ===
                    "AccessDeniedException" ||
                name ===
                    "NoSuchEntity" ||
                name ===
                    "NoSuchEntityException" ||
                /not authorized to perform/i.test(
                    message,
                ) ||
                /cannot be assumed/i.test(
                    message,
                ) ||
                /does not exist/i.test(
                    message,
                );


            console.log(
                `[retry] ${label} attempt ${attempt}/${attempts} failed: ${message} (retryable=${retryable})`,
            );


            if (
                !retryable ||
                attempt ===
                    attempts
            ) {
                throw err;
            }


            await sleep(
                baseDelayMs *
                    Math.pow(
                        2,
                        attempt - 1,
                    ),
            );
        }
    }


    throw lastError;
}


/*
 * -------------------------------------------------------------------------
 * Decode IAM trust policy
 * -------------------------------------------------------------------------
 */

private decodeTrustPolicy(
    policyDocument:
        | string
        | undefined
        | null,
): {
    Version: string;
    Statement: any[];
} {

    if (!policyDocument) {
        return {
            Version:
                "2012-10-17",
            Statement: [],
        };
    }


    const decoded =
        (() => {
            try {
                return decodeURIComponent(
                    policyDocument.replace(
                        /\+/g,
                        "%20",
                    ),
                );
            } catch {
                return policyDocument;
            }
        })();


    const parsed =
        JSON.parse(
            decoded,
        );


    return {
        Version:
            parsed.Version ??
            "2012-10-17",

        Statement:
            Array.isArray(
                parsed.Statement,
            )
                ? parsed.Statement
                : [],
    };
}


/*
 * -------------------------------------------------------------------------
 * Check whether trust policy already contains AE-AWS-IAC
 * -------------------------------------------------------------------------
 */

private trustContainsPrincipal(
    policy: {
        Version: string;
        Statement: any[];
    },
    arn: string,
): boolean {

    return policy.Statement.some(
        (statement) => {

            const action =
                statement.Action;

            const actionMatches =
                action ===
                    "sts:AssumeRole" ||
                (
                    Array.isArray(
                        action,
                    ) &&
                    action.includes(
                        "sts:AssumeRole",
                    )
                );


            if (!actionMatches) {
                return false;
            }


            const principal =
                statement.Principal;


            if (
                typeof principal ===
                "string"
            ) {
                return (
                    principal ===
                    arn
                );
            }


            if (
                Array.isArray(
                    principal,
                )
            ) {
                return principal.includes(
                    arn,
                );
            }


            if (
                principal &&
                typeof principal ===
                    "object"
            ) {

                const awsPrincipal =
                    principal.AWS;


                if (
                    typeof awsPrincipal ===
                    "string"
                ) {
                    return (
                        awsPrincipal ===
                        arn
                    );
                }


                if (
                    Array.isArray(
                        awsPrincipal,
                    )
                ) {
                    return awsPrincipal.includes(
                        arn,
                    );
                }
            }


            return false;
        },
    );
}


/*
 * -------------------------------------------------------------------------
 * Add AE-AWS-IAC to trust policy
 * -------------------------------------------------------------------------
 */

private addPulumiTrust(
    policy: {
        Version: string;
        Statement: any[];
    },
    arn: string,
) {

    if (
        this.trustContainsPrincipal(
            policy,
            arn,
        )
    ) {
        return policy;
    }


    const updated =
        {
            Version:
                policy.Version ??
                "2012-10-17",

            Statement: [
                ...policy.Statement,
            ],
        };


    updated.Statement.push({
        Sid:
            `AllowPulumiIac`,

        Effect:
            "Allow",

        Principal: {
            AWS: arn,
        },

        Action:
            "sts:AssumeRole",
    });


    return updated;
}


/*
 * -------------------------------------------------------------------------
 * Update new-account trust relationship
 * -------------------------------------------------------------------------
 */

private async updateNewAccountTrust(
    accountId: string,
): Promise<string> {

    const orgSts =
        getOrgSts();

    const orgAccountId =
        getOrgAccountId();

    const pulumiIacRoleArn =
        getPulumiIacRoleArn();


    /*
     * Management account bootstrap role
     */
    const bootstrapResponse =
        await orgSts.send(
            new AssumeRoleCommand({
                RoleArn:
                    `arn:aws:iam::${orgAccountId}:role/${MANAGEMENT_ACCOUNT_ROLE_NAME}`,

                RoleSessionName:
                    "bootstrap-new-account",
            }),
        );


    if (
        !bootstrapResponse.Credentials
    ) {
        throw new Error(
            "Failed to assume management account bootstrap role",
        );
    }


    const bootstrapCredentials =
        {
            accessKeyId:
                bootstrapResponse
                    .Credentials
                    .AccessKeyId!,

            secretAccessKey:
                bootstrapResponse
                    .Credentials
                    .SecretAccessKey!,

            sessionToken:
                bootstrapResponse
                    .Credentials
                    .SessionToken!,
        };


    const bootstrapSts =
        new STSClient({
            region:
                process.env.AWS_REGION ??
                process.env.AWS_DEFAULT_REGION ??
                "us-east-1",

            credentials:
                bootstrapCredentials,
        });


    /*
     * Newly-created account role may take
     * some time to become assumable.
     */
    const memberResponse =
        await this.retryWithBackoff(
            () =>
                bootstrapSts.send(
                    new AssumeRoleCommand({
                        RoleArn:
                            `arn:aws:iam::${accountId}:role/${MEMBER_ACCOUNT_ROLE_NAME}`,

                        RoleSessionName:
                            "new-account-trust-update",
                    }),
                ),
            {
                label:
                    `assume ${MEMBER_ACCOUNT_ROLE_NAME} in account ${accountId}`,
            },
        );


    if (
        !memberResponse.Credentials
    ) {
        throw new Error(
            `Failed to assume ${MEMBER_ACCOUNT_ROLE_NAME} in account ${accountId}`,
        );
    }


    const memberCredentials =
        {
            accessKeyId:
                memberResponse
                    .Credentials
                    .AccessKeyId!,

            secretAccessKey:
                memberResponse
                    .Credentials
                    .SecretAccessKey!,

            sessionToken:
                memberResponse
                    .Credentials
                    .SessionToken!,
        };


    const memberIam =
        new IAMClient({
            region:
                process.env.AWS_REGION ??
                process.env.AWS_DEFAULT_REGION ??
                "us-east-1",

            credentials:
                memberCredentials,
        });


    const roleResponse =
        await memberIam.send(
            new GetRoleCommand({
                RoleName:
                    MEMBER_ACCOUNT_ROLE_NAME,
            }),
        );


    const currentPolicy =
        this.decodeTrustPolicy(
            roleResponse.Role
                ?.AssumeRolePolicyDocument ??
                null,
        );


    const updatedPolicy =
        this.addPulumiTrust(
            currentPolicy,
            pulumiIacRoleArn,
        );


    const changed =
        JSON.stringify(
            currentPolicy.Statement,
        ) !==
        JSON.stringify(
            updatedPolicy.Statement,
        );


    if (!changed) {
        return `no-change:${accountId}`;
    }


    await memberIam.send(
        new UpdateAssumeRolePolicyCommand(
            {
                RoleName:
                    MEMBER_ACCOUNT_ROLE_NAME,

                PolicyDocument:
                    JSON.stringify(
                        updatedPolicy,
                    ),
            },
        ),
    );


    return `updated-trust:${accountId}`;
}


/*
 * -------------------------------------------------------------------------
 * Main program
 * -------------------------------------------------------------------------
 */

private async runProgram(
    input: {
        account_name: string;
        account_dl: string;
        account_alias?: string;
        check_aliases?: boolean;
        managed_account_id?: string;
    },
): Promise<ProgramResult> {

    const accountName =
        input.account_name;

    const accountDL =
        input.account_dl;

    const accountAlias =
        input.account_alias ??
        accountName;

    const checkAliases =
        parseBool(
            input.check_aliases,
            true,
        );

    const managedAccountId =
        input.managed_account_id
            ?.trim() ||
        undefined;


    /*
     * =====================================================================
     * 1. VALIDATION
     * =====================================================================
     */

    if (
        !accountName ||
        !accountDL
    ) {
        return {
            accountPlan:
                buildCreateAccountBody({
                    account_name:
                        accountName,

                    account_dl:
                        accountDL,

                    account_alias:
                        accountAlias,

                    decision:
                        "abort",

                    duplicate:
                        "false",

                    reason:
                        "validation_error",

                    error: {
                        code:
                            "ValidationError",

                        message:
                            "account_name and account_dl are required",
                    },

                    plan: {
                        mode:
                            "create",
                    },
                }),
        };
    }


    if (
        _starts_with_forbidden_prefix(
            accountName,
        )
    ) {
        return {
            accountPlan:
                buildCreateAccountBody({
                    account_name:
                        accountName,

                    account_dl:
                        accountDL,

                    account_alias:
                        accountAlias,

                    decision:
                        "abort",

                    duplicate:
                        "false",

                    reason:
                        "validation_error",

                    error: {
                        code:
                            "ValidationError",

                        message:
                            "account_name cannot start with 'aenetworks-'",
                    },

                    plan: {
                        mode:
                            "create",
                    },
                }),
        };
    }


    if (
        _starts_with_forbidden_prefix(
            accountAlias,
        )
    ) {
        return {
            accountPlan:
                buildCreateAccountBody({
                    account_name:
                        accountName,

                    account_dl:
                        accountDL,

                    account_alias:
                        accountAlias,

                    decision:
                        "abort",

                    duplicate:
                        "false",

                    reason:
                        "validation_error",

                    error: {
                        code:
                            "ValidationError",

                        message:
                            "account_alias cannot start with 'aenetworks-'",
                    },

                    plan: {
                        mode:
                            "create",
                    },
                }),
        };
    }


    if (
        !_is_valid_account_name_format(
            accountName,
        )
    ) {
        return {
            accountPlan:
                buildCreateAccountBody({
                    account_name:
                        accountName,

                    account_dl:
                        accountDL,

                    account_alias:
                        accountAlias,

                    decision:
                        "abort",

                    duplicate:
                        "false",

                    reason:
                        "validation_error",

                    error: {
                        code:
                            "ValidationError",

                        message:
                            "account_name invalid (normalize failure)",
                    },

                    plan: {
                        mode:
                            "create",
                    },
                }),
        };
    }


    if (
        !_is_valid_email(
            accountDL,
        )
    ) {
        return {
            accountPlan:
                buildCreateAccountBody({
                    account_name:
                        accountName,

                    account_dl:
                        accountDL,

                    account_alias:
                        accountAlias,

                    decision:
                        "abort",

                    duplicate:
                        "false",

                    reason:
                        "validation_error",

                    error: {
                        code:
                            "ValidationError",

                        message:
                            "account_dl appears invalid",
                    },

                    plan: {
                        mode:
                            "create",
                    },
                }),
        };
    }


    if (
        managedAccountId &&
        !/^\d{12}$/.test(
            managedAccountId,
        )
    ) {
        return {
            accountPlan:
                buildCreateAccountBody({
                    account_name:
                        accountName,

                    account_dl:
                        accountDL,

                    account_alias:
                        accountAlias,

                    decision:
                        "abort",

                    duplicate:
                        "false",

                    reason:
                        "invalid_managed_account_id",

                    account_id:
                        managedAccountId,

                    error: {
                        code:
                            "ValidationError",

                        message:
                            `managedAccountId '${managedAccountId}' is not a valid 12-digit AWS account ID`,
                    },

                    plan: {
                        mode:
                            "managed",
                    },
                }),
        };
    }


    /*
     * =====================================================================
     * 2. AWS CLIENTS
     * =====================================================================
     */

    await buildAwsClients();


    const plannedAlias =
        sanitize_alias(
            accountAlias,
        );


    /*
     * =====================================================================
     * 3. MANAGED ACCOUNT
     *
     * Stage 2+
     * =====================================================================
     */

    if (managedAccountId) {

        const managedAccount =
            await find_account_by_id(
                managedAccountId,
            );


        if (!managedAccount) {
            throw new pulumi.RunError(
                `Managed AWS account '${managedAccountId}' was not found in AWS Organizations`,
            );
        }


        const expectedName =
            _normalize_simple_token(
                accountName,
            );

        const actualName =
            _normalize_simple_token(
                managedAccount.Name,
            );


        const expectedEmail =
            accountDL
                .trim()
                .toLowerCase();

        const actualEmail =
            (
                managedAccount.Email ??
                ""
            )
                .trim()
                .toLowerCase();


        if (
            expectedName !==
                actualName ||
            expectedEmail !==
                actualEmail
        ) {
            throw new pulumi.RunError(
                `Managed account verification failed for '${managedAccountId}'. ` +
                `Expected '${accountName}'/'${accountDL}', ` +
                `but AWS returned '${managedAccount.Name ?? ""}'/'${managedAccount.Email ?? ""}'.`,
            );
        }


        const accountState =
            (
                managedAccount.State ??
                managedAccount.Status ??
                ""
            )
                .trim()
                .toUpperCase();


        if (
            accountState &&
            accountState !==
                "ACTIVE"
        ) {
            throw new pulumi.RunError(
                `Managed AWS account '${managedAccountId}' is in state '${accountState}', not ACTIVE`,
            );
        }


        const memberAccount =
            new aws.organizations.Account(
                "memberAccount",
                {
                    name:
                        accountName,

                    email:
                        accountDL,

                    roleName:
                        MEMBER_ACCOUNT_ROLE_NAME,

                    iamUserAccessToBilling:
                        "ALLOW",

                    closeOnDeletion:
                        false,
                },
                {
                    parent:
                        this,

                    protect:
                        true,
                },
            );


        const body =
            buildCreateAccountBody({
                check_aliases:
                    checkAliases,

                account_name:
                    accountName,

                account_dl:
                    accountDL,

                account_alias:
                    plannedAlias,

                decision:
                    "proceed",

                duplicate:
                    "false",

                dry_run:
                    "false",

                simulated:
                    "false",

                account_id:
                    managedAccountId,

                actions_taken: [
                    `Account '${accountName}' is already owned by this Pulumi stack`,
                    "Account resource retained in cumulative desired state",
                    "Create-time duplicate detection skipped",
                    "One-time trust update not repeated",
                ],

                plan: {
                    account_name:
                        accountName,

                    account_dl:
                        accountDL,

                    account_alias:
                        plannedAlias,

                    account_id:
                        managedAccountId,

                    mode:
                        "managed",

                    ownership_verified:
                        true,
                },
            });


        const actions =
            pulumi.output([
                `Account '${accountName}' (${managedAccountId}) remains managed by this stack`,
                "Create-time duplicate detection skipped",
                "One-time trust update not repeated",
            ]);


        return {
            accountPlan:
                body,

            account:
                memberAccount,

            confirmedActionsTaken:
                actions,
        };
    }


    /*
     * =====================================================================
     * 4. NEW ACCOUNT DUPLICATE CHECK
     *
     * This is the ONLY place index.ts calls duplicate detection.
     * =====================================================================
     */

    const duplicateResult =
        await detectDuplicates({
            accountName,

            accountDL,

            accountAlias:
                plannedAlias,

            checkAliases,
        });


    if (
        duplicateResult.found
    ) {

        pulumi.log.info(
            "[decision] abort",
        );


        return {
            accountPlan:
                buildCreateAccountBody({
                    check_aliases:
                        checkAliases,

                    account_name:
                        accountName,

                    account_dl:
                        accountDL,

                    account_alias:
                        plannedAlias,

                    decision:
                        "abort",

                    dry_run:
                        "false",

                    duplicate:
                        "true",

                    reason:
                        `duplicate_${(duplicateResult.primaryDuplicate as any)?.type ?? "unknown"}`,

                    account_id:
                        null,

                    actions_taken: [
                        `Duplicate ${(duplicateResult.primaryDuplicate as any)?.type ?? "unknown"} detected`,
                        "Account creation aborted",
                    ],

                    all_duplicates:
                        duplicateResult.allDuplicates,

                    primary_duplicate:
                        duplicateResult.primaryDuplicate,

                    plan: {
                        account_name:
                            accountName,

                        account_dl:
                            accountDL,

                        account_alias:
                            plannedAlias,

                        mode:
                            "create",

                        duplicate:
                            true,
                    },
                }),
        };
    }


    /*
     * =====================================================================
     * 5. CREATE REAL AWS ACCOUNT
     * =====================================================================
     */

    pulumi.log.info(
        "[decision] proceed",
    );

    pulumi.log.info(
        `[create-account] creating AWS account '${accountName}'`,
    );


    const memberAccount =
        new aws.organizations.Account(
            "memberAccount",
            {
                name:
                    accountName,

                email:
                    accountDL,

                roleName:
                    MEMBER_ACCOUNT_ROLE_NAME,

                iamUserAccessToBilling:
                    "ALLOW",

                closeOnDeletion:
                    false,
            },
            {
                parent:
                    this,

                protect:
                    true,
            },
        );


    /*
     * =====================================================================
     * 6. POST-CREATE TRUST UPDATE
     * =====================================================================
     *
     * The account resource ID becomes available only after AWS creates
     * the account. Pulumi waits for memberAccount.id before running this.
     */

    const trustStatus =
        memberAccount.id.apply(
            async (
                accountId,
            ) => {

                if (
                    pulumi.runtime.isDryRun()
                ) {
                    return `preview:${accountId}`;
                }


                console.log(
                    `[bootstrap] account ${accountId} is active; updating trust policy`,
                );


                const status =
                    await this.updateNewAccountTrust(
                        accountId,
                    );


                console.log(
                    `[bootstrap] ${status}`,
                );


                return status;
            },
        );


    /*
     * =====================================================================
     * 7. OUTPUTS
     * =====================================================================
     */

    const confirmedActionsTaken =
        trustStatus.apply(
            (
                status,
            ) => [
                `Created New Account '${accountName}'`,

                "Account creation completed and account is Active",

                status.startsWith(
                    "updated-trust",
                )
                    ? `'${MANAGEMENT_ACCOUNT_ROLE_NAME}' updated '${MEMBER_ACCOUNT_ROLE_NAME}' trust relationship to allow 'AE-AWS-IAC'`
                    : status.startsWith(
                          "preview:",
                      )
                      ? "Trust update will run during the real update"
                      : `'${MEMBER_ACCOUNT_ROLE_NAME}' trust relationship already allows 'AE-AWS-IAC'`,
            ],
        );


    const accountPlan =
        buildCreateAccountBody({
            check_aliases:
                checkAliases,

            account_name:
                accountName,

            account_dl:
                accountDL,

            account_alias:
                plannedAlias,

            decision:
                "proceed",

            dry_run:
                "false",

            duplicate:
                "false",

            account_id:
                null,

            simulated:
                "false",

            actions_taken: [
                `Creating New Account '${accountName}'`,
                "Waiting for AWS account creation to complete",
                "Updating OrganizationAccountAccessRole trust",
            ],

            plan: {
                account_name:
                    accountName,

                account_dl:
                    accountDL,

                account_alias:
                    plannedAlias,

                mode:
                    "create",

                duplicate:
                    false,
            },
        });


    return {
        accountPlan,

        account:
            memberAccount,

        confirmedActionsTaken,
    };
    }
}