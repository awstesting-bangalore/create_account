import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

import {
    IAMClient,
    GetRoleCommand,
    ListAccountAliasesCommand,
    UpdateAssumeRolePolicyCommand,
} from "@aws-sdk/client-iam";
import {
    OrganizationsClient,
    ListAccountsCommand,
    type Account as OrgAccount,
} from "@aws-sdk/client-organizations";
declare const process: any;

import {
    STSClient,
    AssumeRoleCommand,
} from "@aws-sdk/client-sts";

/*
 * ============================================================================
 * CREATE NEW AWS ACCOUNT - STAGE 1
 * ============================================================================
 *
 * One-file implementation for the cumulative account stack.
 *
 * Initial run:
 *   1. Validate inputs
 *   2. Build management-account AWS clients
 *   3. Check duplicates (configurable name/core + alias, email always)
 *   4. Abort on duplicate
 *   5. Create AWS Organizations account
 *   6. After creation, update OrganizationAccountAccessRole trust
 *
 * Stage 2+ runs:
 *   - Workato supplies managedAccountId.
 *   - The existing account is verified.
 *   - The same Pulumi Account resource remains declared.
 *   - Duplicate detection is skipped.
 *   - The one-time trust bootstrap is skipped.
 *
 * Pulumi preview is the only preview mechanism. No DRY_RUN application mode
 * exists.
 */

/* ============================================================================
 * 1. CONFIGURATION
 * ========================================================================== */

const AWS_REGION =
    process.env.AWS_REGION ??
    process.env.AWS_DEFAULT_REGION ??
    "us-east-1";



/* ============================================================================
 * 2. TYPES
 * ========================================================================== */

type SimpleAccount = {
    Id?: string;
    Name?: string;
    Email?: string;
    State?: string;
    Status?: string;
};

type DuplicateType = "name" | "email" | "alias" | "core";

type DuplicateMatch = {
    type: DuplicateType;
    account: SimpleAccount;
    meta?: Record<string, unknown> | null;
};

type IndexEntry = {
    acct: SimpleAccount;
    nameKey: string;
};

type AliasEntry = {
    account: SimpleAccount;
    aliases: string[];
    accountId?: string;
};

type IndexBundle = {
    aliasIndex: Record<string, { entries: AliasEntry[] }>;
    nameIndex: Record<string, IndexEntry>;
    emailIndex: Record<string, SimpleAccount>;
};

type DuplicateDetectionResult = {
    found: boolean;
    primaryDuplicate: Record<string, unknown> | null;
    allDuplicates: Array<Record<string, unknown>>;
};

export interface CreateNewAccountArgs {
    accountName: string;
    accountDL: string;
    accountAlias?: string;
    checkAccountNames?: boolean;
    checkAliases?: boolean;
    allowedPrefix?: string;
    forbiddenPrefixes?: string[];
    managementAccountRoleArn: string;
    managementBootstrapRoleArn: string;
    memberAccountRoleName: string;

    // Populated by Workato after Stage 1 and retained on later runs.
    managedAccountId?: string;
}

type AccountPlan = {
    check_account_names: string;
    check_aliases: string;
    account_name: string | null;
    account_dl: string | null;
    account_alias: string | null;
    decision: "proceed" | "abort" | null;
    duplicate: string;
    reason: string | null;
    actions_taken: string[];
    all_duplicates: Array<Record<string, unknown>>;
    primary_duplicate: Record<string, unknown> | null;
    account_id: string | null;
    account_arn: string | null;
    account_state: string | null;
    create_account_status_id: string | null;
    plan: Record<string, unknown>;
    error?: unknown;
};

type ProgramResult = {
    accountPlan: AccountPlan;
    account?: aws.organizations.Account;
    confirmedActionsTaken?: pulumi.Output<string[]>;
};

/* ============================================================================
 * 3. GENERIC HELPERS
 * ========================================================================== */

function parseBool(value: unknown, defaultValue = false): boolean {
    if (value === null || value === undefined) {
        return defaultValue;
    }

    if (typeof value === "boolean") {
        return value;
    }

    return ["1", "true", "yes", "y"].includes(
        String(value).trim().toLowerCase(),
    );
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/* ============================================================================
 * 4. ACCOUNT VALIDATION / NORMALIZATION
 * ========================================================================== */

function sanitizeAlias(value: string | undefined | null): string {
    return (value ?? "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, "-")
        .replace(/-{2,}/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 63);
}

function normalizeSimpleToken(
    value: string | undefined | null,
): string | null {
    if (!value) {
        return null;
    }

    const normalized = String(value)
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, "-")
        .replace(/-{2,}/g, "-")
        .replace(/^-+|-+$/g, "");

    return normalized || null;
}

function startsWithAnyPrefix(
    value: string | undefined | null,
    prefixes: string[],
): boolean {
    const token = normalizeSimpleToken(value);
    return Boolean(
        token &&
            prefixes.some((prefix) =>
                token === prefix || token.startsWith(`${prefix}-`),
            ),
    );
}

function hasAllowedPrefix(
    value: string | undefined | null,
    allowedPrefix: string,
): boolean {
    const token = normalizeSimpleToken(value);
    return Boolean(
        token &&
            (token === allowedPrefix || token.startsWith(`${allowedPrefix}-`)),
    );
}

function getCoreName(
    value: string | undefined | null,
    prefixes: string[],
): string | null {
    const normalized = normalizeSimpleToken(value);
    if (!normalized) {
        return null;
    }

    for (const prefix of prefixes) {
        if (normalized === prefix || normalized.startsWith(`${prefix}-`)) {
            const core = normalized.slice(prefix.length).replace(/^-+/, "");
            return core || normalized;
        }
    }

    return normalized;
}

function isValidEmail(value: string | undefined | null): boolean {
    return (
        typeof value === "string" &&
        value.includes("@") &&
        value.split("@").pop()?.includes(".") === true
    );
}

/* ============================================================================
 * 5. AWS ORGANIZATIONS / STS CLIENTS
 * ========================================================================== */

const loginSts = new STSClient({ region: AWS_REGION });

let orgSts: STSClient | undefined;
let organizations: OrganizationsClient | undefined;

async function buildAwsClients(
    managementAccountRoleArn: string,
): Promise<void> {
    const assumed = await loginSts.send(
        new AssumeRoleCommand({
            RoleArn: managementAccountRoleArn,
            RoleSessionName: "org-access",
        }),
    );

    if (!assumed.Credentials) {
        throw new Error(
            "Failed to assume management account role",
        );
    }

    const credentials = {
        accessKeyId: assumed.Credentials.AccessKeyId!,
        secretAccessKey: assumed.Credentials.SecretAccessKey!,
        sessionToken: assumed.Credentials.SessionToken!,
    };

    orgSts = new STSClient({
        region: AWS_REGION,
        credentials,
    });

    organizations = new OrganizationsClient({
        region: AWS_REGION,
        credentials,
    });

    pulumi.log.info(
        `[org-access] managementAccountRoleArn=${managementAccountRoleArn}`,
    );
}

function getOrgSts(): STSClient {
    if (!orgSts) {
        throw new Error("Organization STS client is not initialized");
    }
    return orgSts;
}

function getOrganizations(): OrganizationsClient {
    if (!organizations) {
        throw new Error("Organizations client is not initialized");
    }
    return organizations;
}

/* ============================================================================
 * 6. ACCOUNT LISTING / LOOKUP
 * ========================================================================== */

async function listAllAccounts(): Promise<SimpleAccount[]> {
    const accounts: SimpleAccount[] = [];
    let nextToken: string | undefined;

    while (true) {
        const response = await getOrganizations().send(
            new ListAccountsCommand(
                nextToken
                    ? { NextToken: nextToken }
                    : {},
            ),
        );

        accounts.push(
            ...(response.Accounts ?? []).map(
                (account: OrgAccount) => ({
                    Id: account.Id,
                    Name: account.Name,
                    Email: account.Email,
                    State: (account as any).State,
                    Status: account.Status,
                }),
            ),
        );

        nextToken = response.NextToken;
        if (!nextToken) {
            break;
        }
    }

    return accounts;
}

async function findAccountById(
    accountId: string,
): Promise<SimpleAccount | null> {
    if (!/^\d{12}$/.test(accountId)) {
        throw new Error(`Invalid AWS account ID '${accountId}'`);
    }

    const accounts = await listAllAccounts();
    return (
        accounts.find((account) => account.Id === accountId) ??
        null
    );
}

/* ============================================================================
 * 7. ACCOUNT ALIAS / DUPLICATE INDEXING
 * ========================================================================== */

type StsCredentials = {
    AccessKeyId?: string;
    SecretAccessKey?: string;
    SessionToken?: string;
};

async function assumeMemberRole(
    accountId: string,
    roleName: string,
    sessionName: string,
): Promise<StsCredentials> {
    const response = await getOrgSts().send(
        new AssumeRoleCommand({
            RoleArn:
                `arn:aws:iam::${accountId}:role/${roleName}`,
            RoleSessionName: sessionName,
        }),
    );

    if (!response.Credentials) {
        throw new Error(
            `Unable to assume ${roleName} in account ${accountId}`,
        );
    }

    return response.Credentials;
}

async function getAccountAliases(
    account: SimpleAccount,
    roleNameForAliasCheck: string,
): Promise<string[] | null> {
    if (!account.Id) {
        return null;
    }

    try {
        const credentials = await assumeMemberRole(
            account.Id,
            roleNameForAliasCheck,
            "duplicate-alias-check",
        );

        const iam = new IAMClient({
            region: AWS_REGION,
            credentials: {
                accessKeyId: credentials.AccessKeyId!,
                secretAccessKey: credentials.SecretAccessKey!,
                sessionToken: credentials.SessionToken!,
            },
        });

        const response = await iam.send(
            new ListAccountAliasesCommand({}),
        );

        return response.AccountAliases ?? [];
    } catch (error) {
        pulumi.log.warn(
            `[alias-check] failed for ${account.Id}: ${String(error)}`,
        );
        return null;
    }
}

async function buildIndexes(
    checkAliases: boolean,
    memberAccountRoleName: string,
): Promise<IndexBundle> {
    const accounts = await listAllAccounts();

    const aliasIndex: IndexBundle["aliasIndex"] = {};
    const nameIndex: IndexBundle["nameIndex"] = {};
    const emailIndex: IndexBundle["emailIndex"] = {};

    for (const account of accounts) {
        const nameKey = normalizeSimpleToken(account.Name);
        if (nameKey) {
            nameIndex[nameKey] = {
                acct: account,
                nameKey,
            };
        }

        const emailKey =
            (account.Email ?? "").trim().toLowerCase();

        if (emailKey) {
            emailIndex[emailKey] = account;
        }

        if (!checkAliases) {
            continue;
        }

        const aliases = await getAccountAliases(
            account,
            memberAccountRoleName,
        );
        if (!aliases?.length) {
            continue;
        }

        for (const alias of aliases) {
            const aliasKey = alias.trim().toLowerCase();
            if (!aliasKey) {
                continue;
            }

            aliasIndex[aliasKey] ??= { entries: [] };
            aliasIndex[aliasKey].entries.push({
                account,
                aliases,
                accountId: account.Id,
            });
        }
    }

    const indexes: IndexBundle = {
        aliasIndex,
        nameIndex,
        emailIndex,
    };

    pulumi.log.info(
        `[index-build] names=${Object.keys(nameIndex).length} ` +
        `emails=${Object.keys(emailIndex).length} ` +
        `aliases=${Object.keys(aliasIndex).length}`,
    );

    return indexes;
}

function choosePrimaryDuplicate(
    duplicates: DuplicateMatch[],
): DuplicateMatch | null {
    const priority: DuplicateType[] = [
        "name",
        "alias",
        "core",
        "email",
    ];

    for (const type of priority) {
        const match = duplicates.find(
            (duplicate) => duplicate.type === type,
        );

        if (match) {
            return match;
        }
    }

    return duplicates[0] ?? null;
}

function buildMatchRows(
    duplicates: DuplicateMatch[],
): Array<Record<string, unknown>> {
    return duplicates.map((duplicate) => ({
        match_type: duplicate.type,
        account_number: duplicate.account.Id ?? null,
        account_name: duplicate.account.Name ?? null,
        account_dl: duplicate.account.Email ?? null,
        meta: duplicate.meta ?? null,
    }));
}

async function detectDuplicates(
    accountName: string,
    accountDL: string,
    accountAlias: string,
    checkAccountNames: boolean,
    checkAliases: boolean,
    accountPrefixes: string[],
    memberAccountRoleName: string,
): Promise<DuplicateDetectionResult> {
    pulumi.log.info(
        `[duplicate-check] account names/core: ${checkAccountNames ? "enabled" : "disabled"}`,
    );
    pulumi.log.info(
        `[duplicate-check] aliases: ${checkAliases ? "enabled" : "disabled"}`,
    );
    pulumi.log.info(
        "[duplicate-check] email: always enabled",
    );
    const indexes = await buildIndexes(
        checkAliases,
        memberAccountRoleName,
    );
    const duplicates: DuplicateMatch[] = [];
    const seen = new Set<string>();

    const addMatch = (
        type: DuplicateType,
        account: SimpleAccount,
        meta: Record<string, unknown> | null = null,
    ) => {
        const identity =
            account.Id ??
            account.Email ??
            account.Name ??
            "unknown";
        const marker = `${type}:${identity}`;

        if (seen.has(marker)) {
            return;
        }

        seen.add(marker);
        duplicates.push({
            type,
            account,
            meta,
        });
    };

    const nameKey = normalizeSimpleToken(accountName);
    const emailKey = accountDL.trim().toLowerCase() || null;
    const aliasKey = normalizeSimpleToken(accountAlias);

    if (checkAccountNames && nameKey && indexes.nameIndex[nameKey]) {
        addMatch(
            "name",
            indexes.nameIndex[nameKey].acct,
            { matched_name: nameKey },
        );
    }

    if (emailKey && indexes.emailIndex[emailKey]) {
        addMatch(
            "email",
            indexes.emailIndex[emailKey],
        );
    }

    if (checkAliases) {
        const aliasKeys = [
            nameKey,
            emailKey,
            aliasKey,
        ].filter(
            (key): key is string => Boolean(key),
        );

        for (const key of aliasKeys) {
            const match = indexes.aliasIndex[key];
            if (match?.entries?.length) {
                addMatch(
                    "alias",
                    match.entries[0].account,
                    { matched_alias: key },
                );
            }
        }
    }

    if (checkAccountNames) {
        const newCoreKeys = new Set<string>();
        for (const value of [accountName, accountAlias]) {
            const core = getCoreName(value, accountPrefixes);
            if (core) {
                newCoreKeys.add(core);
            }
        }

        for (const entry of Object.values(indexes.nameIndex)) {
            const existingCore = getCoreName(entry.nameKey, accountPrefixes);
            if (!existingCore || !newCoreKeys.has(existingCore)) {
                continue;
            }

            if (
                entry.nameKey === normalizeSimpleToken(accountName) ||
                entry.nameKey === normalizeSimpleToken(accountAlias)
            ) {
                continue;
            }

            addMatch(
                "core",
                entry.acct,
                {
                    existing_core: existingCore,
                    new_core: Array.from(newCoreKeys).sort(),
                },
            );
        }

        for (const [aliasKey, aliasMeta] of Object.entries(
            indexes.aliasIndex,
        )) {
            const existingCore = getCoreName(aliasKey, accountPrefixes);
            if (!existingCore || !newCoreKeys.has(existingCore)) {
                continue;
            }

            if (
                aliasKey === normalizeSimpleToken(accountName) ||
                aliasKey === normalizeSimpleToken(accountAlias)
            ) {
                continue;
            }

            const entry = aliasMeta.entries?.[0];
            if (entry) {
                addMatch(
                    "core",
                    entry.account,
                    {
                        existing_core: existingCore,
                        new_core: Array.from(newCoreKeys).sort(),
                    },
                );
            }
        }
    }

    pulumi.log.info(
        `[duplicate-check] ${duplicates.length} duplicate match(es) found`,
    );

    if (!duplicates.length) {
        return {
            found: false,
            primaryDuplicate: null,
            allDuplicates: [],
        };
    }

    const primary = choosePrimaryDuplicate(duplicates);
    const primaryDuplicate = primary
        ? {
              type: primary.type,
              account: {
                  Id: primary.account.Id,
                  Name: primary.account.Name,
                  Email: primary.account.Email,
              },
              meta: primary.meta,
          }
        : null;

    const allDuplicates = buildMatchRows(duplicates);

    pulumi.log.warn(
        `[duplicate-check] duplicate detected: ${primary?.type ?? "unknown"}`,
    );

    return {
        found: true,
        primaryDuplicate,
        allDuplicates,
    };
}

/* ============================================================================
 * 8. PLAN / RESPONSE HELPERS
 * ========================================================================== */

function buildAccountPlan(params: {
    accountName: string;
    accountDL: string;
    accountAlias: string;
    checkAccountNames: boolean;
    checkAliases: boolean;
    decision: "proceed" | "abort";
    duplicate?: boolean;
    reason?: string | null;
    accountId?: string | null;
    actionsTaken?: string[];
    primaryDuplicate?: Record<string, unknown> | null;
    allDuplicates?: Array<Record<string, unknown>>;
    plan?: Record<string, unknown>;
}): AccountPlan {
    return {
        check_account_names: params.checkAccountNames ? "true" : "false",
        check_aliases: params.checkAliases ? "true" : "false",
        account_name: params.accountName,
        account_dl: params.accountDL,
        account_alias: params.accountAlias,
        decision: params.decision,
        duplicate: params.duplicate ? "true" : "false",
        reason: params.reason ?? null,
        actions_taken: params.actionsTaken ?? [],
        all_duplicates: params.allDuplicates ?? [],
        primary_duplicate: params.primaryDuplicate ?? null,
        account_id: params.accountId ?? null,
        account_arn: null,
        account_state: null,
        create_account_status_id: null,
        plan: params.plan ?? {},
    };
}

/* ============================================================================
 * 9. NEW-ACCOUNT TRUST BOOTSTRAP
 * ========================================================================== */

type PolicyStatement = {
    Sid?: string;
    Effect?: string;
    Principal?: unknown;
    Action?: string | string[];
    Resource?: string | string[];
    Condition?: unknown;
};

type PolicyDocument = {
    Version: string;
    Statement: PolicyStatement[];
};

async function retryWithBackoff<T>(
    fn: () => Promise<T>,
    label: string,
): Promise<T> {
    const attempts = 5;
    const baseDelayMs = 2000;
    let lastError: unknown;

    for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
            return await fn();
        } catch (error) {
            lastError = error;

            const name = (error as any)?.name ?? "";
            const message = String(
                (error as any)?.message ?? error ?? "",
            );

            const retryable =
                name === "AccessDenied" ||
                name === "AccessDeniedException" ||
                name === "NoSuchEntity" ||
                name === "NoSuchEntityException" ||
                /not authorized to perform/i.test(message) ||
                /cannot be assumed/i.test(message) ||
                /does not exist/i.test(message);

            pulumi.log.warn(
                `[retry] ${label} attempt ${attempt}/${attempts} failed: ${message} (retryable=${retryable})`,
            );

            if (!retryable || attempt === attempts) {
                throw error;
            }

            await sleep(
                baseDelayMs * Math.pow(2, attempt - 1),
            );
        }
    }

    throw lastError;
}

function decodePolicy(
    policyDocument: string | undefined | null,
): PolicyDocument {
    if (!policyDocument) {
        return {
            Version: "2012-10-17",
            Statement: [],
        };
    }

    let decoded = policyDocument;
    try {
        decoded = decodeURIComponent(
            policyDocument.replace(/\+/g, "%20"),
        );
    } catch {
        // Keep original document when decoding is unnecessary.
    }

    const parsed = JSON.parse(decoded) as PolicyDocument;

    return {
        Version: parsed.Version ?? "2012-10-17",
        Statement: Array.isArray(parsed.Statement)
            ? parsed.Statement
            : [],
    };
}

function principalContains(
    principal: unknown,
    arn: string,
): boolean {
    if (typeof principal === "string") {
        return principal === arn;
    }

    if (Array.isArray(principal)) {
        return principal.includes(arn);
    }

    if (principal && typeof principal === "object") {
        const awsPrincipal = (
            principal as Record<string, unknown>
        ).AWS;

        if (typeof awsPrincipal === "string") {
            return awsPrincipal === arn;
        }

        if (Array.isArray(awsPrincipal)) {
            return awsPrincipal.includes(arn);
        }
    }

    return false;
}

function trustContainsPrincipal(
    policy: PolicyDocument,
    arn: string,
): boolean {
    return policy.Statement.some((statement) => {
        const action = statement.Action;
        const actionMatches =
            action === "sts:AssumeRole" ||
            (Array.isArray(action) &&
                action.includes("sts:AssumeRole"));

        return (
            actionMatches &&
            principalContains(statement.Principal, arn)
        );
    });
}

function addPulumiTrust(
    policy: PolicyDocument,
    arn: string,
): PolicyDocument {
    if (trustContainsPrincipal(policy, arn)) {
        return policy;
    }

    return {
        Version: policy.Version ?? "2012-10-17",
        Statement: [
            ...policy.Statement,
            {
                Sid: "AllowPulumiIac",
                Effect: "Allow",
                Principal: { AWS: arn },
                Action: "sts:AssumeRole",
            },
        ],
    };
}

async function updateNewAccountTrust(
    accountId: string,
    managementBootstrapRoleArn: string,
    memberAccountRoleName: string,
): Promise<string> {
    const managementSts = getOrgSts();
    const iacRoleArn =
        "arn:aws:iam::863748637175:role/AE-AWS-IAC";

    const bootstrap = await managementSts.send(
        new AssumeRoleCommand({
            RoleArn: managementBootstrapRoleArn,
            RoleSessionName: "bootstrap-new-account",
        }),
    );

    if (!bootstrap.Credentials) {
        throw new Error(
            "Failed to assume management account bootstrap role",
        );
    }

    const bootstrapCredentials = {
        accessKeyId: bootstrap.Credentials.AccessKeyId!,
        secretAccessKey:
            bootstrap.Credentials.SecretAccessKey!,
        sessionToken: bootstrap.Credentials.SessionToken!,
    };

    const bootstrapSts = new STSClient({
        region: AWS_REGION,
        credentials: bootstrapCredentials,
    });

    const member = (await retryWithBackoff(
        () =>
            bootstrapSts.send(
                new AssumeRoleCommand({
                    RoleArn:
                        `arn:aws:iam::${accountId}:role/${memberAccountRoleName}`,
                    RoleSessionName: "new-account-trust-update",
                }),
            ),
        `assume ${memberAccountRoleName} in ${accountId}`,
    )) as { Credentials?: StsCredentials };

    if (!member.Credentials) {
        throw new Error(
            `Failed to assume ${memberAccountRoleName} in account ${accountId}`,
        );
    }

    const memberIam = new IAMClient({
        region: AWS_REGION,
        credentials: {
            accessKeyId: member.Credentials.AccessKeyId!,
            secretAccessKey:
                member.Credentials.SecretAccessKey!,
            sessionToken: member.Credentials.SessionToken!,
        },
    });

    const role = await memberIam.send(
        new GetRoleCommand({
            RoleName: memberAccountRoleName,
        }),
    );

    const currentPolicy = decodePolicy(
        role.Role?.AssumeRolePolicyDocument ?? null,
    );

    const updatedPolicy = addPulumiTrust(
        currentPolicy,
        iacRoleArn,
    );

    const changed =
        JSON.stringify(currentPolicy) !==
        JSON.stringify(updatedPolicy);

    if (!changed) {
        return `no-change:${accountId}`;
    }

    await memberIam.send(
        new UpdateAssumeRolePolicyCommand({
            RoleName: memberAccountRoleName,
            PolicyDocument: JSON.stringify(updatedPolicy),
        }),
    );

    return `updated-trust:${accountId}`;
}

/* ============================================================================
 * 10. COMPONENT
 * ========================================================================== */

export class CreateNewAccount extends pulumi.ComponentResource {
    public readonly checkAccountNames!: pulumi.Output<string>;
    public readonly checkAliases!: pulumi.Output<string>;
    public readonly accountName!: pulumi.Output<string>;
    public readonly accountDl!: pulumi.Output<string>;
    public readonly accountAlias!: pulumi.Output<string>;
    public readonly decision!: pulumi.Output<string>;
    public readonly actionsTaken!: pulumi.Output<string[]>;
    public readonly accountId!: pulumi.Output<string>;
    public readonly accountJoinedTimestamp!: pulumi.Output<string>;
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

        const programOut = pulumi.output(
            this.runProgram({
                account_name: args.accountName,
                account_dl: args.accountDL,
                account_alias:
                    args.accountAlias ?? args.accountName,
                check_account_names:
                    args.checkAccountNames ?? true,
                check_aliases:
                    args.checkAliases ?? true,
                managed_account_id:
                    args.managedAccountId,
                allowed_prefix:
                    args.allowedPrefix ?? "aegm",
                forbidden_prefixes:
                    args.forbiddenPrefixes ?? ["aenetworks", "aetn"],
                management_account_role_arn:
                    args.managementAccountRoleArn,
                management_bootstrap_role_arn:
                    args.managementBootstrapRoleArn,
                member_account_role_name:
                    args.memberAccountRoleName,
            }),
        );

        const plan = programOut.apply(
            (result) => result.accountPlan,
        );

        this.checkAccountNames = plan.apply(
            (value) => value.check_account_names,
        );
        this.checkAliases = plan.apply(
            (value) => value.check_aliases,
        );
        this.accountName = plan.apply(
            (value) => value.account_name ?? "",
        );
        this.accountDl = plan.apply(
            (value) => value.account_dl ?? "",
        );
        this.accountAlias = plan.apply(
            (value) => value.account_alias ?? "",
        );
        this.decision = plan.apply(
            (value) => value.decision ?? "",
        );
        this.actionsTaken = programOut.apply(
            (result) =>
                result.confirmedActionsTaken ??
                result.accountPlan.actions_taken,
        );
        this.accountId = programOut.apply((result) =>
            result.account
                ? result.account.id
                : pulumi.output(result.accountPlan.account_id ?? ""),
        );
        this.accountJoinedTimestamp = programOut.apply((result) =>          // add this
            result.account
                ? result.account.joinedTimestamp
                : pulumi.output(""),
        );
        this.reason = plan.apply(
            (value) =>
                value.decision === "abort"
                    ? value.reason ?? ""
                    : "",
        );
        this.duplicate = plan.apply(
            (value) =>
                value.decision === "abort"
                    ? value.duplicate
                    : "",
        );

        this.registerOutputs({
            checkAccountNames: this.checkAccountNames,
            checkAliases: this.checkAliases,
            accountName: this.accountName,
            accountDl: this.accountDl,
            accountAlias: this.accountAlias,
            decision: this.decision,
            actionsTaken: this.actionsTaken,
            accountId: this.accountId,
            accountJoinedTimestamp: this.accountJoinedTimestamp,
            reason: this.reason,
            duplicate: this.duplicate,
        });
    }

    /* ========================================================================
     * 11. MAIN PROGRAM
     * ====================================================================== */

    private async runProgram(input: {
        account_name: string;
        account_dl: string;
        account_alias?: string;
        check_account_names?: boolean;
        check_aliases?: boolean;
        managed_account_id?: string;
        allowed_prefix: string;
        forbidden_prefixes: string[];
        management_account_role_arn: string;
        management_bootstrap_role_arn: string;
        member_account_role_name: string;
    }): Promise<ProgramResult> {
        const accountName = input.account_name?.trim();
        const accountDL = input.account_dl?.trim();
        const accountAlias =
            input.account_alias?.trim() || accountName;
        const managedAccountId =
            input.managed_account_id?.trim() || undefined;
        const checkAccountNames = parseBool(
            input.check_account_names,
            true,
        );
        const checkAliases = parseBool(
            input.check_aliases,
            true,
        );
        const allowedPrefix =
            normalizeSimpleToken(input.allowed_prefix) ?? "aegm";
        const forbiddenPrefixes =
            input.forbidden_prefixes
                .map((prefix) => normalizeSimpleToken(prefix))
                .filter((prefix): prefix is string => Boolean(prefix));
        const managementAccountRoleArn =
            input.management_account_role_arn?.trim();
        const managementBootstrapRoleArn =
            input.management_bootstrap_role_arn?.trim();
        const memberAccountRoleName =
            input.member_account_role_name?.trim();
        const plannedAlias = sanitizeAlias(accountAlias);

        /* --------------------------------------------------------------------
         * 11.1 VALIDATION
         * ------------------------------------------------------------------ */

        if (!accountName || !accountDL) {
            return {
                accountPlan: buildAccountPlan({
                    accountName: accountName ?? "",
                    accountDL: accountDL ?? "",
                    accountAlias: plannedAlias,
                    checkAccountNames,
                    checkAliases,
                    decision: "abort",
                    reason: "validation_error",
                    actionsTaken: [],
                    plan: { mode: "create" },
                }),
            };
        }

        if (startsWithAnyPrefix(accountName, forbiddenPrefixes)) {
            return {
                accountPlan: buildAccountPlan({
                    accountName,
                    accountDL,
                    accountAlias: plannedAlias,
                    checkAccountNames,
                    checkAliases,
                    decision: "abort",
                    reason: "validation_error",
                    plan: { mode: "create" },
                }),
            };
        }

        if (startsWithAnyPrefix(plannedAlias, forbiddenPrefixes)) {
            return {
                accountPlan: buildAccountPlan({
                    accountName,
                    accountDL,
                    accountAlias: plannedAlias,
                    checkAccountNames,
                    checkAliases,
                    decision: "abort",
                    reason: "validation_error",
                    plan: { mode: "create" },
                }),
            };
        }

        if (!hasAllowedPrefix(accountName, allowedPrefix)) {
            return {
                accountPlan: buildAccountPlan({
                    accountName,
                    accountDL,
                    accountAlias: plannedAlias,
                    checkAccountNames,
                    checkAliases,
                    decision: "abort",
                    reason: "validation_error",
                    plan: {
                        mode: "create",
                        allowed_prefix: allowedPrefix,
                    },
                }),
            };
        }

        if (!isValidEmail(accountDL)) {
            return {
                accountPlan: buildAccountPlan({
                    accountName,
                    accountDL,
                    accountAlias: plannedAlias,
                    checkAccountNames,
                    checkAliases,
                    decision: "abort",
                    reason: "validation_error",
                    plan: { mode: "create" },
                }),
            };
        }

        if (
            managedAccountId &&
            !/^\d{12}$/.test(managedAccountId)
        ) {
            throw new pulumi.RunError(
                `managedAccountId '${managedAccountId}' is not a valid 12-digit AWS account ID`,
            );
        }

        /* --------------------------------------------------------------------
         * 11.2 MANAGEMENT ACCOUNT ACCESS
         * ------------------------------------------------------------------ */

        if (!managementAccountRoleArn) {
            throw new pulumi.RunError(
                "appConfig:managementAccountRoleArn is required for Stage 1",
            );
        }

        if (!managementBootstrapRoleArn) {
            throw new pulumi.RunError(
                "appConfig:managementBootstrapRoleArn is required for Stage 1",
            );
        }

        if (!memberAccountRoleName) {
            throw new pulumi.RunError(
                "appConfig:memberAccountRoleName is required for Stage 1",
            );
        }

        if (!checkAccountNames && !checkAliases) {
            throw new pulumi.RunError(
                "Duplicate detection cannot be disabled completely. Enable appConfig:checkAccountNames or appConfig:checkAliases.",
            );
        }

        await buildAwsClients(managementAccountRoleArn);

        /* --------------------------------------------------------------------
         * 11.3 CUMULATIVE RUN - ACCOUNT ALREADY CREATED
         * ------------------------------------------------------------------ */

        if (managedAccountId) {
            const managedAccount = await findAccountById(
                managedAccountId,
            );

            if (!managedAccount) {
                throw new pulumi.RunError(
                    `Managed AWS account '${managedAccountId}' was not found in AWS Organizations`,
                );
            }

            const expectedName = normalizeSimpleToken(
                accountName,
            );
            const actualName = normalizeSimpleToken(
                managedAccount.Name,
            );

            const expectedEmail = accountDL
                .toLowerCase();
            const actualEmail = (
                managedAccount.Email ?? ""
            )
                .trim()
                .toLowerCase();

            if (
                expectedName !== actualName ||
                expectedEmail !== actualEmail
            ) {
                throw new pulumi.RunError(
                    `Managed account verification failed for '${managedAccountId}'. ` +
                    `Expected '${accountName}'/'${accountDL}', ` +
                    `but AWS returned '${managedAccount.Name ?? ""}'/'${managedAccount.Email ?? ""}'.`,
                );
            }

            const state = (
                managedAccount.State ??
                managedAccount.Status ??
                ""
            )
                .trim()
                .toUpperCase();

            if (state && state !== "ACTIVE") {
                throw new pulumi.RunError(
                    `Managed AWS account '${managedAccountId}' is in state '${state}', not ACTIVE`,
                );
            }

            pulumi.log.info(
                `[ownership] account ${managedAccountId} verified and retained in cumulative state`,
            );

            const memberAccount =
                new aws.organizations.Account(
                    "memberAccount",
                    {
                        name: accountName,
                        email: accountDL,
                        roleName:
                            memberAccountRoleName,
                        iamUserAccessToBilling: "ALLOW",
                        closeOnDeletion: false,
                    },
                    {
                        parent: this,
                        protect: true,
                    },
                );

            const actions = pulumi.output([
                `Account '${accountName}' (${managedAccountId}) remains managed by this stack`,
                "Create-time duplicate detection skipped",
                "One-time trust bootstrap skipped",
            ]);

            return {
                accountPlan: buildAccountPlan({
                    accountName,
                    accountDL,
                    accountAlias: plannedAlias,
                    checkAccountNames,
                    checkAliases,
                    decision: "proceed",
                    accountId: managedAccountId,
                    actionsTaken: [
                        `Account '${accountName}' is already owned by this Pulumi stack`,
                        "Account resource retained in cumulative desired state",
                        "Create-time duplicate detection skipped",
                        "One-time trust bootstrap skipped",
                    ],
                    plan: {
                        mode: "managed",
                        account_id: managedAccountId,
                        ownership_verified: true,
                    },
                }),
                account: memberAccount,
                confirmedActionsTaken: actions,
            };
        }

        /* --------------------------------------------------------------------
         * 11.4 INITIAL CREATE - DUPLICATE DETECTION
         * ------------------------------------------------------------------ */

        const duplicateResult = await detectDuplicates(
            accountName,
            accountDL,
            plannedAlias,
            checkAccountNames,
            checkAliases,
            [allowedPrefix, ...forbiddenPrefixes],
            memberAccountRoleName,
        );

        if (duplicateResult.found) {
            pulumi.log.info("[decision] abort");

            return {
                accountPlan: buildAccountPlan({
                    accountName,
                    accountDL,
                    accountAlias: plannedAlias,
                    checkAccountNames,
                    checkAliases,
                    decision: "abort",
                    duplicate: true,
                    reason:
                        `duplicate_${(duplicateResult.primaryDuplicate as any)?.type ?? "unknown"}`,
                    primaryDuplicate:
                        duplicateResult.primaryDuplicate,
                    allDuplicates:
                        duplicateResult.allDuplicates,
                    actionsTaken: [
                        `Duplicate ${(duplicateResult.primaryDuplicate as any)?.type ?? "unknown"} detected`,
                        "Account creation aborted",
                    ],
                    plan: {
                        mode: "create",
                        duplicate: true,
                    },
                }),
            };
        }

        /* --------------------------------------------------------------------
         * 11.5 CREATE AWS ACCOUNT
         * ------------------------------------------------------------------ */

        pulumi.log.info("[decision] proceed");
        pulumi.log.info(
            `[create-account] creating AWS account '${accountName}'`,
        );

        const memberAccount =
            new aws.organizations.Account(
                "memberAccount",
                {
                    name: accountName,
                    email: accountDL,
                    roleName:
                        memberAccountRoleName,
                    iamUserAccessToBilling: "ALLOW",
                    closeOnDeletion: false,
                },
                {
                    parent: this,
                    protect: true,
                },
            );

        /* --------------------------------------------------------------------
         * 11.6 POST-CREATE TRUST UPDATE
         * ------------------------------------------------------------------ */

        const trustStatus = memberAccount.id.apply(
            async (accountId) => {
                if (pulumi.runtime.isDryRun()) {
                    return `preview:${accountId}`;
                }

                pulumi.log.info(
                    `[bootstrap] updating ${memberAccountRoleName} trust in account ${accountId}`,
                );

                return updateNewAccountTrust(
                    accountId,
                    managementBootstrapRoleArn,
                    memberAccountRoleName,
                );
            },
        );

        const confirmedActionsTaken =
            trustStatus.apply((status) => [
                `Created New Account '${accountName}'`,
                "Waiting for AWS account creation to complete",
                status.startsWith("updated-trust")
                    ? `'${memberAccountRoleName}' trust updated to allow 'arn:aws:iam::039892245804:role/TEST-AWS-IAC'`
                    : status.startsWith("preview:")
                      ? "Trust update will run during the real Pulumi update"
                      : `'${memberAccountRoleName}' trust already allows Pulumi IAC`,
            ]);

        return {
            accountPlan: buildAccountPlan({
                accountName,
                accountDL,
                accountAlias: plannedAlias,
                checkAccountNames,
                checkAliases,
                decision: "proceed",
                duplicate: false,
                actionsTaken: [
                    `Creating New Account '${accountName}'`,
                    "Waiting for AWS account creation to complete",
                    `Updating ${memberAccountRoleName} trust`,
                ],
                plan: {
                    mode: "create",
                    duplicate: false,
                },
            }),
            account: memberAccount,
            confirmedActionsTaken,
        };
    }
}