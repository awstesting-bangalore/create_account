/*
 * -----------------------------------------------------------------------------
 * common_helpers.ts
 * -----------------------------------------------------------------------------
 *
 * NOTE: This file was missing from the repository (index.ts imports it, but
 * no version of it exists anywhere in git history). It has been reconstructed
 * from the call sites in index.ts: exported names, argument shapes, and
 * usage patterns were inferred from how index.ts consumes them.
 *
 * This is a best-effort reconstruction, not a restoration of original
 * business logic. In particular:
 *   - getOrgAccountId() and getPulumiIacRoleArn() intentionally source
 *     real, organization-specific identifiers (an AWS account ID and an IAM
 *     role ARN) from environment variables rather than hardcoded values.
 *     Nobody should guess these; they must be supplied by whoever operates
 *     this stack (e.g. via CI/CD environment configuration).
 *   - Duplicate-detection matching rules, alias sanitization, and name/email
 *     validation are reasonable defaults inferred from error message text
 *     in index.ts, not verified organizational policy.
 *
 * Review carefully before relying on this in a real account-creation flow.
 * -----------------------------------------------------------------------------
 */

import {
    STSClient,
    GetCallerIdentityCommand,
} from "@aws-sdk/client-sts";

import {
    OrganizationsClient,
    DescribeAccountCommand,
    ListAccountsCommand,
    type Account,
} from "@aws-sdk/client-organizations";

/*
 * -----------------------------------------------------------------------------
 * Role name constants
 * -----------------------------------------------------------------------------
 *
 * MEMBER_ACCOUNT_ROLE_NAME: the role created by AWS Organizations in every
 * newly-created member account (defaults to the AWS-managed
 * "OrganizationAccountAccessRole").
 *
 * MANAGEMENT_ACCOUNT_ROLE_NAME: the role in the management/org account that
 * is assumed as a bootstrap hop before assuming into the member account.
 * -----------------------------------------------------------------------------
 */

export const MEMBER_ACCOUNT_ROLE_NAME: string =
    process.env.MEMBER_ACCOUNT_ROLE_NAME ??
    "OrganizationAccountAccessRole";

export const MANAGEMENT_ACCOUNT_ROLE_NAME: string =
    process.env.MANAGEMENT_ACCOUNT_ROLE_NAME ??
    "OrganizationAccountAccessRole";

const FORBIDDEN_ACCOUNT_NAME_PREFIX = "aenetworks-";

const AWS_REGION: string =
    process.env.AWS_REGION ??
    process.env.AWS_DEFAULT_REGION ??
    "us-east-1";

/*
 * -----------------------------------------------------------------------------
 * Shared AWS SDK clients
 * -----------------------------------------------------------------------------
 *
 * These clients rely on the ambient AWS SDK credential provider chain
 * (environment variables, shared config/profile, or instance/task role).
 * They are intentionally NOT tied to the Pulumi `aws.Provider` passed into
 * the CreateNewAccount component, since that provider only affects
 * Pulumi-declared resources (e.g. aws.organizations.Account) and not these
 * direct, imperative AWS SDK calls.
 * -----------------------------------------------------------------------------
 */

let stsClient: STSClient | undefined;
let organizationsClient: OrganizationsClient | undefined;

export async function buildAwsClients(): Promise<void> {
    if (!stsClient) {
        stsClient = new STSClient({ region: AWS_REGION });
    }

    if (!organizationsClient) {
        organizationsClient = new OrganizationsClient({ region: AWS_REGION });
    }

    // Fail fast with a clear error if ambient credentials cannot resolve,
    // rather than surfacing a confusing error deep inside a later API call.
    await stsClient.send(new GetCallerIdentityCommand({}));
}

export function getOrgSts(): STSClient {
    if (!stsClient) {
        throw new Error(
            "AWS clients not initialized; call buildAwsClients() first",
        );
    }

    return stsClient;
}

function getOrganizationsClient(): OrganizationsClient {
    if (!organizationsClient) {
        throw new Error(
            "AWS clients not initialized; call buildAwsClients() first",
        );
    }

    return organizationsClient;
}

/*
 * -----------------------------------------------------------------------------
 * Organization identity helpers
 * -----------------------------------------------------------------------------
 *
 * These intentionally read from environment variables rather than embedding
 * a real AWS account ID / IAM role ARN in source code.
 * -----------------------------------------------------------------------------
 */

export function getOrgAccountId(): string {
    const accountId = process.env.ORG_ACCOUNT_ID;

    if (!accountId) {
        throw new Error(
            "ORG_ACCOUNT_ID environment variable is required (AWS Organizations management account ID)",
        );
    }

    return accountId;
}

export function getPulumiIacRoleArn(): string {
    const roleArn = process.env.PULUMI_IAC_ROLE_ARN;

    if (!roleArn) {
        throw new Error(
            "PULUMI_IAC_ROLE_ARN environment variable is required (ARN of the 'AE-AWS-IAC' principal to trust)",
        );
    }

    return roleArn;
}

/*
 * -----------------------------------------------------------------------------
 * AWS Organizations lookups
 * -----------------------------------------------------------------------------
 */

export async function find_account_by_id(
    accountId: string,
): Promise<Account | undefined> {
    const response = await getOrganizationsClient().send(
        new DescribeAccountCommand({ AccountId: accountId }),
    );

    return response.Account;
}

export async function listOrgAccounts(): Promise<Account[]> {
    const client = getOrganizationsClient();
    const accounts: Account[] = [];

    let nextToken: string | undefined;

    do {
        const response = await client.send(
            new ListAccountsCommand({ NextToken: nextToken }),
        );

        accounts.push(...(response.Accounts ?? []));
        nextToken = response.NextToken;
    } while (nextToken);

    return accounts;
}

/*
 * -----------------------------------------------------------------------------
 * Misc utilities
 * -----------------------------------------------------------------------------
 */

export function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

export function parseBool(
    value: boolean | string | undefined,
    defaultValue: boolean,
): boolean {
    if (value === undefined) {
        return defaultValue;
    }

    if (typeof value === "boolean") {
        return value;
    }

    const normalized = value.trim().toLowerCase();

    if (["true", "1", "yes"].includes(normalized)) {
        return true;
    }

    if (["false", "0", "no"].includes(normalized)) {
        return false;
    }

    return defaultValue;
}

/*
 * AWS IAM account aliases must be lowercase, 3-63 characters, and contain
 * only letters, digits, and hyphens (not adjacent, not leading/trailing).
 */
export function sanitize_alias(alias: string): string {
    let sanitized = alias.trim().toLowerCase();

    sanitized = sanitized.replace(/[^a-z0-9-]/g, "-");
    sanitized = sanitized.replace(/-+/g, "-");
    sanitized = sanitized.replace(/^-+|-+$/g, "");

    if (sanitized.length < 3) {
        sanitized = sanitized.padEnd(3, "0");
    }

    if (sanitized.length > 63) {
        sanitized = sanitized.slice(0, 63).replace(/-+$/, "");
    }

    return sanitized;
}

export function _starts_with_forbidden_prefix(value: string): boolean {
    return value.trim().toLowerCase().startsWith(FORBIDDEN_ACCOUNT_NAME_PREFIX);
}

/*
 * AWS Organizations account names allow 1-50 characters. This permits
 * letters, digits, spaces, hyphens, underscores, and periods.
 */
export function _is_valid_account_name_format(name: string): boolean {
    const trimmed = name.trim();

    if (trimmed.length === 0 || trimmed.length > 50) {
        return false;
    }

    return /^[\w .-]+$/.test(trimmed);
}

export function _is_valid_email(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

export function _normalize_simple_token(
    token: string | undefined | null,
): string {
    return (token ?? "").trim().toLowerCase().replace(/\s+/g, " ");
}

/*
 * -----------------------------------------------------------------------------
 * Account plan output
 * -----------------------------------------------------------------------------
 */

export type AccountPlanOutput = {
    // These are always populated by buildCreateAccountBody's defaulting
    // below, so they are non-optional here.
    check_aliases: boolean;
    account_alias: string;
    decision: "proceed" | "abort";
    duplicate: "true" | "false";
    actions_taken: string[];

    account_name: string;
    account_dl: string;
    dry_run?: "true" | "false";
    simulated?: "true" | "false";
    account_id?: string | null;
    reason?: string;
    all_duplicates?: unknown[];
    primary_duplicate?: unknown;
    error?: {
        code: string;
        message: string;
    };
    plan?: Record<string, unknown>;
};

export function buildCreateAccountBody(
    input: Partial<AccountPlanOutput> & {
        account_name: string;
        account_dl: string;
    },
): AccountPlanOutput {
    return {
        check_aliases: input.check_aliases ?? true,
        account_name: input.account_name,
        account_dl: input.account_dl,
        account_alias: input.account_alias ?? input.account_name,
        decision: input.decision ?? "proceed",
        duplicate: input.duplicate ?? "false",
        dry_run: input.dry_run,
        simulated: input.simulated,
        account_id: input.account_id,
        reason: input.reason,
        actions_taken: input.actions_taken ?? [],
        all_duplicates: input.all_duplicates,
        primary_duplicate: input.primary_duplicate,
        error: input.error,
        plan: input.plan,
    };
}
