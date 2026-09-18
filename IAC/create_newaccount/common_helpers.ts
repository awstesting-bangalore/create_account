import * as pulumi from "@pulumi/pulumi";
import { STSClient } from "@aws-sdk/client-sts";
import {
    OrganizationsClient,
    DescribeAccountCommand,
    ListAccountsCommand,
} from "@aws-sdk/client-organizations";

/*
 * -----------------------------------------------------------------------------
 * RECONSTRUCTED MODULE
 * -----------------------------------------------------------------------------
 * This file did not exist in the repository (it was referenced by index.ts's
 * imports but never committed). It has been reconstructed from the call
 * sites in index.ts. Review the assumptions below against your org's actual
 * IAM naming conventions before relying on this in production:
 *
 * - MEMBER_ACCOUNT_ROLE_NAME / MANAGEMENT_ACCOUNT_ROLE_NAME default to the
 *   AWS-standard "OrganizationAccountAccessRole" and can be overridden via
 *   environment variables so no incorrect role name is silently baked in.
 * - getOrgAccountId() / getPulumiIacRoleArn() intentionally throw rather than
 *   guess a value, since a wrong org account ID or role ARN could route the
 *   trust-policy update at the wrong account/principal.
 * -----------------------------------------------------------------------------
 */

// -----------------------------------------------------------------------------
// Role name constants
// -----------------------------------------------------------------------------

export const MEMBER_ACCOUNT_ROLE_NAME: string =
    process.env.AE_MEMBER_ACCOUNT_ROLE_NAME ??
    "OrganizationAccountAccessRole";

export const MANAGEMENT_ACCOUNT_ROLE_NAME: string =
    process.env.AE_MANAGEMENT_ACCOUNT_ROLE_NAME ??
    "OrganizationAccountAccessRole";

// -----------------------------------------------------------------------------
// AWS client helpers
// -----------------------------------------------------------------------------

let orgSts: STSClient | undefined;
let orgClient: OrganizationsClient | undefined;

const region =
    process.env.AWS_REGION ??
    process.env.AWS_DEFAULT_REGION ??
    "us-east-1";

/**
 * Returns a cached STS client built from the ambient (default) AWS
 * credential chain, matching Stage 2's expectation that the default
 * provider assumes the target account's OrganizationAccountAccessRole.
 */
export function getOrgSts(): STSClient {
    if (!orgSts) {
        orgSts = new STSClient({ region });
    }
    return orgSts;
}

/**
 * Returns the AWS Organizations management/org account ID. Sourced from
 * config rather than guessed, since a wrong value would misdirect the
 * cross-account trust update.
 */
export function getOrgAccountId(): string {
    const accountId = process.env.AE_ORG_ACCOUNT_ID;
    if (!accountId) {
        throw new pulumi.RunError(
            "AE_ORG_ACCOUNT_ID is not set. Set it to the AWS Organizations " +
            "management account ID before running Stage 2 trust updates.",
        );
    }
    return accountId;
}

/**
 * Returns the ARN of the IAM role/principal that should be granted
 * sts:AssumeRole trust in newly created member accounts (referred to as
 * "AE-AWS-IAC" elsewhere in this component).
 */
export function getPulumiIacRoleArn(): string {
    const roleArn = process.env.AE_PULUMI_IAC_ROLE_ARN;
    if (!roleArn) {
        throw new pulumi.RunError(
            "AE_PULUMI_IAC_ROLE_ARN is not set. Set it to the ARN of the " +
            "'AE-AWS-IAC' principal that should be trusted by new member accounts.",
        );
    }
    return roleArn;
}

/**
 * Lazily initializes the shared AWS Organizations client used for account
 * lookups. Safe to call repeatedly.
 */
export async function buildAwsClients(): Promise<void> {
    if (!orgClient) {
        orgClient = new OrganizationsClient({ region });
    }
}

function requireOrgClient(): OrganizationsClient {
    if (!orgClient) {
        throw new pulumi.RunError(
            "AWS Organizations client not initialized; call buildAwsClients() first.",
        );
    }
    return orgClient;
}

// -----------------------------------------------------------------------------
// Account lookup
// -----------------------------------------------------------------------------

export interface OrganizationsAccountSummary {
    Id?: string;
    Name?: string;
    Email?: string;
    Status?: string;
    State?: string;
}

/**
 * Looks up an existing AWS Organizations account by ID. Returns undefined
 * if the account does not exist or cannot be described.
 */
export async function find_account_by_id(
    accountId: string,
): Promise<OrganizationsAccountSummary | undefined> {
    const client = requireOrgClient();

    try {
        const response = await client.send(
            new DescribeAccountCommand({ AccountId: accountId }),
        );

        if (!response.Account) {
            return undefined;
        }

        return {
            Id: response.Account.Id,
            Name: response.Account.Name,
            Email: response.Account.Email,
            Status: response.Account.Status,
        };
    } catch (err) {
        const name = (err as any)?.name ?? "";
        if (name === "AccountNotFoundException") {
            return undefined;
        }
        throw err;
    }
}

/**
 * Lists every account in the organization (paginated), for duplicate
 * detection. Read-only; does not mutate any AWS state.
 */
export async function listAllAccounts(): Promise<OrganizationsAccountSummary[]> {
    const client = requireOrgClient();
    const accounts: OrganizationsAccountSummary[] = [];
    let nextToken: string | undefined;

    do {
        const response = await client.send(
            new ListAccountsCommand({ NextToken: nextToken }),
        );

        for (const account of response.Accounts ?? []) {
            accounts.push({
                Id: account.Id,
                Name: account.Name,
                Email: account.Email,
                Status: account.Status,
            });
        }

        nextToken = response.NextToken;
    } while (nextToken);

    return accounts;
}

// -----------------------------------------------------------------------------
// Small pure helpers
// -----------------------------------------------------------------------------

export function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

export function parseBool(
    value: unknown,
    defaultValue: boolean,
): boolean {
    if (value === undefined || value === null || value === "") {
        return defaultValue;
    }
    if (typeof value === "boolean") {
        return value;
    }
    const normalized = String(value).trim().toLowerCase();
    if (["true", "1", "yes", "y"].includes(normalized)) {
        return true;
    }
    if (["false", "0", "no", "n"].includes(normalized)) {
        return false;
    }
    return defaultValue;
}

const FORBIDDEN_PREFIX = "aenetworks-";

/**
 * AWS account names/aliases in this org must not start with the internal
 * "aenetworks-" prefix (reserved), per the validation error messages in
 * index.ts.
 */
export function _starts_with_forbidden_prefix(value: string): boolean {
    return value.trim().toLowerCase().startsWith(FORBIDDEN_PREFIX);
}

/**
 * Lowercases, trims, and strips everything but letters/digits so that
 * cosmetic differences (spacing, punctuation, casing) don't cause a false
 * mismatch when comparing an expected vs. actual account name.
 */
export function _normalize_simple_token(
    value: string | undefined | null,
): string {
    return (value ?? "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");
}

/**
 * An account name is considered valid if it is non-empty, within AWS
 * Organizations' 50-character limit, and normalizes to a non-empty token.
 */
export function _is_valid_account_name_format(value: string): boolean {
    const trimmed = value.trim();
    if (trimmed.length === 0 || trimmed.length > 50) {
        return false;
    }
    return _normalize_simple_token(trimmed).length > 0;
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function _is_valid_email(value: string): boolean {
    return EMAIL_PATTERN.test(value.trim());
}

/**
 * Sanitizes a proposed account alias to satisfy AWS IAM account alias
 * constraints: 3-63 chars, lowercase letters/digits/hyphens, must start
 * and end with a letter or digit, no consecutive hyphens.
 */
export function sanitize_alias(alias: string): string {
    let sanitized = alias
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9-]+/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-+/, "")
        .replace(/-+$/, "");

    if (sanitized.length === 0) {
        sanitized = "account";
    }

    if (sanitized.length < 3) {
        sanitized = sanitized.padEnd(3, "0");
    }

    if (sanitized.length > 63) {
        sanitized = sanitized.slice(0, 63).replace(/-+$/, "");
    }

    return sanitized;
}

// -----------------------------------------------------------------------------
// Account plan output builder
// -----------------------------------------------------------------------------

export interface AccountPlanOutput {
    check_aliases: string;
    account_name: string;
    account_dl: string;
    account_alias: string;
    decision: string;
    dry_run: string;
    duplicate: string;
    reason: string;
    account_id: string | null;
    simulated: string;
    actions_taken: string[];
    error?: { code: string; message: string };
    all_duplicates?: unknown[];
    primary_duplicate?: unknown;
    plan: Record<string, unknown>;
}

type AccountPlanInput = {
    check_aliases?: unknown;
    account_name?: string;
    account_dl?: string;
    account_alias?: string;
    decision?: string;
    dry_run?: unknown;
    duplicate?: unknown;
    reason?: string;
    account_id?: string | null;
    simulated?: unknown;
    actions_taken?: string[];
    error?: { code: string; message: string };
    all_duplicates?: unknown[];
    primary_duplicate?: unknown;
    plan?: Record<string, unknown>;
};

/**
 * Normalizes the assorted partial plan objects built throughout index.ts
 * into the full AccountPlanOutput shape expected by the component's
 * registered outputs.
 */
export function buildCreateAccountBody(
    input: AccountPlanInput,
): AccountPlanOutput {
    return {
        check_aliases: String(
            input.check_aliases === undefined ? true : input.check_aliases,
        ),
        account_name: input.account_name ?? "",
        account_dl: input.account_dl ?? "",
        account_alias: input.account_alias ?? "",
        decision: input.decision ?? "proceed",
        dry_run: String(
            input.dry_run === undefined
                ? pulumi.runtime.isDryRun()
                : input.dry_run,
        ),
        duplicate: String(
            input.duplicate === undefined ? false : input.duplicate,
        ),
        reason: input.reason ?? "",
        account_id: input.account_id ?? null,
        simulated: String(
            input.simulated === undefined ? false : input.simulated,
        ),
        actions_taken: input.actions_taken ?? [],
        error: input.error,
        all_duplicates: input.all_duplicates,
        primary_duplicate: input.primary_duplicate,
        plan: input.plan ?? {},
    };
}
