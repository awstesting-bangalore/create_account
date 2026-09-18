import * as pulumi from "@pulumi/pulumi";
import type * as aws from "@pulumi/aws";
import {
    OrganizationsClient,
    ListAccountsCommand,
    type Account as OrgAccount,
} from "@aws-sdk/client-organizations";
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { IAMClient, ListAccountAliasesCommand } from "@aws-sdk/client-iam";

declare const process: any;

/*
 * -----------------------------------------------------
 * common_helpers/shared.ts
 * -----------------------------------------------------
 * Config, types, generic utilities, AWS-org/duplicate-detection
 * helpers, and plan-body builders shared by BOTH the dry-run
 * (simulate_createaccount) and real-run (org_createaccount) flows.
 *
 * Anything used by only one of those two flows does NOT live here
 * (e.g. retry/backoff + trust-policy logic is real-run only, and
 * fake-status persistence is dry-run only).
 */

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------
export const AWS_REGION = process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION ?? "us-east-1";
export const ORG_ASSUME_ROLE_ARN =
    process.env.ORG_ASSUME_ROLE_ARN ?? "arn:aws:iam::533702098697:role/AE-AWS-IAC";
export const MEMBER_ACCOUNT_ROLE_NAME =
    process.env.MEMBER_ACCOUNT_ROLE_NAME ?? "OrganizationAccountAccessRole";
export const MANAGEMENT_ACCOUNT_ROLE_NAME =
    process.env.MANAGEMENT_ACCOUNT_ROLE_NAME ??
    process.env.ROOT_ACCOUNT_ROLE_NAME ??
    "AE-AWS-Bootstrap-NewAccount";

export const ALIASES_CACHE_TTL = Number(process.env.ALIASES_CACHE_TTL_SECONDS ?? "300");

// DRY_RUN means the safe simulation path.
export const DRY_RUN_FLAG = parseBool(process.env.DRY_RUN, false);
export const DRY_RUN_SUCCEEDS_AFTER = Math.max(1, Number(process.env.DRY_RUN_SUCCEEDS_AFTER ?? "3"));
export const DRY_RUN_POLL_DELAY_SECONDS = Number(process.env.DRY_RUN_POLL_DELAY_SECONDS ?? "0");
export const DRY_RUN_ACCOUNT_ID = process.env.DRY_RUN_ACCOUNT_ID ?? "854838859219";

const _PREFIXES_CSV = process.env.ACCOUNT_PREFIXES ?? "aegm-,aenetworks-";
export const _PREFIXES = _PREFIXES_CSV
    .split(",")
    .map((p: string) => p.trim().toLowerCase())
    .filter((p: string) => p !== "");
export const FORBIDDEN_PREFIX = "aenetworks-";

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------
export type SimpleAccount = {
    Id?: string;
    Name?: string;
    Email?: string;
    State?: string;
    Status?: string;
};

export type DuplicateMatch = {
    type: "name" | "email" | "alias" | "core";
    account: SimpleAccount;
    meta?: Record<string, unknown> | null;
};

export type IndexEntry = {
    acct: SimpleAccount;
    nameKey: string | null;
};

export type AliasEntry = {
    account: SimpleAccount;
    aliases: string[];
    accountId?: string;
};

export type IndexBundle = {
    aliasIndex: Record<string, { entries: AliasEntry[] }>;
    nameIndex: Record<string, IndexEntry>;
    emailIndex: Record<string, SimpleAccount>;
};

export type AccountPlanOutput = {
    check_aliases: string;
    account_name: string | null;
    account_dl: string | null;
    account_alias: string | null;
    decision: "proceed" | "abort" | null;
    dry_run: string;
    duplicate: string;
    reason: string | null;
    actions_taken: string[];
    all_duplicates: Array<Record<string, unknown>>;
    primary_duplicate: Record<string, unknown> | null;
    account_id: string | null;
    account_arn: string | null;
    account_state: string | null;
    create_account_status_id: string | null;
    simulated: string;
    state?: string | null;
    requested_timestamp?: string | null;
    completed_timestamp?: string | null;
    failure_reason?: string | null;
    message?: string | null;
    last_status?: unknown;
    plan: Record<string, unknown>;
    error?: unknown;
};

// Common return contract shared by both the dry-run and real-run
// create-account entry points (createAccountDryRun / createAccountReal).
export type CreateAccountResult = {
    statusCode: number;
    body: AccountPlanOutput;
    memberAccount?: aws.organizations.Account;
    bootstrapStatus?: pulumi.Output<string>;
    confirmedActionsTaken?: pulumi.Output<string[]>;
};

// -----------------------------------------------------------------------------
// Generic helpers
// -----------------------------------------------------------------------------
export function boolToString(value: boolean | null | undefined) {
    return value ? "true" : "false";
}

export function parseBool(val: unknown, defaultValue = false): boolean {
    if (val === null || val === undefined) return defaultValue;
    if (typeof val === "boolean") return val;
    const s = String(val).trim().toLowerCase();
    return ["1", "true", "yes", "y"].includes(s);
}


export function defaultJsonReplacer(_key: string, value: any) {
    if (value instanceof Error) {
        return { name: value.name, message: value.message, stack: value.stack };
    }
    if (typeof value === "bigint") return value.toString();
    if (typeof value === "undefined") return null;
    return value;
}

export function sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

export function get_param(event: unknown, name: string, defaultValue: unknown = undefined) {
    if (!event || typeof event !== "object") return defaultValue;
    const e = event as Record<string, any>;
    if (name in e) return e[name] ?? defaultValue;
    const qsp = e.queryStringParameters ?? {};
    if (name in qsp) return qsp[name] ?? defaultValue;
    const body = e.body;
    if (body) {
        try {
            const bodyJson = typeof body === "string" ? JSON.parse(body) : body;
            return bodyJson?.[name] ?? defaultValue;
        } catch {
            return defaultValue;
        }
    }
    return defaultValue;
}

// -----------------------------------------------------------------------------
// Account-name / alias / email validation
// -----------------------------------------------------------------------------
export function sanitize_alias(value: string | undefined | null): string {
    const v = (value ?? "").trim().toLowerCase();
    return v
        .replace(/[^a-z0-9-]/g, "-")
        .replace(/-{2,}/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 63);
}

export function _normalize_simple_token(name: string | undefined | null) {
    if (!name) return null;
    let n = String(name).trim().toLowerCase();
    n = n.replace(/[^a-z0-9-]/g, "-");
    n = n.replace(/-{2,}/g, "-").replace(/^-+|-+$/g, "");
    return n || null;
}

export function _starts_with_forbidden_prefix(value: string | undefined | null) {
    const token = _normalize_simple_token(value);
    return Boolean(token && token.startsWith(FORBIDDEN_PREFIX));
}

export function _get_core_name_from_token(token: string | undefined | null) {
    if (!token) return null;
    const normalized = _normalize_simple_token(token);
    if (!normalized) return null;

    for (const p of _PREFIXES) {
        const p_clean = p.replace(/-+$/g, "");
        if (normalized.startsWith(p_clean)) {
            let core = normalized.slice(p_clean.length);
            if (core.startsWith("-")) core = core.slice(1);
            core = core.replace(/^-+|-+$/g, "");
            return core || normalized;
        }
    }

    return normalized;
}

export function _core_key(value: string | undefined | null) {
    const token = _normalize_simple_token(value);
    if (!token) return null;
    return _get_core_name_from_token(token);
}

export function _is_valid_account_name_format(name: string | undefined | null) {
    if (!name) return false;
    return Boolean(_normalize_simple_token(name));
}

export function _is_valid_email(email: string | undefined | null) {
    return typeof email === "string" && email.includes("@") && email.split("@").pop()?.includes(".") === true;
}

// -----------------------------------------------------------------------------
// AWS client bootstrap
// -----------------------------------------------------------------------------
const loginSts = new STSClient({ region: AWS_REGION });
let _orgSts: STSClient | undefined;
let _org: OrganizationsClient | undefined;
let _orgAccountId: string | undefined;
let _pulumiIacRoleArn: string | undefined;

function toIamRoleArnFromCallerIdentity(identity: { Arn?: string | undefined; Account?: string | undefined }): string {
    const arn = identity.Arn ?? "";
    const account = identity.Account ?? "";

    const assumedRoleMatch = arn.match(/^arn:aws:sts::(\d+):assumed-role\/([^/]+)\/.*$/);
    if (assumedRoleMatch) {
        return `arn:aws:iam::${assumedRoleMatch[1]}:role/${assumedRoleMatch[2]}`;
    }

    const iamRoleMatch = arn.match(/^arn:aws:iam::(\d+):role\/.+$/);
    if (iamRoleMatch) {
        return arn;
    }

    if (account) {
        return `arn:aws:iam::${account}:role/AE-AWS-IAC`;
    }

    throw new Error(`Unable to derive IAM role ARN from caller identity: ${arn}`);
}

/**
 * Assumes ORG_ASSUME_ROLE_ARN in the root/management account and caches the
 * resulting clients + identity info. Must be called before any of the
 * getOrg-family/list_all_accounts/assume_role/build_indexes_* helpers below,
 * and before real_run's bootstrap_new_account_role_trust.
 */
export async function buildAwsClients(): Promise<void> {
    const callerIdentity = await loginSts.send(new GetCallerIdentityCommand({}));
    console.log("[caller-identity]", JSON.stringify(callerIdentity));
    _pulumiIacRoleArn = toIamRoleArnFromCallerIdentity(callerIdentity);

    const baseCreds = await loginSts.send(
        new AssumeRoleCommand({
            RoleArn: ORG_ASSUME_ROLE_ARN,
            RoleSessionName: "org-access",
        }),
    );

    if (!baseCreds.Credentials) {
        throw new Error("Failed to assume organization access role");
    }

    const assumedCreds = {
        accessKeyId: baseCreds.Credentials.AccessKeyId!,
        secretAccessKey: baseCreds.Credentials.SecretAccessKey!,
        sessionToken: baseCreds.Credentials.SessionToken!,
    };

    _orgSts = new STSClient({ region: AWS_REGION, credentials: assumedCreds });
    _org = new OrganizationsClient({ region: AWS_REGION, credentials: assumedCreds });

    const orgIdentity = await _orgSts.send(new GetCallerIdentityCommand({}));
    _orgAccountId = orgIdentity.Account ?? undefined;
    console.log("[org-caller-identity]", JSON.stringify(orgIdentity));
}

// Accessors used by both flows (real_run also needs orgSts/orgAccountId/
// pulumiIacRoleArn for the trust-policy bootstrap step). Centralizing the
// "has buildAwsClients() run yet?" check here avoids repeating the same
// null-guard in every caller.
export function getOrg(): OrganizationsClient {
    if (!_org) throw new Error("Organizations client is not initialized; call buildAwsClients() first");
    return _org;
}

export function getOrgSts(): STSClient {
    if (!_orgSts) throw new Error("orgSts is not initialized; call buildAwsClients() first");
    return _orgSts;
}

export function getOrgAccountId(): string {
    if (!_orgAccountId) throw new Error("Organization account id is not available; call buildAwsClients() first");
    return _orgAccountId;
}

export function getPulumiIacRoleArn(): string {
    if (!_pulumiIacRoleArn) {
        throw new Error("Could not determine the Pulumi IAC role ARN from caller identity; call buildAwsClients() first");
    }
    return _pulumiIacRoleArn;
}

// -----------------------------------------------------------------------------
// Accounts listing and duplicate indexing
// -----------------------------------------------------------------------------
export async function list_all_accounts() {
    const org = getOrg();
    const accounts: SimpleAccount[] = [];
    let next_token: string | undefined;
    while (true) {
        const response = await org.send(new ListAccountsCommand(next_token ? { NextToken: next_token } : {}));
        accounts.push(
            ...(response.Accounts ?? []).map((a: OrgAccount) => ({
                Id: a.Id,
                Name: a.Name,
                Email: a.Email,
                State: (a as any).State,
                Status: a.Status,
            })),
        );
        next_token = response.NextToken;
        if (!next_token) break;
    }
    return accounts;
}

export async function find_account_by_id(accountId: string): Promise<SimpleAccount | null> {
    const normalizedAccountId = String(accountId ?? "").trim();
    if (!/^\d{12}$/.test(normalizedAccountId)) {
        throw new Error(`Invalid AWS account ID '${accountId}'`);
    }

    const accounts = await list_all_accounts();
    return accounts.find((account) => account.Id === normalizedAccountId) ?? null;
}

export async function assume_role(account_id: string, role_name = MEMBER_ACCOUNT_ROLE_NAME, session_name = "account-bootstrap") {
    const orgSts = getOrgSts();
    const resp = await orgSts.send(
        new AssumeRoleCommand({
            RoleArn: `arn:aws:iam::${account_id}:role/${role_name}`,
            RoleSessionName: session_name,
        }),
    );
    return resp.Credentials;
}

async function try_get_account_aliases_for_account(acct: SimpleAccount) {
    const acct_id = acct.Id;
    if (!acct_id) return null;
    try {
        const creds = await assume_role(acct_id, MEMBER_ACCOUNT_ROLE_NAME, "alias-check");
        if (!creds?.AccessKeyId || !creds.SecretAccessKey || !creds.SessionToken) return null;
        const iam = new IAMClient({
            region: AWS_REGION,
            credentials: {
                accessKeyId: creds.AccessKeyId,
                secretAccessKey: creds.SecretAccessKey,
                sessionToken: creds.SessionToken,
            },
        });
        const resp = await iam.send(new ListAccountAliasesCommand({}));
        return resp.AccountAliases ?? [];
    } catch (e) {
        pulumi.log.warn(`[alias-check] failed for ${acct_id}: ${String(e)}`);
        return null;
    }
}

const _index_cache: {
    built_at: number;
    alias_index: IndexBundle["aliasIndex"] | null;
    name_index: IndexBundle["nameIndex"] | null;
    email_index: IndexBundle["emailIndex"] | null;
} = {
    built_at: 0,
    alias_index: null,
    name_index: null,
    email_index: null,
};

export async function build_indexes_parallel() {
    const now = Date.now() / 1000;
    if (
        _index_cache.alias_index &&
        _index_cache.name_index &&
        _index_cache.email_index &&
        now - _index_cache.built_at < ALIASES_CACHE_TTL
    ) {
        return [
            _index_cache.alias_index,
            _index_cache.name_index,
            _index_cache.email_index,
        ] as const;
    }

    const accounts = await list_all_accounts();
    const alias_index: IndexBundle["aliasIndex"] = {};
    const name_index: IndexBundle["nameIndex"] = {};
    const email_index: IndexBundle["emailIndex"] = {};

    for (const acct of accounts) {
        try {
            const nameKey = _normalize_simple_token(acct.Name);
            if (nameKey) {
                name_index[nameKey] = { acct, nameKey };
            }
            const em = (acct.Email ?? "").trim().toLowerCase();
            if (em) {
                email_index[em] = acct;
            }
        } catch {
            // ignore per-account indexing failures
        }

        const aliases = await try_get_account_aliases_for_account(acct);
        if (!aliases || aliases.length === 0) continue;
        for (const a of aliases) {
            const a_norm = (a ?? "").trim().toLowerCase();
            if (!a_norm) continue;
            alias_index[a_norm] ??= { entries: [] };
            alias_index[a_norm].entries.push({ account: acct, aliases, accountId: acct.Id });
        }
    }

    _index_cache.built_at = Date.now() / 1000;
    _index_cache.alias_index = alias_index;
    _index_cache.name_index = name_index;
    _index_cache.email_index = email_index;

    pulumi.log.info(
        `[index-build] Index table has been built\n` +
        `account names = ${Object.keys(name_index).length}\n` +
        `account emails = ${Object.keys(email_index).length}\n` +
        `account aliases = ${Object.keys(alias_index).length}`,
    );
    return [alias_index, name_index, email_index] as const;
}

async function _cached_indexes() {
    return build_indexes_parallel();
}

export async function _find_all_duplicates(
    account_name: string | null = null,
    email: string | null = null,
    account_alias: string | null = null,
    check_aliases = false,
) {
    const [alias_index, name_index, email_index] = await _cached_indexes();
    const results: DuplicateMatch[] = [];
    const seen = new Set<string>();

    const name_key = _normalize_simple_token(account_name);
    const email_key = (email ?? "").trim().toLowerCase() || null;
    const alias_input_key = _normalize_simple_token(account_alias);

    const append_if_new = (typ: DuplicateMatch["type"], acct: SimpleAccount, meta: Record<string, unknown> | null = null) => {
        const unique = acct.Id || acct.Email || acct.Name || "unknown";
        const marker = `${typ}:${unique}`;
        if (seen.has(marker)) return;
        seen.add(marker);
        results.push({ type: typ, account: acct, meta });
    };

    if (name_key && name_index && name_key in name_index) {
        append_if_new("name", name_index[name_key].acct, { matched_name: name_key });
    }
    if (email_key && email_index && email_key in email_index) {
        append_if_new("email", email_index[email_key], null);
    }

    if (check_aliases && alias_index) {
        if (name_key && name_key in alias_index && alias_index[name_key].entries?.length) {
            append_if_new("alias", alias_index[name_key].entries[0].account, { matched_alias: name_key });
        }
        if (email_key && email_key in alias_index && alias_index[email_key].entries?.length) {
            append_if_new("alias", alias_index[email_key].entries[0].account, { matched_alias: email_key });
        }
        if (alias_input_key && alias_input_key in alias_index && alias_index[alias_input_key].entries?.length) {
            append_if_new("alias", alias_index[alias_input_key].entries[0].account, { matched_alias: alias_input_key });
        }
    }

    const new_core_keys = new Set<string>();
    for (const raw of [account_name, account_alias]) {
        const ck = _core_key(raw);
        if (ck) new_core_keys.add(ck);
    }

    if (new_core_keys.size > 0) {
        if (name_index) {
            for (const entry of Object.values(name_index)) {
                const existing_core = _core_key(entry.nameKey);
                if (existing_core && new_core_keys.has(existing_core)) {
                    if (entry.nameKey !== _normalize_simple_token(account_name) && entry.nameKey !== _normalize_simple_token(account_alias)) {
                        append_if_new("core", entry.acct, {
                            existing_core,
                            new_core: Array.from(new_core_keys).sort(),
                        });
                    }
                }
            }
        }

        if (alias_index) {
            for (const [alias_key, meta] of Object.entries(alias_index)) {
                const existing_core = _core_key(alias_key);
                if (existing_core && new_core_keys.has(existing_core)) {
                    if (alias_key !== _normalize_simple_token(account_name) && alias_key !== _normalize_simple_token(account_alias)) {
                        const entries = meta.entries ?? [];
                        if (entries.length) {
                            append_if_new("core", entries[0].account, {
                                existing_core,
                                new_core: Array.from(new_core_keys).sort(),
                            });
                        }
                    }
                }
            }
        }
    }

    console.log("[dup-check] name_key=", name_key, "alias_input_key=", alias_input_key, "email_key=", email_key);
    console.log(
        "[dup-check] counts: alias_index=", alias_index ? Object.keys(alias_index).length : 0,
        "name_index=", name_index ? Object.keys(name_index).length : 0,
        "email_index=", email_index ? Object.keys(email_index).length : 0,
    );
    console.log("[dup-check] new_core_keys=", Array.from(new_core_keys).sort());

    return results;
}

export function _choose_primary_duplicate(dups: DuplicateMatch[]) {
    if (!dups || dups.length === 0) return null;
    const priority: DuplicateMatch["type"][] = ["name", "alias", "core", "email"];
    for (const p of priority) {
        const found = dups.find((d) => d.type === p);
        if (found) return found;
    }
    return dups[0];
}

export function _build_match_rows(dups: DuplicateMatch[]) {
    return (dups ?? []).map((d) => ({
        match_type: d.type,
        account_number: d.account?.Id ?? null,
        account_name: d.account?.Name ?? null,
        account_dl: d.account?.Email ?? null,
        meta: d.meta ?? null,
    }));
}

// -----------------------------------------------------------------------------
// Plan / response-body builders
// -----------------------------------------------------------------------------
export function makeEmptyPlan(): AccountPlanOutput {
    return {
        check_aliases: "true",
        account_name: null,
        account_dl: null,
        account_alias: null,
        decision: null,
        dry_run: boolToString(DRY_RUN_FLAG),
        duplicate: "false",
        reason: null,
        actions_taken: [],
        all_duplicates: [],
        primary_duplicate: null,
        account_id: null,
        account_arn: null,
        account_state: null,
        create_account_status_id: null,
        simulated: boolToString(DRY_RUN_FLAG),
        plan: {},
    };
}

export function buildPlanOutput(params: Partial<AccountPlanOutput> & { plan?: Record<string, unknown> }): AccountPlanOutput {
    const base = makeEmptyPlan();
    return {
        ...base,
        ...params,
        actions_taken: params.actions_taken ?? base.actions_taken,
        all_duplicates: params.all_duplicates ?? base.all_duplicates,
        primary_duplicate: params.primary_duplicate ?? base.primary_duplicate,
        plan: params.plan ?? base.plan,
    };
}

export function buildCreateAccountBody(
    params: Record<string, any> & {
        plan: Record<string, unknown>;
    },
): AccountPlanOutput {
    const toStr = (
        v: any,
        fallback: string,
    ) => {
        if (
            v === null ||
            v === undefined
        ) {
            return fallback;
        }

        if (typeof v === "boolean") {
            return boolToString(v);
        }

        return String(v);
    };

    return buildPlanOutput({
        check_aliases:
            toStr(
                params.check_aliases,
                "true",
            ),
        account_name:
            params.account_name ?? null,
        account_dl:
            params.account_dl ?? null,
        account_alias:
            params.account_alias ?? null,
        decision:
            params.decision ?? null,
        dry_run:
            toStr(
                params.dry_run,
                boolToString(
                    DRY_RUN_FLAG,
                ),
            ),
        duplicate:
            toStr(
                params.duplicate,
                "false",
            ),
        reason:
            params.reason ?? null,
        actions_taken:
            params.actions_taken ?? [],
        all_duplicates:
            params.all_duplicates ?? [],
        primary_duplicate:
            params.primary_duplicate ??
            null,
        account_id:
            params.account_id ?? null,
        account_arn:
            params.account_arn ?? null,
        account_state:
            params.account_state ?? null,
        create_account_status_id:
            params.create_account_status_id ??
            null,
        simulated:
            toStr(
                params.simulated,
                boolToString(
                    DRY_RUN_FLAG,
                ),
            ),
        state:
            params.state ?? null,
        requested_timestamp:
            params.requested_timestamp ??
            null,
        completed_timestamp:
            params.completed_timestamp ??
            null,
        failure_reason:
            params.failure_reason ?? null,
        message:
            params.message ?? null,
        last_status:
            params.last_status,
        plan:
            params.plan,
        error:
            params.error,
    });
}