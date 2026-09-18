import {
    listAllAccounts,
    _normalize_simple_token,
    type OrganizationsAccountSummary,
} from "./common_helpers";

/*
 * -----------------------------------------------------------------------------
 * RECONSTRUCTED MODULE
 * -----------------------------------------------------------------------------
 * This file did not exist in the repository (it was referenced by index.ts's
 * imports but never committed). It has been reconstructed from the single
 * call site in index.ts.
 *
 * Scope: checks the organization's existing accounts for a name or email
 * match before creating a new one. Alias-level duplicate checking across
 * member accounts is NOT implemented here, since verifying an IAM account
 * alias requires assuming a role into every existing member account, which
 * this component has no mandate to do. AWS Organizations' own CreateAccount
 * API independently rejects duplicate emails, so email-based duplicates are
 * still caught even if this pre-check were ever bypassed.
 * -----------------------------------------------------------------------------
 */

export interface DuplicateMatch {
    type: "name" | "email";
    accountId?: string;
    accountName?: string;
    accountEmail?: string;
}

export interface DuplicateDetectionResult {
    found: boolean;
    allDuplicates: DuplicateMatch[];
    primaryDuplicate?: DuplicateMatch;
}

export interface DuplicateDetectionInput {
    accountName: string;
    accountDL: string;
    accountAlias?: string;
    checkAliases?: boolean;
}

export async function detectDuplicates(
    input: DuplicateDetectionInput,
): Promise<DuplicateDetectionResult> {
    const expectedName = _normalize_simple_token(input.accountName);
    const expectedEmail = input.accountDL.trim().toLowerCase();

    const accounts: OrganizationsAccountSummary[] = await listAllAccounts();

    const duplicates: DuplicateMatch[] = [];

    for (const account of accounts) {
        const actualEmail = (account.Email ?? "").trim().toLowerCase();
        if (actualEmail && actualEmail === expectedEmail) {
            duplicates.push({
                type: "email",
                accountId: account.Id,
                accountName: account.Name,
                accountEmail: account.Email,
            });
            continue;
        }

        const actualName = _normalize_simple_token(account.Name);
        if (actualName && actualName === expectedName) {
            duplicates.push({
                type: "name",
                accountId: account.Id,
                accountName: account.Name,
                accountEmail: account.Email,
            });
        }
    }

    // Email collisions are the strongest signal (AWS enforces email
    // uniqueness org-wide), so prefer reporting those first.
    const primaryDuplicate =
        duplicates.find((d) => d.type === "email") ?? duplicates[0];

    return {
        found: duplicates.length > 0,
        allDuplicates: duplicates,
        primaryDuplicate,
    };
}
