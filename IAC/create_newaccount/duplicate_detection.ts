/*
 * -----------------------------------------------------------------------------
 * duplicate_detection.ts
 * -----------------------------------------------------------------------------
 *
 * NOTE: This file was missing from the repository (index.ts imports it, but
 * no version of it exists anywhere in git history). It has been
 * reconstructed from the single call site in index.ts. The matching rules
 * below (exact name/email match against existing AWS Organizations member
 * accounts) are a reasonable default, not verified organizational policy.
 * Alias collisions are not checked here because AWS Organizations has no API
 * to list every account's IAM alias; that collision is instead surfaced by
 * AWS at IAM-alias-creation time. Review before relying on this in a real
 * account-creation flow.
 * -----------------------------------------------------------------------------
 */

import {
    listOrgAccounts,
    _normalize_simple_token,
} from "./common_helpers";

export type DuplicateMatch = {
    type: "name" | "email";
    accountId: string;
    matchedOn: string;
};

export type DuplicateDetectionResult = {
    found: boolean;
    allDuplicates: DuplicateMatch[];
    primaryDuplicate?: DuplicateMatch;
};

export async function detectDuplicates(input: {
    accountName: string;
    accountDL: string;
    accountAlias: string;
    checkAliases: boolean;
}): Promise<DuplicateDetectionResult> {
    const accounts = await listOrgAccounts();

    const normalizedName = _normalize_simple_token(input.accountName);
    const normalizedEmail = input.accountDL.trim().toLowerCase();

    const duplicates: DuplicateMatch[] = [];

    for (const account of accounts) {
        if (
            account.Id &&
            _normalize_simple_token(account.Name) === normalizedName
        ) {
            duplicates.push({
                type: "name",
                accountId: account.Id,
                matchedOn: account.Name ?? "",
            });
        }

        if (
            account.Id &&
            (account.Email ?? "").trim().toLowerCase() === normalizedEmail
        ) {
            duplicates.push({
                type: "email",
                accountId: account.Id,
                matchedOn: account.Email ?? "",
            });
        }
    }

    return {
        found: duplicates.length > 0,
        allDuplicates: duplicates,
        primaryDuplicate: duplicates[0],
    };
}
