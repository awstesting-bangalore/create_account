import * as pulumi from "@pulumi/pulumi";

import {
    _find_all_duplicates,
    _choose_primary_duplicate,
    _build_match_rows,
} from "./common_helpers";

export interface DuplicateDetectionInput {
    accountName: string;
    accountDL: string;
    accountAlias: string;
    checkAliases: boolean;
}

export interface DuplicateDetectionResult {
    found: boolean;
    primaryDuplicate: Record<string, unknown> | null;
    allDuplicates: Array<Record<string, unknown>>;
}

export async function detectDuplicates(
    input: DuplicateDetectionInput,
): Promise<DuplicateDetectionResult> {
    const duplicates =
        await _find_all_duplicates(
            input.accountName,
            input.accountDL,
            input.accountAlias,
            input.checkAliases,
        );

    pulumi.log.info(
        `[duplicate-check] ${duplicates.length} duplicate match(es) found`,
    );

    if (duplicates.length === 0) {
        return {
            found: false,
            primaryDuplicate: null,
            allDuplicates: [],
        };
    }

    const primary =
        _choose_primary_duplicate(
            duplicates,
        );

    const primaryDuplicate =
        primary
            ? {
                  type:
                      primary.type,

                  account: {
                      Id:
                          primary.account?.Id,

                      Name:
                          primary.account?.Name,

                      Email:
                          primary.account?.Email,
                  },

                  meta:
                      primary.meta,
              }
            : null;

    const allDuplicates =
        _build_match_rows(
            duplicates,
        );

    pulumi.log.warn(
        `[duplicate-check] duplicate detected: ${primary?.type ?? "unknown"}`,
    );

    return {
        found: true,
        primaryDuplicate,
        allDuplicates,
    };
}