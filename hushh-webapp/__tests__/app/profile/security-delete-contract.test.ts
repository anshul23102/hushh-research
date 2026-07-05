import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const profilePageSource = readFileSync(
  join(process.cwd(), "app/profile/page.tsx"),
  "utf8",
).replace(/\r\n/g, "\n");

describe("profile security deletion contract", () => {
  it("keeps Security reachable before vault creation", () => {
    expect(profilePageSource).toMatch(
      /vaultAccess\.needsVaultCreation\s*&&\s*panel\s*!==\s*['"]security['"]/,
    );
  });

  it("allows no-vault account deletion without forcing vault creation", () => {
    expect(profilePageSource).toContain("if (!nextHasVault)");
    expect(profilePageSource).toContain("setShowDeleteConfirm(true);");
    expect(profilePageSource).toContain(
      "No vault exists yet. This deletes cloud-linked account records.",
    );
    expect(profilePageSource).not.toContain("Create vault to delete account");
  });

  it("keeps the delete-everything confirmation button mobile-safe", () => {
    expect(profilePageSource).toMatch(/['"]Yes,\s*Delete\s*Everything['"]/);
    expect(profilePageSource).toContain("!whitespace-normal");
    expect(profilePageSource).toContain("min-h-10");
    expect(profilePageSource).toContain("sm:min-w-[12rem]");
  });
});
