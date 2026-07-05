import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const profilePageSource = readFileSync(
  join(process.cwd(), "app/profile/page.tsx"),
  "utf8",
).replace(/\r\n/g, "\n");

describe("profile workspace duplication contract", () => {
  it("keeps One dashboard workspaces out of the Profile landing screen", () => {
    expect(profilePageSource).not.toContain('<SettingsGroup title="Workspaces">');
    expect(profilePageSource).not.toMatch(
      /const\s+openMyDataPanel\s*=\s*\(\)\s*=>\s*router\.push\(\s*ROUTES\.PKM\s*\);/,
    );
    expect(profilePageSource).not.toMatch(
      /const\s+openAccessPanel\s*=\s*\(\)\s*=>\s*router\.push\(\s*ROUTES\.CONSENTS\s*\);/,
    );
    expect(profilePageSource).not.toMatch(
      /const\s+openGmailPanel\s*=\s*\(\)\s*=>\s*router\.push\(\s*ROUTES\.GMAIL\s*\);/,
    );
    expect(profilePageSource).toContain('<SettingsGroup title="Settings">');
    expect(profilePageSource).not.toContain("myDataRootBadge");
    expect(profilePageSource).not.toContain("accessRootBadge");
    expect(profilePageSource).not.toContain("Data loaded partially");
    expect(profilePageSource).not.toContain("Access loaded partially");
    expect(profilePageSource).not.toContain("Unlock to review sync and receipts.");
    expect(profilePageSource).not.toContain("Unlock to review email requests.");
  });

  it("loads legacy workspace data only for legacy workspace panels", () => {
    expect(profilePageSource).toContain("function profileRouteNeedsWorkspaceData");
    expect(profilePageSource).toMatch(
      /return\s+panel\s*===\s*['"]my-data['"]\s*\|\|\s*panel\s*===\s*['"]access['"];/,
    );
    expect(profilePageSource).toMatch(
      /enabled:\s*Boolean\(\s*user\?\.uid\s*\)\s*&&\s*!authLoading\s*&&\s*activePanel\s*===\s*['"]gmail['"]/,
    );
  });
});
