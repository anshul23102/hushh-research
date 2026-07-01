import { describe, expect, it, vi } from "vitest";

const mockSessionStorage = vi.hoisted(() => ({
  store: {} as Record<string, string>,
}));

vi.mock("@/lib/utils/session-storage", () => ({
  setSessionItem: vi.fn((key: string, value: string) => {
    mockSessionStorage.store[key] = value;
  }),
  getSessionItem: vi.fn((key: string) => mockSessionStorage.store[key] || null),
  removeSessionItem: vi.fn((key: string) => {
    delete mockSessionStorage.store[key];
  }),
}));

import {
  resolveGmailConnectionPresentation,
  resolveGmailLastUpdatedLabel,
  resolveGmailStatusSummary,
  resolveGmailSyncFeedback,
  sanitizeGmailUserMessage,
  buildProfileGmailReturnPath,
  stashProfileGmailReturnStatus,
  consumeProfileGmailReturnStatus,
  isRecoverableGmailOAuthReplayError,
  resolveGmailConnectedLabel,
} from "@/lib/profile/mail-flow";

describe("resolveGmailSyncFeedback", () => {
  it("keeps non-terminal sync states out of the success path", () => {
    expect(
      resolveGmailSyncFeedback({
        configured: true,
        connected: true,
        status: "connected",
        scope_csv: "gmail.readonly",
        last_sync_status: "running",
        auto_sync_enabled: true,
        revoked: false,
        latest_run: {
          run_id: "run-1",
          user_id: "user-123",
          trigger_source: "manual",
          status: "running",
          listed_count: 4,
          filtered_count: 2,
          synced_count: 1,
          extracted_count: 1,
          duplicates_dropped: 0,
          extraction_success_rate: 1,
        },
      }),
    ).toEqual({
      kind: "message",
      message: "We're still syncing your receipts.",
    });
  });

  it("keeps failed sync states on the error path", () => {
    expect(
      resolveGmailSyncFeedback({
        configured: true,
        connected: true,
        status: "connected",
        scope_csv: "gmail.readonly",
        last_sync_status: "failed",
        last_sync_error: "Mailbox locked.",
        auto_sync_enabled: true,
        revoked: false,
      }),
    ).toEqual({
      kind: "error",
      message: "Mailbox locked.",
    });
  });

  it("uses success only for completed sync states", () => {
    expect(
      resolveGmailSyncFeedback({
        configured: true,
        connected: true,
        status: "connected",
        scope_csv: "gmail.readonly",
        last_sync_status: "completed",
        auto_sync_enabled: true,
        revoked: false,
      }),
    ).toEqual({
      kind: "success",
      message: "Receipts updated.",
    });
  });
});

describe("resolveGmailConnectionPresentation", () => {
  it("uses an explicit loading state before connector status resolves", () => {
    expect(
      resolveGmailConnectionPresentation({
        status: null,
        loading: true,
        errorText: null,
      }),
    ).toMatchObject({
      state: "loading",
      badgeLabel: "Checking",
      isConnected: false,
    });
  });

  it("surfaces sync failures as needs-attention while staying connected", () => {
    expect(
      resolveGmailConnectionPresentation({
        status: {
          configured: true,
          connected: true,
          status: "connected",
          google_email: "dev@hushh.ai",
          scope_csv: "gmail.readonly",
          last_sync_status: "failed",
          last_sync_error: "Mailbox locked.",
          auto_sync_enabled: true,
          revoked: false,
        },
      }),
    ).toMatchObject({
      state: "sync_failed",
      badgeLabel: "Try again",
      isConnected: true,
    });
  });

  it("treats fetch errors as needs-attention instead of disconnected", () => {
    expect(
      resolveGmailConnectionPresentation({
        status: null,
        loading: false,
        errorText: "Failed to load Gmail connector state.",
      }),
    ).toMatchObject({
      state: "sync_failed",
      badgeLabel: "Try again",
      isConnected: false,
    });
  });

  it("keeps passive backfill in the connected background state instead of blocking sync", () => {
    expect(
      resolveGmailConnectionPresentation({
        status: {
          configured: true,
          connected: true,
          status: "connected",
          google_email: "dev@hushh.ai",
          scope_csv: "gmail.readonly",
          last_sync_status: "running",
          auto_sync_enabled: true,
          revoked: false,
          sync_state: "backfill_running",
          latest_run: {
            run_id: "run-backfill",
            user_id: "user-1",
            trigger_source: "backfill",
            sync_mode: "backfill",
            status: "running",
            listed_count: 1,
            filtered_count: 1,
            synced_count: 1,
            extracted_count: 1,
            duplicates_dropped: 0,
            extraction_success_rate: 1,
          },
        },
      }),
    ).toMatchObject({
      state: "connected_backfill_running",
      badgeLabel: "Connected",
      isConnected: true,
    });
  });

  it("does not keep completed backfill runs in the background running state", () => {
    expect(
      resolveGmailConnectionPresentation({
        status: {
          configured: true,
          connected: true,
          status: "connected",
          google_email: "dev@hushh.ai",
          scope_csv: "gmail.readonly",
          last_sync_status: "completed",
          auto_sync_enabled: true,
          revoked: false,
          sync_state: "backfill_running",
          latest_run: {
            run_id: "run-backfill-complete",
            user_id: "user-1",
            trigger_source: "backfill",
            sync_mode: "backfill",
            status: "completed",
            listed_count: 4,
            filtered_count: 3,
            synced_count: 3,
            extracted_count: 3,
            duplicates_dropped: 0,
            extraction_success_rate: 1,
          },
        },
      }),
    ).toMatchObject({
      state: "connected",
      badgeLabel: "Connected",
      latestSyncBadge: "completed",
      isConnected: true,
    });
  });
});

describe("sanitizeGmailUserMessage", () => {
  it("hides raw backend error details", () => {
    expect(
      sanitizeGmailUserMessage(
        "DB operation failed [<raw_sql>.execute_raw]: (psycopg2.OperationalError) server closed the connection unexpectedly",
        {
          fallback:
            "Something went wrong while syncing your emails. Please try again in a moment.",
        },
      ),
    ).toBe(
      "Something went wrong while syncing your emails. Please try again in a moment.",
    );
  });

  it("hides proxy timeout and connection errors", () => {
    expect(
      sanitizeGmailUserMessage("fetch failed: connection refused", {
        fallback:
          "Something went wrong while syncing your emails. Please try again in a moment.",
      }),
    ).toBe(
      "Something went wrong while syncing your emails. Please try again in a moment.",
    );
  });
});

describe("resolveGmailStatusSummary", () => {
  it("returns a calm success summary for connected Gmail", () => {
    expect(
      resolveGmailStatusSummary({
        status: {
          configured: true,
          connected: true,
          status: "connected",
          google_email: "dev@hushh.ai",
          scope_csv: "gmail.readonly",
          last_sync_status: "completed",
          last_sync_at: "2026-04-03T10:00:00.000Z",
          auto_sync_enabled: true,
          revoked: false,
        },
      }),
    ).toMatchObject({
      tone: "success",
      title: "Receipts are up to date",
      detail: "Connected to dev@hushh.ai",
    });
  });

  it("formats last updated labels directly from raw timestamps", () => {
    const label = resolveGmailLastUpdatedLabel({
      configured: true,
      connected: true,
      status: "connected",
      google_email: "dev@hushh.ai",
      scope_csv: "gmail.readonly",
      last_sync_status: "completed",
      last_sync_at: new Date(Date.now() - 60_000).toISOString(),
      auto_sync_enabled: true,
      revoked: false,
    });

    expect(label).toMatch(/^Last updated /);
  });
});

describe("resolveGmailConnectedLabel", () => {
  it("uses custom email if provided", () => {
    expect(
      resolveGmailConnectedLabel({
        configured: true,
        connected: true,
        status: "connected",
        google_email: "test@hushh.ai",
        scope_csv: "gmail.readonly",
        last_sync_status: "completed",
        auto_sync_enabled: true,
        revoked: false,
      }),
    ).toBe("Connected to test@hushh.ai");
  });

  it("uses generic label if email is missing", () => {
    expect(
      resolveGmailConnectedLabel({
        configured: true,
        connected: true,
        status: "connected",
        scope_csv: "gmail.readonly",
        last_sync_status: "completed",
        auto_sync_enabled: true,
        revoked: false,
      }),
    ).toBe("Connected to your Gmail");
  });
});

describe("buildProfileGmailReturnPath", () => {
  it("resolves the correct profile return path with search parameters", () => {
    expect(buildProfileGmailReturnPath()).toBe("/profile?panel=gmail");
  });
});

describe("profile Gmail OAuth session stash", () => {
  it("saves, consumes, and purges return status on session storage", () => {
    const status = {
      configured: true,
      connected: true,
      status: "connected",
      google_email: "oauth-user@hushh.ai",
      scope_csv: "gmail.readonly",
      last_sync_status: "completed",
      auto_sync_enabled: true,
      revoked: false,
    } as any;

    stashProfileGmailReturnStatus(status);
    expect(mockSessionStorage.store["profile_gmail_oauth_return_status"]).toBe(
      JSON.stringify(status)
    );

    const consumed = consumeProfileGmailReturnStatus();
    expect(consumed).toEqual(status);
    expect(mockSessionStorage.store["profile_gmail_oauth_return_status"]).toBeUndefined();
  });

  it("returns null if return status is not present or invalid", () => {
    expect(consumeProfileGmailReturnStatus()).toBeNull();

    mockSessionStorage.store["profile_gmail_oauth_return_status"] = "{invalid json";
    expect(consumeProfileGmailReturnStatus()).toBeNull();
  });
});

describe("isRecoverableGmailOAuthReplayError", () => {
  it("correctly identifies recoverable replay errors", () => {
    expect(isRecoverableGmailOAuthReplayError("oauth state expired")).toBe(true);
    expect(isRecoverableGmailOAuthReplayError("invalid oauth state token")).toBe(true);
    expect(isRecoverableGmailOAuthReplayError(new Error("code has already been used"))).toBe(true);
    expect(isRecoverableGmailOAuthReplayError("some normal error")).toBe(false);
  });
});
