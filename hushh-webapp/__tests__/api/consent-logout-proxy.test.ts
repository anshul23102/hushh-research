import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/app/api/_utils/backend", () => ({
  getPythonApiUrl: () => "http://backend.test",
}));

type LogoutRoute = {
  POST: (request: NextRequest) => Promise<Response>;
};

let route: LogoutRoute;

beforeEach(async () => {
  vi.restoreAllMocks();
  route = await import("../../app/api/consent/logout/route");
});

function logoutRequest(headers: Record<string, string> = {}) {
  return new NextRequest("http://localhost:3000/api/consent/logout", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify({ userId: "user_123" }),
  });
}

describe("POST /api/consent/logout proxy", () => {
  it("requires a vault-owner token before proxying", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("should not be called", { status: 500 }));

    const response = await route.POST(logoutRequest());
    const payload = await response.json();

    expect(response.status).toBe(401);
    expect(payload).toEqual({ error: "Authorization header is required" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards vault-owner auth headers to the backend logout route", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "success", revoked: 1 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );

    const response = await route.POST(
      logoutRequest({
        Authorization: "Bearer HCT:vault-owner",
        "X-Hushh-Consent": "HCT:vault-owner",
      })
    );
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(payload).toEqual({ status: "success", revoked: 1 });
    expect(fetchMock).toHaveBeenCalledWith(
      "http://backend.test/api/consent/logout",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer HCT:vault-owner",
          "X-Hushh-Consent": "HCT:vault-owner",
        }),
        body: JSON.stringify({ userId: "user_123" }),
      })
    );
  });
});
