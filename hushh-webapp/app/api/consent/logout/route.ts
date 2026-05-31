// app/api/consent/logout/route.ts

/**
 * Logout API - Destroy Session Tokens
 *
 * Proxies to Python backend to destroy all session tokens.
 * Called when user logs out.
 */

import { NextRequest, NextResponse } from "next/server";
import { getPythonApiUrl } from "@/app/api/_utils/backend";
import {
  invalidJsonPayloadResponse,
  readJsonObject,
} from "@/app/api/_utils/json-body";

const BACKEND_URL = getPythonApiUrl();

export async function POST(request: NextRequest) {
  try {
    const body = (await readJsonObject(request)) as { userId?: string } | null;
    if (!body) {
      return invalidJsonPayloadResponse();
    }
    const { userId } = body;
    const authHeader =
      request.headers.get("authorization") ||
      request.headers.get("Authorization");
    const consentHeader =
      request.headers.get("x-hushh-consent") ||
      request.headers.get("X-Hushh-Consent");

    if (!userId) {
      return NextResponse.json(
        { error: "userId is required" },
        { status: 400 },
      );
    }

    if (!authHeader && !consentHeader) {
      return NextResponse.json(
        { error: "Authorization header is required" },
        { status: 401 },
      );
    }

    console.log("[API] Destroying session tokens");

    const response = await fetch(`${BACKEND_URL}/api/consent/logout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(authHeader ? { Authorization: authHeader } : {}),
        ...(consentHeader ? { "X-Hushh-Consent": consentHeader } : {}),
      },
      body: JSON.stringify({ userId }),
    });

    if (!response.ok) {
      const error = await response.text();
      console.error("[API] Backend error:", error);
      return NextResponse.json(
        { error: "Failed to destroy session tokens" },
        { status: response.status },
      );
    }

    const data = await response.json();
    console.log("[API] Session tokens destroyed");

    return NextResponse.json(data);
  } catch (error) {
    console.error("[API] Logout error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 },
    );
  }
}
