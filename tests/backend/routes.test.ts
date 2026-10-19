import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import express, { type Router } from "express";
import ssh2 from "ssh2";
import {
  createMockCtx,
  type MockPluginContext,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import manifestJson from "../../manifest.json";
import { activate } from "../../src/backend/index.js";

const manifest = manifestJson as unknown as PluginManifest;
const ed = ssh2.utils.generateKeyPairSync("ed25519");
const other = ssh2.utils.generateKeyPairSync("ed25519");
const PUBLIC_LINE = ed.public.trim();

let mock: MockPluginContext;
let server: http.Server;
let port: number;

async function start(permissions?: string[]) {
  let router: Router | null = null;
  mock = createMockCtx({
    pluginId: manifest.id,
    manifest,
    capabilities: manifest.capabilities,
    router: () => (router = express.Router()),
    permissions,
    hosts: [
      { id: 7, userId: "user-1", name: "mine" },
      { id: 8, userId: "someone-else", name: "theirs" },
    ] as never,
    sshKeyCredentials: [
      { id: 3, name: "deploy", username: "root", publicKey: PUBLIC_LINE },
    ],
  });
  await activate(mock.ctx);

  const app = express();
  app.use(express.json());
  app.use((_req, _res, next) => {
    mock.setActor("user-1");
    next();
  });
  app.use((req, res, next) => router!(req, res, next));
  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  port = (server.address() as AddressInfo).port;
}

beforeEach(async () => {
  await start();
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function post(path: string, body?: unknown) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return { status: response.status, body: await response.json() };
}

describe("key routes", () => {
  it("generates a key pair of the asked type", async () => {
    const result = await post("/generate-key-pair", {
      keyType: "ssh-ed25519",
    });
    expect(result.status).toBe(200);
    expect(result.body.success).toBe(true);
    expect(result.body.publicKey).toMatch(/^ssh-ed25519 /);
    expect(result.body.privateKey).toContain("PRIVATE KEY");
  });

  it("generates an RSA pair with the asked size", async () => {
    const result = await post("/generate-key-pair", {
      keyType: "ssh-rsa",
      keySize: 2048,
    });
    expect(result.body.keySize).toBe(2048);
    expect(result.body.publicKey).toMatch(/^ssh-rsa /);
  });

  it("refuses an unknown key type", async () => {
    const result = await post("/generate-key-pair", { keyType: "dsa" });
    expect(result.status).toBe(400);
  });

  it("detects the type of a private key", async () => {
    const result = await post("/detect-key-type", { privateKey: ed.private });
    expect(result.body).toMatchObject({
      success: true,
      keyType: "ssh-ed25519",
      hasPublicKey: true,
    });
  });

  it("needs a private key to detect", async () => {
    const result = await post("/detect-key-type", {});
    expect(result.status).toBe(400);
  });

  it("answers on the old credentials paths too", async () => {
    const result = await post("/credentials/detect-key-type", {
      privateKey: ed.private,
    });
    expect(result.body.keyType).toBe("ssh-ed25519");
  });

  it("detects the type of a public key", async () => {
    const result = await post("/detect-public-key-type", {
      publicKey: PUBLIC_LINE,
    });
    expect(result.body).toMatchObject({
      success: true,
      keyType: "ssh-ed25519",
    });
  });

  it("derives the public key", async () => {
    const result = await post("/generate-public-key", {
      privateKey: ed.private,
    });
    expect(result.body.success).toBe(true);
    expect(result.body.publicKey.split(" ")[1]).toBe(PUBLIC_LINE.split(" ")[1]);
  });

  it("answers 400 when the private key cannot be read", async () => {
    const result = await post("/generate-public-key", { privateKey: "nope" });
    expect(result.status).toBe(400);
  });

  it("validates a matching pair and rejects a mismatch", async () => {
    const good = await post("/validate-key-pair", {
      privateKey: ed.private,
      publicKey: PUBLIC_LINE,
    });
    expect(good.body.isValid).toBe(true);

    const bad = await post("/validate-key-pair", {
      privateKey: ed.private,
      publicKey: other.public,
    });
    expect(bad.body.isValid).toBe(false);
    expect(bad.body.error).toBeTruthy();
  });

  it("blocks users without the credentials view permission", async () => {
    vi.spyOn(mock.ctx.rbac, "has").mockResolvedValue(false);
    const result = await post("/generate-key-pair", {});
    expect(result.status).toBe(403);
  });
});

describe("deploy", () => {
  const url = "/credentials/3/deploy-to-host";

  it("adds the key through stdin and verifies it", async () => {
    const exec = vi
      .spyOn(mock.ctx.ssh, "exec")
      .mockResolvedValueOnce(ok(0)) // prepare
      .mockResolvedValueOnce(ok(1)) // not there yet
      .mockResolvedValueOnce(ok(0)) // add
      .mockResolvedValueOnce(ok(0)); // verify
    const result = await post(url, { targetHostId: 7 });
    expect(result.status).toBe(200);
    expect(result.body.message).toBe("SSH key deployed successfully");
    const add = exec.mock.calls[2];
    expect(add[2]?.stdin).toBe(`${PUBLIC_LINE} deploy@Termix\n`);
    expect(add[1]).not.toContain(PUBLIC_LINE);
    expect(mock.audits.at(-1)).toMatchObject({
      action: "deploy_credential_key",
      success: true,
      resourceId: "3",
    });
  });

  it("leaves a key that is already on the host", async () => {
    const exec = vi
      .spyOn(mock.ctx.ssh, "exec")
      .mockResolvedValueOnce(ok(0))
      .mockResolvedValueOnce(ok(0));
    const result = await post(url, { targetHostId: 7 });
    expect(result.body.message).toBe("SSH key already deployed");
    expect(exec).toHaveBeenCalledTimes(2);
  });

  it("fails when the key is not found after adding it", async () => {
    vi.spyOn(mock.ctx.ssh, "exec")
      .mockResolvedValueOnce(ok(0))
      .mockResolvedValueOnce(ok(1))
      .mockResolvedValueOnce(ok(0))
      .mockResolvedValueOnce(ok(1));
    const result = await post(url, { targetHostId: 7 });
    expect(result.status).toBe(500);
    expect(result.body.error).toMatch(/verification/);
  });

  it("only deploys to hosts the user owns", async () => {
    const exec = vi.spyOn(mock.ctx.ssh, "exec");
    const result = await post(url, { targetHostId: 8 });
    expect(result.status).toBe(404);
    expect(exec).not.toHaveBeenCalled();
    expect(mock.audits.at(-1)).toMatchObject({ success: false });
  });

  it("answers 404 for a credential that is not a key of the user", async () => {
    const result = await post("/credentials/99/deploy-to-host", {
      targetHostId: 7,
    });
    expect(result.status).toBe(404);
  });

  it("needs both ids", async () => {
    const result = await post(url, {});
    expect(result.status).toBe(400);
  });

  it("needs the host edit permission", async () => {
    vi.spyOn(mock.ctx.rbac, "has").mockImplementation(
      async (permission) => permission !== "hosts.edit",
    );
    const exec = vi.spyOn(mock.ctx.ssh, "exec");
    const result = await post(url, { targetHostId: 7 });
    expect(result.status).toBe(403);
    expect(exec).not.toHaveBeenCalled();
  });

  it("explains a connection failure", async () => {
    vi.spyOn(mock.ctx.ssh, "exec").mockRejectedValue(
      new Error("connect ECONNREFUSED 10.0.0.1:22"),
    );
    const result = await post(url, { targetHostId: 7 });
    expect(result.status).toBe(500);
    expect(result.body.error).toMatch(/Connection refused/);
  });

  it("refuses an odd public key before connecting", async () => {
    vi.spyOn(mock.ctx.credentials, "publicKey").mockResolvedValue(
      "ssh-ed25519 not*base64",
    );
    const exec = vi.spyOn(mock.ctx.ssh, "exec");
    const result = await post(url, { targetHostId: 7 });
    expect(result.status).toBe(500);
    expect(result.body.error).toMatch(/Invalid public key/);
    expect(exec).not.toHaveBeenCalled();
  });
});

function ok(code: number) {
  return {
    stdout: "",
    stderr: "",
    code,
    truncated: false,
    timedOut: false,
  };
}
