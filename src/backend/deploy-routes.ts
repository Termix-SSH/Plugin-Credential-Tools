import type { Request, Response, Router } from "express";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { errorMessage, requireCorePermission } from "./guards.js";

function describeDeployError(err: unknown): string {
  const message = errorMessage(err, "Connection failed");
  if (message.includes("All configured authentication methods failed")) {
    return "Authentication failed. Please check your credentials and ensure the SSH service is running.";
  }
  if (message.includes("ENOTFOUND") || message.includes("ENOENT")) {
    return "Could not resolve hostname or connect to server.";
  }
  if (message.includes("ECONNREFUSED")) {
    return "Connection refused. The server may not be running or the port may be incorrect.";
  }
  if (message.includes("ETIMEDOUT")) {
    return "Connection timed out. Check your network connection and server availability.";
  }
  if (
    message.includes("authentication failed") ||
    message.includes("Permission denied")
  ) {
    return "Authentication failed. Please check your username and password/key.";
  }
  if (message === "SSH connection timeout") return "Connection timeout";
  return message;
}

/** The authorized_keys line, unwrapping the older {"data": "..."} form. */
function keyLine(publicKey: string): string {
  try {
    const parsed = JSON.parse(publicKey);
    if (parsed && typeof parsed.data === "string") return parsed.data.trim();
  } catch {
    // plain text
  }
  return publicKey.trim();
}

async function deployKey(
  ctx: PluginContext,
  hostId: number,
  publicKey: string,
  credentialName: string,
): Promise<{ success: boolean; message?: string; error?: string }> {
  const line = keyLine(publicKey);
  const parts = line.split(" ");
  if (parts.length < 2) {
    return {
      success: false,
      error: "Invalid public key format - must contain at least 2 parts",
    };
  }
  const keyPattern = parts[1];
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(keyPattern)) {
    return { success: false, error: "Invalid public key data" };
  }

  const options = { purpose: "credential-deploy", timeoutMs: 30000 };
  const hasKey = `grep -F "${keyPattern}" ~/.ssh/authorized_keys >/dev/null 2>&1`;

  try {
    const prepare = await ctx.ssh.exec(
      hostId,
      "test -d ~/.ssh || mkdir -p ~/.ssh; chmod 700 ~/.ssh",
      options,
    );
    if (prepare.code !== 0) {
      return {
        success: false,
        error: `mkdir command failed with code ${prepare.code}`,
      };
    }

    const existing = await ctx.ssh.exec(hostId, hasKey, options);
    if (existing.code === 0) {
      return { success: true, message: "SSH key already deployed" };
    }

    // The key travels on stdin, so nothing needs shell escaping.
    const comment = `${credentialName.replace(/[\r\n]/g, " ")}@Termix`;
    const add = await ctx.ssh.exec(
      hostId,
      "cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
      { ...options, stdin: `${line} ${comment}\n` },
    );
    if (add.code !== 0) {
      return {
        success: false,
        error: `Key deployment failed with code ${add.code}`,
      };
    }

    const verified = await ctx.ssh.exec(hostId, hasKey, options);
    return verified.code === 0
      ? { success: true, message: "SSH key deployed successfully" }
      : { success: false, error: "Key deployment verification failed" };
  } catch (error) {
    return { success: false, error: describeDeployError(error) };
  }
}

export function registerDeployRoutes(router: Router, ctx: PluginContext): void {
  /**
   * @openapi
   * /plugin-api/credential-tools/credentials/{id}/deploy-to-host:
   *   post:
   *     summary: Deploy an SSH key to a host
   *     description: Adds the public key of a saved key credential to the authorized keys of one of your hosts, over SSH. You need to be allowed to view credentials and edit hosts. Every deploy is written to the audit log.
   *     tags:
   *       - Credential Tools
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required:
   *               - targetHostId
   *             properties:
   *               targetHostId:
   *                 type: integer
   *     responses:
   *       200:
   *         description: SSH key deployed.
   *       400:
   *         description: Missing ids or the credential is not a usable key.
   *       403:
   *         description: Not allowed.
   *       404:
   *         description: Credential or target host not found.
   *       500:
   *         description: Failed to deploy the SSH key.
   */
  router.post(
    "/credentials/:id/deploy-to-host",
    requireCorePermission(ctx, "credentials.view"),
    requireCorePermission(ctx, "hosts.edit"),
    async (req: Request, res: Response) => {
      const credentialId = parseInt(String(req.params.id), 10);
      const targetHostId = Number(req.body?.targetHostId);
      if (!credentialId || !Number.isInteger(targetHostId) || !targetHostId) {
        return res.status(400).json({
          success: false,
          error: "Credential ID and target host ID are required",
        });
      }

      const audit = (success: boolean, errorMessageText?: string) =>
        ctx.audit.record({
          action: "deploy_credential_key",
          resourceType: "credential",
          resourceId: String(credentialId),
          details: JSON.stringify({ targetHostId }),
          success,
          errorMessage: errorMessageText,
          request: req,
        });

      try {
        const keys = await ctx.credentials.listSshKeys();
        const credential = keys.find((key) => key.id === credentialId);
        if (!credential) {
          await audit(false, "Credential not found");
          return res.status(404).json({
            success: false,
            error: "Credential not found, or it is not an SSH key",
          });
        }

        // Writing authorized_keys is an owner action.
        const access = await ctx.hosts.checkAccess(targetHostId, "manage");
        if (!access.hasAccess || !access.isOwner) {
          await audit(false, "Target host not found");
          return res
            .status(404)
            .json({ success: false, error: "Target host not found" });
        }

        const publicKey = await ctx.credentials.publicKey(credentialId);
        if (!publicKey) {
          await audit(false, "No public key");
          return res.status(400).json({
            success: false,
            error: "Public key is required for deployment",
          });
        }

        const result = await deployKey(
          ctx,
          targetHostId,
          publicKey,
          credential.name,
        );
        await audit(result.success, result.error);
        if (!result.success) {
          return res.status(500).json({
            success: false,
            error: result.error || "Deployment failed",
          });
        }
        res.json({
          success: true,
          message: result.message || "SSH key deployed successfully",
        });
      } catch (error) {
        await audit(false, errorMessage(error, "Failed to deploy SSH key"));
        res.status(500).json({
          success: false,
          error: errorMessage(error, "Failed to deploy SSH key"),
        });
      }
    },
  );
}
