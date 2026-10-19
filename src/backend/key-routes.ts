import crypto from "node:crypto";
import type { Request, Response, Router } from "express";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import {
  detectSshKeyType,
  generateSshKeyPair,
  publicKeyFromPrivate,
  validateSshKeyPair,
  type SshKeyKind,
} from "@termix-ssh/plugin-sdk/ssh-keys";
import { errorMessage, requireCorePermission, statusFor } from "./guards.js";

const KEY_TYPES: SshKeyKind[] = [
  "ssh-ed25519",
  "ssh-rsa",
  "ecdsa-sha2-nistp256",
];

/** Secret references like op://... turn into the real key and passphrase. */
async function resolveKey(
  ctx: PluginContext,
  key: string,
  passphrase?: string | null,
) {
  return ctx.credentials.resolveKeyRefs(key, passphrase);
}

/** A public key in PEM form for private keys ssh2 cannot read. */
function pemPublicKey(
  privateKey: string,
  passphrase?: string,
): { publicKey: string; keyType: string } | null {
  try {
    const priv = crypto.createPrivateKey({ key: privateKey, passphrase });
    const pem = crypto
      .createPublicKey(priv)
      .export({ type: "spki", format: "pem" });
    const type = priv.asymmetricKeyType;
    return {
      publicKey: String(pem),
      keyType:
        type === "rsa"
          ? "ssh-rsa"
          : type === "ed25519"
            ? "ssh-ed25519"
            : type === "ec"
              ? "ecdsa-sha2-nistp256"
              : "unknown",
    };
  } catch {
    return null;
  }
}

export function registerKeyRoutes(router: Router, ctx: PluginContext): void {
  const canView = requireCorePermission(ctx, "credentials.view");

  /**
   * @openapi
   * /plugin-api/credential-tools/detect-key-type:
   *   post:
   *     summary: Detect SSH key type
   *     description: Detects the type of an SSH private key.
   *     tags:
   *       - Credential Tools
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               privateKey:
   *                 type: string
   *               keyPassword:
   *                 type: string
   *     responses:
   *       200:
   *         description: Key type detection result.
   *       400:
   *         description: Private key is required.
   *       403:
   *         description: Not allowed.
   *       500:
   *         description: Failed to detect key type.
   */
  router.post(
    ["/detect-key-type", "/credentials/detect-key-type"],
    canView,
    async (req: Request, res: Response) => {
      const { privateKey, keyPassword } = req.body ?? {};
      if (!privateKey || typeof privateKey !== "string") {
        return res.status(400).json({ error: "Private key is required" });
      }
      try {
        const resolved = await resolveKey(ctx, privateKey, keyPassword);
        const keyType = detectSshKeyType(resolved.key, resolved.passphrase);
        const publicKey = publicKeyFromPrivate(
          resolved.key,
          resolved.passphrase,
        );
        res.json({
          success: keyType !== null,
          keyType: keyType ?? "unknown",
          detectedKeyType: keyType ?? "unknown",
          hasPublicKey: !!publicKey,
          error: keyType ? null : "Not a readable SSH key",
        });
      } catch (error) {
        res.status(statusFor(error)).json({
          error: errorMessage(error, "Failed to detect key type"),
        });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/credential-tools/detect-public-key-type:
   *   post:
   *     summary: Detect SSH public key type
   *     description: Detects the type of an SSH public key.
   *     tags:
   *       - Credential Tools
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               publicKey:
   *                 type: string
   *     responses:
   *       200:
   *         description: Key type detection result.
   *       400:
   *         description: Public key is required.
   *       403:
   *         description: Not allowed.
   */
  router.post(
    ["/detect-public-key-type", "/credentials/detect-public-key-type"],
    canView,
    async (req: Request, res: Response) => {
      const { publicKey } = req.body ?? {};
      if (!publicKey || typeof publicKey !== "string") {
        return res.status(400).json({ error: "Public key is required" });
      }
      const keyType = detectSshKeyType(publicKey);
      res.json({
        success: keyType !== null,
        keyType: keyType ?? "unknown",
        detectedKeyType: keyType ?? "unknown",
        error: keyType ? null : "Not a readable SSH public key",
      });
    },
  );

  /**
   * @openapi
   * /plugin-api/credential-tools/validate-key-pair:
   *   post:
   *     summary: Check that an SSH key pair matches
   *     tags:
   *       - Credential Tools
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               privateKey:
   *                 type: string
   *               publicKey:
   *                 type: string
   *               keyPassword:
   *                 type: string
   *     responses:
   *       200:
   *         description: Validation result.
   *       400:
   *         description: A key is missing.
   *       403:
   *         description: Not allowed.
   */
  router.post(
    ["/validate-key-pair", "/credentials/validate-key-pair"],
    canView,
    async (req: Request, res: Response) => {
      const { privateKey, publicKey, keyPassword } = req.body ?? {};
      if (!privateKey || typeof privateKey !== "string") {
        return res.status(400).json({ error: "Private key is required" });
      }
      if (!publicKey || typeof publicKey !== "string") {
        return res.status(400).json({ error: "Public key is required" });
      }
      const result = validateSshKeyPair(privateKey, publicKey, keyPassword);
      res.json({
        isValid: result.isValid,
        privateKeyType: detectSshKeyType(privateKey, keyPassword) ?? "unknown",
        publicKeyType: detectSshKeyType(publicKey) ?? "unknown",
        generatedPublicKey: publicKeyFromPrivate(privateKey, keyPassword),
        error: result.error ?? null,
      });
    },
  );

  /**
   * @openapi
   * /plugin-api/credential-tools/generate-key-pair:
   *   post:
   *     summary: Generate an SSH key pair
   *     tags:
   *       - Credential Tools
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               keyType:
   *                 type: string
   *                 enum: [ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256]
   *               keySize:
   *                 type: integer
   *               passphrase:
   *                 type: string
   *     responses:
   *       200:
   *         description: The new key pair.
   *       400:
   *         description: Unsupported key type or size.
   *       403:
   *         description: Not allowed.
   */
  router.post(
    ["/generate-key-pair", "/credentials/generate-key-pair"],
    canView,
    async (req: Request, res: Response) => {
      const {
        keyType = "ssh-ed25519",
        keySize = 2048,
        passphrase,
      } = req.body ?? {};
      if (!KEY_TYPES.includes(keyType)) {
        return res
          .status(400)
          .json({ success: false, error: "Unsupported key type" });
      }
      try {
        const pair = generateSshKeyPair(keyType, {
          bits: keyType === "ssh-rsa" ? Number(keySize) : undefined,
          passphrase:
            typeof passphrase === "string" && passphrase.trim()
              ? passphrase
              : undefined,
        });
        res.json({
          success: true,
          privateKey: pair.privateKey,
          publicKey: pair.publicKey,
          keyType,
          format: "ssh",
          algorithm: keyType,
          keySize: keyType === "ssh-rsa" ? Number(keySize) : undefined,
          curve: keyType === "ecdsa-sha2-nistp256" ? "nistp256" : undefined,
        });
      } catch (error) {
        res.status(400).json({
          success: false,
          error: errorMessage(error, "SSH key generation failed"),
        });
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/credential-tools/generate-public-key:
   *   post:
   *     summary: Get the public key for a private key
   *     tags:
   *       - Credential Tools
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               privateKey:
   *                 type: string
   *               keyPassword:
   *                 type: string
   *     responses:
   *       200:
   *         description: The public key.
   *       400:
   *         description: The private key could not be read.
   *       403:
   *         description: Not allowed.
   */
  router.post(
    ["/generate-public-key", "/credentials/generate-public-key"],
    canView,
    async (req: Request, res: Response) => {
      const { privateKey, keyPassword } = req.body ?? {};
      if (!privateKey || typeof privateKey !== "string") {
        return res.status(400).json({ error: "Private key is required" });
      }
      try {
        const resolved = await resolveKey(ctx, privateKey, keyPassword);
        const line = publicKeyFromPrivate(resolved.key, resolved.passphrase);
        if (line) {
          return res.json({
            success: true,
            publicKey: line,
            keyType: line.split(" ")[0],
            format: "ssh",
          });
        }
        const pem = pemPublicKey(resolved.key, resolved.passphrase);
        if (pem) return res.json({ success: true, ...pem, format: "pem" });
        res.status(400).json({
          success: false,
          error: "Unable to parse private key. Tried multiple formats.",
        });
      } catch (error) {
        res.status(statusFor(error)).json({
          success: false,
          error: errorMessage(error, "Failed to generate public key"),
        });
      }
    },
  );
}
