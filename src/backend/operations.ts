import type {
  PluginContext,
  PluginOperationContext,
} from "@termix-ssh/plugin-sdk/backend";
import { deployKey } from "./deploy-routes.js";

function requireHost(context: PluginOperationContext): number {
  if (context.hostId === undefined) throw new Error("This needs a host");
  return context.hostId;
}

async function requirePermission(ctx: PluginContext, permission: string) {
  if (!(await ctx.rbac.has(permission))) {
    throw new Error(`Missing the ${permission} permission`);
  }
}

/** Key deploys as actions, so one key can go to many hosts in a rollout. */
export function registerOperations(ctx: PluginContext): void {
  if (typeof ctx.operations?.register !== "function") return;

  ctx.operations.register("credential-tools.list-keys", {
    run: async () => {
      await requirePermission(ctx, "credentials.view");
      const keys = await ctx.credentials.listSshKeys();
      return {
        summary: `${keys.length} SSH keys`,
        data: {
          rows: keys.map((key) => ({ id: String(key.id), name: key.name })),
          options: keys.map((key) => ({
            value: String(key.id),
            label: key.name,
          })),
        },
      };
    },
  });

  ctx.operations.register("credential-tools.deploy-key", {
    describe: async (input) => {
      const keys = await ctx.credentials.listSshKeys();
      const key = keys.find((entry) => String(entry.id) === String(input.key));
      return `Would add ${key?.name ?? "the key"} to authorized_keys`;
    },
    run: async (input, context) => {
      const hostId = requireHost(context);
      await requirePermission(ctx, "credentials.view");
      await requirePermission(ctx, "hosts.edit");
      const keys = await ctx.credentials.listSshKeys();
      const key = keys.find((entry) => String(entry.id) === String(input.key));
      if (!key)
        throw new Error("Credential not found, or it is not an SSH key");
      // Writing authorized_keys is an owner action.
      const access = await ctx.hosts.checkAccess(hostId, "manage");
      if (!access.hasAccess || !access.isOwner) {
        throw new Error("Only the host's owner can add keys to it");
      }
      const publicKey = await ctx.credentials.publicKey(key.id);
      if (!publicKey) throw new Error("This key has no public key");
      const result = await deployKey(ctx, hostId, publicKey, key.name);
      if (!result.success) throw new Error(result.error ?? "Deploy failed");
      return {
        summary: result.message ?? "SSH key deployed",
        changed: result.message !== "SSH key already deployed",
      };
    },
  });
}
