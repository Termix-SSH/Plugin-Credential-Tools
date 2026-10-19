import type { Router } from "express";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { registerKeyRoutes } from "./key-routes.js";
import { registerDeployRoutes } from "./deploy-routes.js";

export async function activate(ctx: PluginContext) {
  const router = ctx.http.router<Router>();
  router.use(ctx.rbac.require("use") as never);
  registerKeyRoutes(router, ctx);
  registerDeployRoutes(router, ctx);
}

export async function deactivate() {
  // Everything registered through ctx is disposed by core.
}
