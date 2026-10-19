import type { NextFunction, Request, Response } from "express";
import {
  PluginCapabilityError,
  type PluginContext,
} from "@termix-ssh/plugin-sdk/backend";

/** Lets a request through only when the user holds a core permission. */
export function requireCorePermission(ctx: PluginContext, permission: string) {
  return async (_req: Request, res: Response, next: NextFunction) => {
    try {
      if (await ctx.rbac.has(permission)) return next();
      res.status(403).json({ error: `Missing the ${permission} permission` });
    } catch (error) {
      next(error);
    }
  };
}

export function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}

export function statusFor(error: unknown, fallback = 500): number {
  return error instanceof PluginCapabilityError ? 403 : fallback;
}
