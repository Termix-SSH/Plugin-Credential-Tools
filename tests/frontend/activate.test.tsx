import { afterEach, describe, expect, it } from "vitest";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import * as plugin from "../../src/frontend/index";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

describe(`${manifest.id} activate`, () => {
  it("activates and deactivates without adding a tab or rail item", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.tabs()).toEqual([]);
    expect(rendered.registered.railItems()).toEqual([]);
  });
});

describe("deploying a key from its row", () => {
  it("is a plain button that opens the dialog in the same frame", async () => {
    const { checkFrameApp } = await import("@termix-ssh/plugin-sdk/testing");
    const { registrations } = await checkFrameApp(plugin, {
      manifest: manifestJson as unknown as Record<string, unknown>,
    });
    const row = registrations.find(
      (entry) =>
        entry.kind === "slotContribution" &&
        (entry.data as { slotId?: string }).slotId === "credentials.rowActions",
    )?.data as Record<string, unknown>;
    expect(row).toMatchObject({
      kind: "button",
      actionId: "credential-tools.deploy",
    });
    expect(row.component).toBeUndefined();

    const { invokeAction } = await import("@termix-ssh/plugin-sdk/frontend");
    const { findAllByText } = await import("@testing-library/react");
    rendered = await renderWithApp(plugin, { manifest, locales });
    const overlay = rendered.renderSlot("shell.overlay");
    await invokeAction("credential-tools.deploy", {
      id: 4,
      name: "laptop key",
    });
    expect((await findAllByText(overlay, /laptop key/)).length).toBeGreaterThan(
      0,
    );
  });
});
