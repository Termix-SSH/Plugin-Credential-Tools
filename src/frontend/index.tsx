import {
  useEffect,
  useState,
  type ComponentProps,
  type ComponentType,
  type ReactNode,
} from "react";
import { Upload } from "lucide-react";
import type { TermixApp } from "@termix-ssh/plugin-sdk/frontend";
import { DeployDialog, type DeployTarget } from "./DeployDialog";
import { KeyGenerator } from "./KeyGenerator";
import { PublicKeyDeriver } from "./PublicKeyDeriver";

export function activate(app: TermixApp): void {
  // The row button runs an action and the dialog is an overlay, both in the
  // background frame, so they share this.
  // Components other surfaces render must hide themselves from users who
  // may not use the plugin.
  function useAllowed(): boolean {
    const [allowed, setAllowed] = useState(false);
    useEffect(() => {
      let cancelled = false;
      void app.hasPermission("use").then((ok) => {
        if (!cancelled) setAllowed(ok);
      });
      return () => {
        cancelled = true;
      };
    }, []);
    return allowed;
  }

  function Gate({ children }: { children: ReactNode }) {
    return useAllowed() ? <>{children}</> : null;
  }

  const listeners = new Set<(target: DeployTarget) => void>();
  const openDeploy = (target: DeployTarget) => {
    for (const listener of listeners) listener(target);
  };

  function DeployHost() {
    const [target, setTarget] = useState<DeployTarget | null>(null);
    useEffect(() => {
      listeners.add(setTarget);
      return () => {
        listeners.delete(setTarget);
      };
    }, []);
    return (
      <DeployDialog
        api={app.api}
        credential={target}
        onClose={() => setTarget(null)}
      />
    );
  }

  app.registerComponent("credentials.keyGenerator", ((
    props: Omit<ComponentProps<typeof KeyGenerator>, "api">,
  ) => (
    <Gate>
      <KeyGenerator api={app.api} {...props} />
    </Gate>
  )) as ComponentType<Record<string, unknown>>);
  app.registerComponent("credentials.publicKeyDeriver", ((
    props: Omit<ComponentProps<typeof PublicKeyDeriver>, "api">,
  ) => (
    <Gate>
      <PublicKeyDeriver api={app.api} {...props} />
    </Gate>
  )) as ComponentType<Record<string, unknown>>);

  app.registerSlotContribution("shell.overlay", {
    actionId: "credential-tools.deployDialog",
    titleKey: "credentials.deployDialogTitle",
    kind: "component",
    component: DeployHost as ComponentType<Record<string, unknown>>,
  });
  // A plain button on each key row: no component, so no frame per row.
  app.registerAction(
    "credential-tools.deploy",
    (target: DeployTarget) => {
      if (target && target.id !== undefined) {
        openDeploy({ id: target.id, name: target.name });
      }
    },
    { permission: "use" },
  );
  app.registerSlotContribution("credentials.rowActions", {
    actionId: "credential-tools.deploy",
    titleKey: "credentials.deploySSHKeyTitle",
    icon: Upload,
    kind: "button",
  });
}
