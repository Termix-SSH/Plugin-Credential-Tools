import {
  useEffect,
  useState,
  type ComponentProps,
  type ComponentType,
  type ReactNode,
} from "react";
import { Upload } from "lucide-react";
import {
  useTranslation,
  type TermixApp,
} from "@termix-ssh/plugin-sdk/frontend";
import { DeployDialog, type DeployTarget } from "./DeployDialog";
import { KeyGenerator } from "./KeyGenerator";
import { PublicKeyDeriver } from "./PublicKeyDeriver";

export function activate(app: TermixApp): void {
  // The row button and the dialog live in different places in the sidebar;
  // they talk through this.
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

  function DeployButton({
    credential,
    buttonClassName,
  }: {
    credential: DeployTarget;
    buttonClassName?: string;
  }) {
    const { t } = useTranslation();
    return (
      <Gate>
        <button
          title={t("credentials.deploySSHKeyTitle")}
          onClick={(event) => {
            event.stopPropagation();
            openDeploy({ id: credential.id, name: credential.name });
          }}
          className={buttonClassName}
        >
          <Upload className="size-3.5" />
        </button>
      </Gate>
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

  app.registerSlotContribution("credentials.panel", {
    actionId: "credential-tools.panel",
    titleKey: "credentials.deployDialogTitle",
    kind: "component",
    component: DeployHost as ComponentType<Record<string, unknown>>,
  });
  app.registerSlotContribution("credentials.rowActions", {
    actionId: "credential-tools.deploy",
    titleKey: "credentials.deploySSHKeyTitle",
    kind: "component",
    component: DeployButton as unknown as ComponentType<
      Record<string, unknown>
    >,
  });
}
