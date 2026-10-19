import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Upload } from "lucide-react";
import {
  useTranslation,
  type PluginApiClient,
} from "@termix-ssh/plugin-sdk/frontend";
import {
  Button,
  InlineView,
  Select2,
  enabledHostProtocols,
  getErrorMessage,
  getSSHHosts,
  sshHostToHost,
  type Host,
} from "@termix-ssh/plugin-sdk/ui";

export interface DeployTarget {
  id: number | string;
  name: string;
}

/** Pick a host and copy a key credential's public key to it. */
export function DeployDialog({
  api,
  credential,
  onClose,
}: {
  api: PluginApiClient;
  credential: DeployTarget | null;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [hostId, setHostId] = useState("");
  const [deploying, setDeploying] = useState(false);

  useEffect(() => {
    if (!credential) return;
    setHostId("");
    let cancelled = false;
    getSSHHosts()
      .then((list) => {
        if (!cancelled) setHosts(list.map(sshHostToHost));
      })
      .catch(() => {
        if (!cancelled) setHosts([]);
      });
    return () => {
      cancelled = true;
    };
  }, [credential]);

  const deploy = async () => {
    if (!credential || !hostId) return;
    setDeploying(true);
    try {
      await api.post(`/credentials/${credential.id}/deploy-to-host`, {
        targetHostId: Number(hostId),
      });
      toast.success(t("credentials.keyDeployedSuccess"));
      onClose();
    } catch (error) {
      toast.error(getErrorMessage(error, t("credentials.failedToDeployKey")));
    } finally {
      setDeploying(false);
    }
  };

  return (
    <InlineView
      open={!!credential}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      icon={<Upload className="size-4" />}
      title={t("credentials.deployDialogTitle")}
      footer={
        <div className="ml-auto flex gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            disabled={deploying}
          >
            {t("hosts.cancelBtn")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="border-accent-brand/40 text-accent-brand hover:bg-accent-brand/10"
            disabled={!hostId || deploying}
            onClick={() => void deploy()}
          >
            {deploying
              ? t("credentials.deployingBtn")
              : t("credentials.deployBtn")}
          </Button>
        </div>
      }
    >
      <p className="text-xs text-muted-foreground">
        {t("credentials.deployDialogDesc", { name: credential?.name })}
      </p>
      <div className="flex flex-col gap-1.5">
        <label className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
          {t("credentials.targetHostLabel")}
        </label>
        <Select2
          className="flex h-9 w-full border border-border bg-background px-3 py-1 text-xs outline-none focus:ring-1 focus:ring-ring"
          value={hostId}
          onChange={(e) => setHostId(e.target.value)}
        >
          <option value="">{t("credentials.selectHostOption")}</option>
          {hosts
            .filter((h) => h.enableSsh || enabledHostProtocols(h).length === 0)
            .map((h) => (
              <option key={h.id} value={h.id}>
                {h.name || h.ip}
              </option>
            ))}
        </Select2>
      </div>
    </InlineView>
  );
}
