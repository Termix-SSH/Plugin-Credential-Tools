import { useState } from "react";
import { toast } from "sonner";
import {
  useTranslation,
  type PluginApiClient,
} from "@termix-ssh/plugin-sdk/frontend";
import { Button } from "@termix-ssh/plugin-sdk/ui";

/** The "generate from private key" button next to the public key field. */
export function PublicKeyDeriver({
  api,
  privateKey,
  passphrase,
  onDerived,
}: {
  api: PluginApiClient;
  privateKey?: string;
  passphrase?: string;
  onDerived?: (publicKey: string) => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);

  const derive = async () => {
    setBusy(true);
    try {
      const { data } = await api.post<{ publicKey?: string }>(
        "/generate-public-key",
        {
          privateKey,
          keyPassword:
            passphrase && passphrase !== "existing_key_password"
              ? passphrase
              : undefined,
        },
      );
      if (data?.publicKey) {
        onDerived?.(data.publicKey);
        toast.success(t("hosts.publicKeyGenerated"));
      } else {
        toast.error(t("hosts.failedToGeneratePublicKey"));
      }
    } catch {
      toast.error(t("hosts.failedToGeneratePublicKey"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className="h-6 text-[10px] px-2 border-accent-brand/40 text-accent-brand"
      disabled={!privateKey || privateKey === "existing_key" || busy}
      onClick={() => void derive()}
    >
      {busy ? t("hosts.generatingKey") : t("hosts.generateFromPrivateKey")}
    </Button>
  );
}
