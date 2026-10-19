import { useState } from "react";
import { toast } from "sonner";
import {
  useTranslation,
  type PluginApiClient,
} from "@termix-ssh/plugin-sdk/frontend";
import { Button, getErrorMessage } from "@termix-ssh/plugin-sdk/ui";

type KeyType = "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256";

const OPTIONS: Array<{ label: string; type: KeyType; bits?: number }> = [
  { label: "Ed25519", type: "ssh-ed25519" },
  { label: "ECDSA (nistp256)", type: "ecdsa-sha2-nistp256" },
  { label: "RSA (2048)", type: "ssh-rsa", bits: 2048 },
];

interface GenerateResponse {
  success: boolean;
  privateKey?: string;
  publicKey?: string;
  error?: string;
}

/** The generate buttons in the credential editor. */
export function KeyGenerator({
  api,
  passphrase,
  onGenerated,
}: {
  api: PluginApiClient;
  passphrase?: string;
  onGenerated?: (pair: { privateKey: string; publicKey: string }) => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);

  const generate = async (option: (typeof OPTIONS)[number]) => {
    setBusy(true);
    try {
      const { data } = await api.post<GenerateResponse>("/generate-key-pair", {
        keyType: option.type,
        keySize: option.bits,
        passphrase:
          passphrase && passphrase !== "existing_key_password"
            ? passphrase
            : undefined,
      });
      if (data.success && data.privateKey && data.publicKey) {
        onGenerated?.({
          privateKey: data.privateKey,
          publicKey: data.publicKey,
        });
        toast.success(t("hosts.keyPairGenerated", { label: option.label }));
      } else {
        toast.error(data.error ?? t("hosts.failedToGenerateKeyPair"));
      }
    } catch (error) {
      toast.error(getErrorMessage(error, t("hosts.failedToGenerateKeyPair")));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="p-3 border border-border bg-muted/20">
      <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-2">
        {t("hosts.generateKeyPairTitle")}
      </p>
      <p className="text-[10px] text-muted-foreground mb-2">
        {t("hosts.generateKeyPairDescription")}
      </p>
      <div className="flex flex-wrap gap-2">
        {OPTIONS.map((option) => (
          <Button
            key={option.label}
            type="button"
            variant="outline"
            size="sm"
            className="h-7 text-[10px] px-2"
            disabled={busy}
            onClick={() => void generate(option)}
          >
            {busy
              ? t("hosts.generatingKey")
              : t("hosts.generateLabel", { label: option.label })}
          </Button>
        ))}
      </div>
    </div>
  );
}
