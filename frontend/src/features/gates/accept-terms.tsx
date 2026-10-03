"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/data";
import { Alert, LoadingBlock } from "@/components/ui/feedback";
import { Checkbox } from "@/components/ui/form";
import { useLegalDocuments } from "@/features/public/legal-document";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import { SESSION_KEY } from "@/lib/session";

export function AcceptTerms() {
  const router = useRouter();
  const client = useQueryClient();
  const { data: docs, isPending } = useLegalDocuments();
  const [checked, setChecked] = useState(false);
  const terms = docs?.find((d) => d.kind === "terms");
  const aup = docs?.find((d) => d.kind === "acceptable_use");
  const accept = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/me/attestations", {
          body: { terms_version: terms!.version, acceptable_use_version: aup!.version, attest_lawful_use: true },
        }),
      ),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: SESSION_KEY });
      router.replace("/dashboard");
    },
  });
  return (
    <div className="w-full max-w-lg space-y-5">
      <h1 className="text-2xl font-semibold tracking-tight">Please review the updated terms</h1>
      {isPending ? <LoadingBlock /> : null}
      {terms && aup ? (
        <Card className="space-y-4 p-5">
          <ul className="flex flex-col gap-1 text-sm">
            <li>
              <Link href="/legal/terms" target="_blank" className="text-primary underline">Terms of Use</Link> — version {terms.version}
            </li>
            <li>
              <Link href="/legal/acceptable-use" target="_blank" className="text-primary underline">Acceptable Use Policy</Link> — version {aup.version}
            </li>
          </ul>
          <Checkbox
            label="I accept these terms and will use Angel Engine only for lawful investigations of public information."
            checked={checked}
            onChange={(e) => setChecked(e.target.checked)}
          />
          {accept.isError ? <Alert tone="danger">{messageOf(accept.error)}</Alert> : null}
          <Button variant="primary" disabled={!checked} loading={accept.isPending} onClick={() => accept.mutate()}>
            Accept and continue
          </Button>
        </Card>
      ) : null}
    </div>
  );
}
