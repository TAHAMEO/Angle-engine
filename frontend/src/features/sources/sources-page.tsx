"use client";

import { FilePlus2, Search } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { PageHeader } from "@/components/shell/app-shell";
import { Button } from "@/components/ui/button";
import { Tabs } from "@/components/ui/data";
import { useInvestigation } from "@/lib/investigation";
import { takeCollectPrefill, type CollectPrefill } from "@/lib/prefill";

import { CollectDialog, useConnectors } from "./collect-dialog";
import { ConnectorCatalog } from "./connectors";
import { ManualCaptureDialog } from "./manual-capture";
import { RunsPanel } from "./runs";
import { SourcesTable } from "./sources-table";
import { SuggestionsPanel } from "./suggestions";

export function SourcesPage() {
  const { investigation: inv, can } = useInvestigation();
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const writable = can("content:write");
  const [collectOpen, setCollectOpen] = useState(() => writable && params.get("collect") === "1");
  const [prefill] = useState<CollectPrefill | null>(() => takeCollectPrefill());
  const [manualOpen, setManualOpen] = useState(false);
  const [tab, setTab] = useState(params.get("tab") ?? "sources");
  const { data: connectors, isPending } = useConnectors(inv.id);

  const closeCollect = (open: boolean) => {
    setCollectOpen(open);
    if (!open && params.get("collect")) router.replace(pathname);
  };
  return (
    <>
      <PageHeader
        title="Sources"
        description="Where every piece of evidence came from: captured public pages, registry records, archives and image matches — with capture dates and access status."
        actions={
          writable ? (
            <>
              <Button variant="secondary" onClick={() => setManualOpen(true)}>
                <FilePlus2 className="h-4 w-4" aria-hidden /> Add manually
              </Button>
              <Button variant="primary" onClick={() => setCollectOpen(true)}>
                <Search className="h-4 w-4" aria-hidden /> Collect
              </Button>
            </>
          ) : undefined
        }
      />
      <Tabs
        label="Sources"
        value={tab}
        onValueChange={setTab}
        tabs={[
          { value: "sources", label: "Sources", content: <SourcesTable /> },
          { value: "runs", label: "Collection runs", content: <RunsPanel /> },
          { value: "suggestions", label: "Suggestions", content: <SuggestionsPanel /> },
          { value: "connectors", label: "Connectors", content: <ConnectorCatalog connectors={connectors} loading={isPending} /> },
        ]}
      />
      {writable ? <CollectDialog open={collectOpen} onOpenChange={closeCollect} prefill={prefill} /> : null}
      {writable ? <ManualCaptureDialog open={manualOpen} onOpenChange={setManualOpen} /> : null}
    </>
  );
}
