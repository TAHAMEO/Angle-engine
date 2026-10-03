"use client";

import { useParams } from "next/navigation";

import { LoadingBlock } from "@/components/ui/feedback";
import { AssistantDrawer } from "@/features/assistant/assistant-drawer";
import { QueryError } from "@/features/common/states";
import { StatusBanners } from "@/features/investigations/status-banners";
import { InvestigationProvider, useInvestigationDetail } from "@/lib/investigation";

export default function InvestigationLayout({ children }: { children: React.ReactNode }) {
  const { id } = useParams<{ id: string }>();
  const { data, error, isPending, refetch } = useInvestigationDetail(id);
  if (isPending) return <LoadingBlock label="Loading investigation" />;
  if (error || !data) return <QueryError error={error} retry={() => void refetch()} />;
  return (
    <InvestigationProvider investigation={data}>
      <StatusBanners />
      {children}
      <AssistantDrawer />
    </InvestigationProvider>
  );
}
