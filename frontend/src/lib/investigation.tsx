"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { createContext, useContext } from "react";

import { api, unwrap } from "@/lib/api/client";
import type { InvestigationDetail } from "@/lib/api/types";
import { qk } from "@/lib/query/keys";

export function useInvestigationId(): string | null {
  const params = useParams<{ id?: string }>();
  const id = params?.id;
  return typeof id === "string" && /^[0-9a-f-]{36}$/i.test(id) ? id : null;
}

export function investigationQuery(id: string) {
  return {
    queryKey: qk.investigation(id),
    queryFn: () =>
      unwrap(api.GET("/api/v1/investigations/{investigation_id}", { params: { path: { investigation_id: id } } })),
  };
}

export function useInvestigationDetail(id: string | null) {
  return useQuery({ ...investigationQuery(id ?? ""), enabled: Boolean(id) });
}

interface Ctx {
  investigation: InvestigationDetail;
  can: (permission: string) => boolean;
}

const InvestigationContext = createContext<Ctx | null>(null);

export function InvestigationProvider({ investigation, children }: { investigation: InvestigationDetail; children: React.ReactNode }) {
  const can = (permission: string) => investigation.permissions.includes(permission);
  return <InvestigationContext.Provider value={{ investigation, can }}>{children}</InvestigationContext.Provider>;
}

export function useInvestigation(): Ctx {
  const ctx = useContext(InvestigationContext);
  if (!ctx) throw new Error("useInvestigation must be used inside an investigation page");
  return ctx;
}

export function path(id: string, section = ""): string {
  return `/investigations/${id}${section ? `/${section}` : ""}`;
}
