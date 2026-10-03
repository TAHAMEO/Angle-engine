"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/feedback";
import { Field, Input, Select, Textarea } from "@/components/ui/form";
import { Dialog } from "@/components/ui/overlay";
import { toast } from "@/components/ui/toast";
import { EvidencePicker, type PickedEvidence } from "@/features/evidence/evidence-picker";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { S } from "@/lib/api/types";
import { useInvestigation } from "@/lib/investigation";

import { ENTITY_LABELS, REL_LABELS } from "./types";

export function useEntities(investigationId: string, enabled = true) {
  return useQuery({
    queryKey: ["investigations", investigationId, "entities"],
    enabled,
    queryFn: () =>
      unwrap(
        api.GET("/api/v1/investigations/{investigation_id}/entities", {
          params: { path: { investigation_id: investigationId }, query: { limit: 100 } },
        }),
      ),
  });
}

export function AddEntityDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const [type, setType] = useState<S<"EntityType">>("organization");
  const [name, setName] = useState("");
  const [basis, setBasis] = useState("");
  const [links, setLinks] = useState<PickedEvidence[]>([]);
  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/entities", {
          params: { path: { investigation_id: inv.id } },
          body: { type, name: name.trim(), public_role_basis: type === "public_figure" ? basis.trim() : null, evidence_ids: links.map((l) => l.evidence_id) },
        }),
      ),
    onSuccess: () => {
      onOpenChange(false);
      setName("");
      setBasis("");
      setLinks([]);
      void client.invalidateQueries({ queryKey: ["investigations", inv.id] });
      toast("Entity added", { tone: "success" });
    },
    onError: (e) => toast("The entity was not added", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      className="max-w-2xl"
      title="Add an entity"
      description="Entities are public things: organizations, websites, documents, places, brands — or public figures in their public role. There is no entity type for private individuals."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={create.isPending}
            disabled={!name.trim() || (type === "public_figure" && basis.trim().length < 10)}
            onClick={() => create.mutate()}
          >
            Add entity
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Type">
            {(props) => (
              <Select {...props} value={type} onChange={(e) => setType(e.target.value as S<"EntityType">)}>
                {Object.entries(ENTITY_LABELS).map(([key, label]) => (
                  <option key={key} value={key}>
                    {label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Name" required>
            {(props) => <Input {...props} value={name} onChange={(e) => setName(e.target.value)} />}
          </Field>
        </div>
        {type === "public_figure" ? (
          <>
            <Alert tone="warning">Only the public role is recorded (e.g. &quot;Mayor of Springfield 2019–2023&quot;) — no private details.</Alert>
            <Field label="Basis for treating them as a public figure" required>
              {(props) => <Textarea {...props} rows={2} value={basis} onChange={(e) => setBasis(e.target.value)} />}
            </Field>
          </>
        ) : null}
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Evidence mentioning it (optional)</legend>
          <EvidencePicker value={links} onChange={setLinks} />
        </fieldset>
      </div>
    </Dialog>
  );
}

export function AddRelationshipDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { investigation: inv } = useInvestigation();
  const client = useQueryClient();
  const { data: entities } = useEntities(inv.id, open);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [relType, setRelType] = useState<S<"RelationshipType">>("mentions");
  const [links, setLinks] = useState<PickedEvidence[]>([]);
  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/api/v1/investigations/{investigation_id}/relationships", {
          params: { path: { investigation_id: inv.id } },
          body: { from_entity_id: from, to_entity_id: to, rel_type: relType, evidence_ids: links.map((l) => l.evidence_id) },
        }),
      ),
    onSuccess: () => {
      onOpenChange(false);
      setLinks([]);
      void client.invalidateQueries({ queryKey: ["investigations", inv.id] });
      toast("Relationship added", { description: "It starts as unverified.", tone: "success" });
    },
    onError: (e) => toast("The relationship was not added", { description: messageOf(e), tone: "danger" }),
  });
  const options = (entities?.items ?? []).map((e) => (
    <option key={e.id} value={e.id}>
      {e.name} ({ENTITY_LABELS[e.type] ?? e.type})
    </option>
  ));
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      className="max-w-2xl"
      title="Add a relationship"
      description="Every relationship needs at least one evidence item that supports it."
      footer={
        <>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" loading={create.isPending} disabled={!from || !to || from === to || !links.length} onClick={() => create.mutate()}>
            Add relationship
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="From">
            {(props) => (
              <Select {...props} value={from} onChange={(e) => setFrom(e.target.value)}>
                <option value="">Choose…</option>
                {options}
              </Select>
            )}
          </Field>
          <Field label="Relationship">
            {(props) => (
              <Select {...props} value={relType} onChange={(e) => setRelType(e.target.value as S<"RelationshipType">)}>
                {Object.entries(REL_LABELS).map(([key, label]) => (
                  <option key={key} value={key}>
                    {label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="To">
            {(props) => (
              <Select {...props} value={to} onChange={(e) => setTo(e.target.value)}>
                <option value="">Choose…</option>
                {options}
              </Select>
            )}
          </Field>
        </div>
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">
            Supporting evidence <span className="text-danger">*</span>
          </legend>
          <EvidencePicker value={links} onChange={setLinks} />
        </fieldset>
      </div>
    </Dialog>
  );
}
