"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, CheckCircle2, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { z } from "@/lib/zod";

import { PageHeader } from "@/components/shell/app-shell";
import { PolicyDecisionPanel } from "@/components/security/policy-panel";
import { Button } from "@/components/ui/button";
import { Card, DefinitionList } from "@/components/ui/data";
import { Alert, LoadingBlock } from "@/components/ui/feedback";
import { Checkbox, Field, Input, Select, Textarea } from "@/components/ui/form";
import { toast } from "@/components/ui/toast";
import { useLegalDocuments } from "@/features/public/legal-document";
import { api, unwrap } from "@/lib/api/client";
import { PolicyAcknowledgementError, PolicyRefusalError, ValidationError, messageOf, type PolicyPayload } from "@/lib/api/errors";
import type { S } from "@/lib/api/types";
import { cn } from "@/lib/utils";

import { LAWFUL_BASES, PURPOSE_CATEGORIES, SUBJECT_TYPES } from "./labels";

const schema = z.object({
  title: z.string().trim().min(3, "Use at least 3 characters.").max(140, "Use at most 140 characters."),
  description: z.string().max(2000).optional(),
  subject_type: z.enum(Object.keys(SUBJECT_TYPES) as [string, ...string[]], { message: "Choose what the investigation is about." }),
  purpose_category: z.enum(Object.keys(PURPOSE_CATEGORIES) as [string, ...string[]], { message: "Choose a purpose category." }),
  purpose: z
    .string()
    .trim()
    .min(50, "Describe the purpose in at least 50 characters: what you need to establish and why.")
    .max(4000),
  lawful_basis: z.enum(Object.keys(LAWFUL_BASES) as [string, ...string[]], { message: "Choose a lawful basis." }),
  authorization_ref: z.string().max(200).optional(),
  jurisdiction: z.string().max(100).optional(),
  lawful_purpose: z.boolean().refine(Boolean, "Required"),
  no_harassment_or_stalking: z.boolean().refine(Boolean, "Required"),
  no_discrimination: z.boolean().refine(Boolean, "Required"),
  no_impersonation: z.boolean().refine(Boolean, "Required"),
  understand_audit: z.boolean().refine(Boolean, "Required"),
});
type Values = z.infer<typeof schema>;

const STEPS = [
  { title: "Basics", fields: ["title", "description", "subject_type", "purpose_category"] },
  { title: "Purpose and legal basis", fields: ["purpose", "lawful_basis", "authorization_ref", "jurisdiction"] },
  { title: "Attestations", fields: ["lawful_purpose", "no_harassment_or_stalking", "no_discrimination", "no_impersonation", "understand_audit"] },
  { title: "Review", fields: [] },
] as const;

const ATTESTATIONS: { name: keyof Values; label: string }[] = [
  { name: "lawful_purpose", label: "I have a lawful purpose and the authority to carry out this investigation." },
  {
    name: "no_harassment_or_stalking",
    label: "I will not use Angel Engine to harass, stalk, locate or monitor anyone, or to find private contact details.",
  },
  {
    name: "no_discrimination",
    label: "I will not use it to infer sensitive characteristics (health, religion, sexuality, ethnicity, politics) or to discriminate.",
  },
  { name: "no_impersonation", label: "I will not impersonate anyone or create deceptive accounts." },
  { name: "understand_audit", label: "I understand my activity is recorded in a tamper-evident audit log that supervisors and auditors can review." },
];

function StepIndicator({ step }: { step: number }) {
  return (
    <ol className="mb-6 flex flex-wrap gap-2" aria-label="Progress">
      {STEPS.map((s, index) => (
        <li
          key={s.title}
          aria-current={index === step ? "step" : undefined}
          className={cn(
            "flex items-center gap-2 rounded-full border px-3 py-1 text-[13px]",
            index === step ? "border-primary bg-primary/10 font-medium text-foreground" : "border-border text-muted",
          )}
        >
          <span className={cn("grid h-5 w-5 place-items-center rounded-full text-[11px]", index < step ? "bg-success/20 text-success" : "bg-surface-3")}>
            {index < step ? <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> : index + 1}
          </span>
          {s.title}
          {index < step ? <span className="sr-only">(completed)</span> : null}
        </li>
      ))}
    </ol>
  );
}

export function NewInvestigationWizard() {
  const router = useRouter();
  const client = useQueryClient();
  const [step, setStep] = useState(0);
  const [policy, setPolicy] = useState<PolicyPayload | null>(null);
  const [preflight, setPreflight] = useState<S<"PreflightOut"> | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const { data: docs, isPending: docsPending } = useLegalDocuments();
  const terms = docs?.find((d) => d.kind === "terms");
  const aup = docs?.find((d) => d.kind === "acceptable_use");

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: {
      title: "",
      description: "",
      purpose: "",
      authorization_ref: "",
      jurisdiction: "",
      lawful_purpose: false,
      no_harassment_or_stalking: false,
      no_discrimination: false,
      no_impersonation: false,
      understand_audit: false,
    },
  });
  const { register, formState, getValues, setValue, trigger, setError, control } = form;
  const errors = formState.errors;
  const purposeLength = useWatch({ control, name: "purpose" })?.trim().length ?? 0;
  const subject = useWatch({ control, name: "subject_type" });

  const focusHeading = () => window.setTimeout(() => headingRef.current?.focus(), 0);

  const runPreflight = async (): Promise<boolean> => {
    const values = getValues();
    try {
      const result = await unwrap(
        api.POST("/api/v1/policy/preflight", {
          body: { text: values.purpose, surface: "investigation_purpose", subject_type: values.subject_type as S<"SubjectType"> },
        }),
      );
      setPreflight(result);
      return result.decision !== "refuse";
    } catch (error) {
      if (error instanceof PolicyRefusalError) {
        // Refusals are recorded server-side and come back as a policy-refused problem.
        const policy = error.policy;
        setPreflight({
          decision: "refuse",
          categories: policy.categories,
          notices: policy.notices ?? [],
          rationale: policy.rationale ?? "",
          alternatives: (policy.alternatives ?? []).map((a) => ({ ...a })),
          requires_acknowledgement: false,
          requires_review: false,
        });
        return false;
      }
      toast("The purpose could not be checked", { description: messageOf(error), tone: "danger" });
      return false;
    }
  };

  const next = async () => {
    const ok = await trigger(STEPS[step]!.fields as unknown as (keyof Values)[]);
    if (!ok) return;
    if (step === 1 && !(await runPreflight())) return;
    setStep((s) => s + 1);
    focusHeading();
  };

  const create = useMutation({
    mutationFn: (acknowledge: boolean) => {
      const v = getValues();
      return unwrap(
        api.POST("/api/v1/investigations", {
          body: {
            title: v.title.trim(),
            description: v.description?.trim() || null,
            subject_type: v.subject_type as S<"SubjectType">,
            purpose_category: v.purpose_category as S<"PurposeCategory">,
            purpose: v.purpose.trim(),
            lawful_basis: v.lawful_basis as S<"LawfulBasis">,
            authorization_ref: v.authorization_ref?.trim() || null,
            jurisdiction: v.jurisdiction?.trim() || null,
            acknowledge_policy_notices: acknowledge,
            attestations: {
              lawful_purpose: v.lawful_purpose,
              no_harassment_or_stalking: v.no_harassment_or_stalking,
              no_discrimination: v.no_discrimination,
              no_impersonation: v.no_impersonation,
              understand_audit: v.understand_audit,
              terms_version: terms?.version ?? "",
              acceptable_use_version: aup?.version ?? "",
            },
          },
        }),
      );
    },
    onSuccess: async (result) => {
      await client.invalidateQueries({ queryKey: ["investigations"] });
      const inv = result.investigation;
      toast(inv.status === "pending_review" ? "Sent for supervisor review" : "Investigation created", {
        description:
          inv.status === "pending_review"
            ? "A supervisor who is not you must approve it. It is read-only until then."
            : `${inv.ref} is ready.`,
        tone: "success",
      });
      router.push(`/investigations/${inv.id}`);
    },
    onError: (error) => {
      if (error instanceof PolicyRefusalError || error instanceof PolicyAcknowledgementError) {
        setPolicy(error.policy);
      } else if (error instanceof ValidationError) {
        for (const item of error.fieldErrors) {
          const field = item.loc[item.loc.length - 1];
          if (typeof field === "string" && field in getValues()) setError(field as keyof Values, { message: item.msg });
        }
        setStep(0);
        toast("Some fields need attention", { tone: "danger" });
      } else {
        toast("The investigation was not created", { description: messageOf(error), tone: "danger" });
      }
    },
  });

  const v = getValues();
  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="New investigation"
        description="Angel Engine works only with public sources and lawful purposes. Every investigation records why it exists and on what legal basis."
      />
      <StepIndicator step={step} />
      <Card className="p-5 sm:p-6">
        <h2 ref={headingRef} tabIndex={-1} className="mb-4 text-lg font-semibold outline-none">
          {STEPS[step]!.title}
        </h2>
        <form
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            if (step < STEPS.length - 1) void next();
            else create.mutate(false);
          }}
          className="space-y-5"
        >
          {step === 0 ? (
            <>
              <Field label="Title" required error={errors.title?.message} hint="Shown to members only. Avoid personal names — the reference ID is used in URLs and page titles.">
                {(props) => <Input {...props} {...register("title")} autoComplete="off" />}
              </Field>
              <Field label="Short description" error={errors.description?.message}>
                {(props) => <Textarea {...props} rows={2} {...register("description")} />}
              </Field>
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">
                  What is the investigation about? <span className="text-danger">*</span>
                </legend>
                <div className="grid gap-2 sm:grid-cols-2">
                  {Object.entries(SUBJECT_TYPES).map(([value, meta]) => (
                    <label
                      key={value}
                      className={cn(
                        "flex cursor-pointer gap-2.5 rounded-md border p-3 text-sm",
                        subject === value ? "border-primary bg-primary/5" : "border-border hover:bg-surface-2",
                      )}
                    >
                      <input type="radio" value={value} {...register("subject_type")} className="mt-1 accent-[var(--primary)]" />
                      <span>
                        <span className="font-medium">{meta.label}</span>
                        <span className="block text-[13px] text-muted">{meta.help}</span>
                      </span>
                    </label>
                  ))}
                </div>
                {errors.subject_type ? <p className="text-[13px] font-medium text-danger">{errors.subject_type.message}</p> : null}
              </fieldset>
              {subject === "individual" ? (
                <Alert tone="warning" title="Individual subjects need approval">
                  A supervisor who is not you must approve this investigation before any work starts. It then runs in restricted mode: no
                  contact or location details, stricter redaction, no AI image analysis or reverse image search, and a second approver for
                  promotions.
                </Alert>
              ) : null}
              <Field label="Purpose category" required error={errors.purpose_category?.message}>
                {(props) => (
                  <Select {...props} {...register("purpose_category")} defaultValue="">
                    <option value="" disabled>
                      Choose…
                    </option>
                    {Object.entries(PURPOSE_CATEGORIES).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </>
          ) : null}

          {step === 1 ? (
            <>
              <Field
                label="Purpose"
                required
                error={errors.purpose?.message}
                hint={`${purposeLength} / 50 characters minimum. Say what you need to establish and why — for example "Verify whether the photo of the flooded station published on 2 March was taken in 2026 or is a recycled older image."`}
              >
                {(props) => <Textarea {...props} rows={5} {...register("purpose", { onChange: () => setPreflight(null) })} />}
              </Field>
              <Field label="Lawful basis" required error={errors.lawful_basis?.message}>
                {(props) => (
                  <Select {...props} {...register("lawful_basis")} defaultValue="">
                    <option value="" disabled>
                      Choose…
                    </option>
                    {Object.entries(LAWFUL_BASES).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Authorization reference" hint="Case, matter, ticket or warrant reference (stored encrypted)." error={errors.authorization_ref?.message}>
                  {(props) => <Input {...props} {...register("authorization_ref")} autoComplete="off" />}
                </Field>
                <Field label="Jurisdiction" hint="For example: EU (GDPR), UK, US-CA." error={errors.jurisdiction?.message}>
                  {(props) => <Input {...props} {...register("jurisdiction")} autoComplete="off" />}
                </Field>
              </div>
              {preflight && preflight.decision !== "allow" ? (
                <PolicyDecisionPanel
                  policy={{ ...preflight, decision: preflight.decision as PolicyPayload["decision"] }}
                  onUseAlternative={(alternative) => {
                    if (alternative.template) setValue("purpose", alternative.template, { shouldValidate: true });
                    setPreflight(null);
                  }}
                />
              ) : null}
            </>
          ) : null}

          {step === 2 ? (
            <>
              {docsPending ? <LoadingBlock /> : null}
              <p className="text-sm text-muted">
                These statements are recorded with this investigation, bound to the{" "}
                <Link href="/legal/terms" target="_blank" className="text-primary underline underline-offset-2 hover:decoration-2">
                  Terms of Use{terms ? ` (version ${terms.version})` : ""}
                </Link>{" "}
                and the{" "}
                <Link href="/legal/acceptable-use" target="_blank" className="text-primary underline underline-offset-2 hover:decoration-2">
                  Acceptable Use Policy{aup ? ` (version ${aup.version})` : ""}
                </Link>
                .
              </p>
              <fieldset className="space-y-3">
                <legend className="sr-only">Attestations</legend>
                {ATTESTATIONS.map((item) => (
                  <div key={item.name}>
                    <Checkbox label={item.label} {...register(item.name)} aria-invalid={errors[item.name] ? true : undefined} />
                    {errors[item.name] ? <p className="mt-1 ml-6.5 text-[13px] font-medium text-danger">Please confirm this statement.</p> : null}
                  </div>
                ))}
              </fieldset>
            </>
          ) : null}

          {step === 3 ? (
            <>
              <DefinitionList
                items={[
                  ["Title", v.title],
                  ["Subject", SUBJECT_TYPES[v.subject_type]?.label ?? "—"],
                  ["Purpose category", PURPOSE_CATEGORIES[v.purpose_category] ?? "—"],
                  ["Purpose", <span key="p" className="whitespace-pre-line">{v.purpose}</span>],
                  ["Lawful basis", LAWFUL_BASES[v.lawful_basis] ?? "—"],
                  ["Authorization reference", v.authorization_ref || "—"],
                  ["Jurisdiction", v.jurisdiction || "—"],
                  ["Attestations", "All five confirmed"],
                ]}
              />
              {preflight?.decision === "review" || v.subject_type === "individual" ? (
                <Alert tone="info" title="After you create it">
                  The investigation goes to a supervisor for approval and stays read-only until then.
                </Alert>
              ) : null}
              {policy ? (
                <PolicyDecisionPanel
                  policy={policy}
                  onAcknowledge={policy.decision === "warn" ? () => create.mutate(true) : undefined}
                  acknowledging={create.isPending}
                  onUseAlternative={(alternative) => {
                    if (alternative.template) setValue("purpose", alternative.template);
                    setPolicy(null);
                    setStep(1);
                    focusHeading();
                  }}
                />
              ) : null}
            </>
          ) : null}

          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-4">
            {step > 0 ? (
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setStep((s) => s - 1);
                  focusHeading();
                }}
              >
                <ArrowLeft className="h-4 w-4" aria-hidden /> Back
              </Button>
            ) : (
              <Button asChild variant="ghost">
                <Link href="/investigations">Cancel</Link>
              </Button>
            )}
            {step < STEPS.length - 1 ? (
              <Button type="submit" variant="primary">
                Continue <ArrowRight className="h-4 w-4" aria-hidden />
              </Button>
            ) : (
              <Button type="submit" variant="primary" loading={create.isPending} disabled={!terms || !aup || (policy?.decision === "refuse")}>
                <ShieldCheck className="h-4 w-4" aria-hidden /> Create investigation
              </Button>
            )}
          </div>
        </form>
      </Card>
    </div>
  );
}
