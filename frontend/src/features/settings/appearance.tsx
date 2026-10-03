"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useTheme } from "next-themes";
import { useSyncExternalStore } from "react";

import { Card, CardHeader } from "@/components/ui/data";
import { toast } from "@/components/ui/toast";
import { api, unwrap } from "@/lib/api/client";
import { messageOf } from "@/lib/api/errors";
import type { User } from "@/lib/api/types";
import { SESSION_KEY, useSession } from "@/lib/session";
import { cn } from "@/lib/utils";

type Theme = "dark" | "light" | "system";
type Density = "comfortable" | "compact";

function Choice<T extends string>({ name, value, options, onChange }: { name: string; value: T; options: { value: T; label: string; help: string }[]; onChange: (value: T) => void }) {
  return (
    <fieldset className="grid gap-2 sm:grid-cols-3">
      <legend className="sr-only">{name}</legend>
      {options.map((option) => (
        <label
          key={option.value}
          className={cn("flex cursor-pointer gap-2.5 rounded-md border p-3 text-sm", value === option.value ? "border-primary bg-primary/5" : "border-border")}
        >
          <input type="radio" name={name} className="mt-1 accent-[var(--primary)]" checked={value === option.value} onChange={() => onChange(option.value)} />
          <span>
            <span className="font-medium">{option.label}</span>
            <span className="block text-[13px] text-muted">{option.help}</span>
          </span>
        </label>
      ))}
    </fieldset>
  );
}

export function AppearanceSettings() {
  const { theme, setTheme } = useTheme();
  const mounted = useSyncExternalStore(
    () => () => undefined,
    () => true,
    () => false,
  );
  const { data } = useSession();
  const client = useQueryClient();
  const user = data?.user as User | undefined;
  const prefs = (user?.preferences ?? {}) as { density?: Density; theme?: Theme };
  const save = useMutation({
    mutationFn: (preferences: { theme?: Theme; density?: Density }) => unwrap(api.PATCH("/api/v1/me", { body: { preferences: { ...prefs, ...preferences } } })),
    onSuccess: () => void client.invalidateQueries({ queryKey: SESSION_KEY }),
    onError: (e) => toast("The preference was not saved", { description: messageOf(e), tone: "danger" }),
  });
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Theme" description="Dark is the default. Both themes meet WCAG AA contrast." />
        <div className="p-4">
          <Choice<Theme>
            name="Theme"
            value={mounted ? ((theme as Theme | undefined) ?? "dark") : "dark"}
            onChange={(value) => {
              setTheme(value);
              save.mutate({ theme: value });
            }}
            options={[
              { value: "dark", label: "Dark", help: "Calm, low-glare workspace." },
              { value: "light", label: "Light", help: "High-key for bright rooms and printing." },
              { value: "system", label: "System", help: "Follow your device setting." },
            ]}
          />
        </div>
      </Card>
      <Card>
        <CardHeader title="Density" description="Saved to your account." />
        <div className="p-4">
          <Choice<Density>
            name="Density"
            value={prefs.density ?? "comfortable"}
            onChange={(value) => save.mutate({ density: value })}
            options={[
              { value: "comfortable", label: "Comfortable", help: "More spacing in tables and lists." },
              { value: "compact", label: "Compact", help: "More rows on screen." },
            ]}
          />
        </div>
      </Card>
    </div>
  );
}
