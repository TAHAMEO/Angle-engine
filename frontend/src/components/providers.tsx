"use client";

import { QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { Toast, Tooltip } from "radix-ui";
import { useState } from "react";

import { Toaster } from "@/components/ui/toast";
import { makeQueryClient } from "@/lib/query/client";

export function Providers({ children, nonce }: { children: React.ReactNode; nonce?: string }) {
  const [client] = useState(makeQueryClient);
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem disableTransitionOnChange nonce={nonce}>
      <QueryClientProvider client={client}>
        <Tooltip.Provider delayDuration={300}>
          <Toast.Provider swipeDirection="right" duration={6000}>
            {children}
            <Toaster />
          </Toast.Provider>
        </Tooltip.Provider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
