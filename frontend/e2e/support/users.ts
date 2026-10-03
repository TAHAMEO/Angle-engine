/**
 * Demo accounts created by `angel-engine seed-demo` (offline demo / e2e only). The password and TOTP secrets are
 * fixed, public development values and are refused by production settings.
 */
export const DEMO_PASSWORD = "Demo-Harbour-Lantern-2026";

export type Role = "investigator" | "supervisor" | "admin" | "auditor" | "viewer";

export const USERS: Record<Role, { email: string; name: string; totpSecret: string }> = {
  admin: { email: "admin@angel-engine.example", name: "Avery Admin", totpSecret: "2RK6JLGRP5COXCL7EMU726X3YH6MNOCZ" },
  supervisor: { email: "supervisor@angel-engine.example", name: "Sam Supervisor", totpSecret: "QADCK5KE6WZZBFHFU6FNTKT74LEVZ2OK" },
  investigator: { email: "investigator@angel-engine.example", name: "Ivy Investigator", totpSecret: "NZ2AORS6DOMYDQF6G7BM6SDUM634WBKS" },
  viewer: { email: "viewer@angel-engine.example", name: "Vic Viewer", totpSecret: "3CWEOQU3ONX6UMTXD7VCDAPSWC2ATGQA" },
  auditor: { email: "auditor@angel-engine.example", name: "Aud Auditor", totpSecret: "RHVQ3LX6INXMHBX3ZNBL6UNIGUTAP7BH" },
};

/** Storage-state files written by auth.setup.ts (git-ignored: they hold live session cookies). */
export const AUTH: Record<Role, string> = {
  investigator: "e2e/.auth/investigator.json",
  supervisor: "e2e/.auth/supervisor.json",
  admin: "e2e/.auth/admin.json",
  auditor: "e2e/.auth/auditor.json",
  viewer: "e2e/.auth/viewer.json",
};

export const DEMO_INVESTIGATION = "Northwind Coffee Roasters — expansion claims";
export const PENDING_INVESTIGATION = "Public statements attributed to a council spokesperson";
export const DEMO_REPORT = "Northwind expansion — verification report";
export const ACCESS_REQUEST_NAME = "Nia Newcomer";
