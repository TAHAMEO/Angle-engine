import { expect, signIn, test as setup } from "./support/fixtures";
import { AUTH, type Role } from "./support/users";

const ROLES: Role[] = ["investigator", "supervisor", "admin", "auditor"];

for (const role of ROLES) {
  setup(`sign in as ${role}`, async ({ page, context }) => {
    await signIn(page, role);
    await expect(page.getByRole("button", { name: /^Account: / })).toBeVisible();

    // The session cookie is never readable by scripts and never sent cross-site.
    const cookies = await context.cookies();
    const session = cookies.find((cookie) => cookie.name.endsWith("ae_sid"));
    expect(session, "session cookie").toBeDefined();
    expect(session?.httpOnly).toBe(true);
    expect(session?.sameSite).toBe("Strict");
    for (const cookie of cookies.filter((c) => c.name.includes("ae_"))) expect(cookie.sameSite).toBe("Strict");

    await context.storageState({ path: AUTH[role] });
  });
}
