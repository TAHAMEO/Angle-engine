import { AdminNav } from "@/features/admin/admin-nav";

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <div>
      <AdminNav />
      <div className="mt-6">{children}</div>
    </div>
  );
}
