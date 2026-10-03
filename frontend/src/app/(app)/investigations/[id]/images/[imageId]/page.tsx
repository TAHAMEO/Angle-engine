import type { Metadata } from "next";

import { ImageDetailView } from "@/features/images/image-detail";

export const metadata: Metadata = { title: "Image · Angel Engine" };

export default function ImageDetailPage() {
  return <ImageDetailView />;
}
