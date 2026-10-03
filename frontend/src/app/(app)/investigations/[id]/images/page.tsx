import type { Metadata } from "next";

import { ImageList } from "@/features/images/image-list";

export const metadata: Metadata = { title: "Image analysis · Angel Engine" };

export default function ImagesPage() {
  return <ImageList />;
}
