export const IN_PROGRESS = new Set(["uploaded", "scanning", "clean", "analyzing"]);

export const CLUE_LABELS: Record<string, string> = {
  visible_text: "Visible text",
  url: "URL",
  domain: "Domain",
  username: "Username",
  hashtag: "Hashtag",
  email_domain: "Email domain",
  date: "Date",
  organization: "Organization",
  brand: "Brand",
  object: "Object",
  landmark: "Landmark",
  sign: "Sign",
  public_location: "Public place",
  exif_field: "Metadata field",
};

export const CLUE_SOURCES: Record<string, string> = {
  ocr: "Text recognition (OCR)",
  metadata: "Embedded metadata",
  objects: "Object detection",
  ai: "AI vision (hypothesis)",
  provider: "Vision provider",
};

export const STAGE_LABELS: Record<string, string> = {
  file_info: "File checks",
  decode: "Safe decoding",
  hashing: "Perceptual hashes",
  metadata: "Metadata",
  faces: "Face detection (count only)",
  ocr: "Text recognition",
  objects: "Object detection",
  preview: "Sanitized preview",
  clues: "Clue extraction",
  sandbox: "Sandbox",
};

export const ACCEPTED_TYPES: Record<string, string[]> = {
  "image/jpeg": [".jpg", ".jpeg"],
  "image/png": [".png"],
  "image/gif": [".gif"],
  "image/webp": [".webp"],
  "image/tiff": [".tif", ".tiff"],
  "image/bmp": [".bmp"],
};

export const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;

export function previewUrl(investigationId: string, imageId: string): string {
  return `/api/v1/investigations/${investigationId}/images/${imageId}/preview`;
}
