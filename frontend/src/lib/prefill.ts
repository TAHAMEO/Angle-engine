/**
 * One-shot hand-over of a lawful query between pages (an accepted AI query suggestion, a pivot, a lawful alternative).
 * Kept in memory only so free-text queries never land in URLs or browser history.
 */
export interface CollectPrefill {
  query: string;
  input_type?: string;
  connector_id?: string;
}

let pending: CollectPrefill | null = null;

export function setCollectPrefill(value: CollectPrefill): void {
  pending = value;
}

export function takeCollectPrefill(): CollectPrefill | null {
  const value = pending;
  pending = null;
  return value;
}
