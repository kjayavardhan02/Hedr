export function slugify(value: string): string {
  return value.replace(/[^a-z0-9]+/gi, "-").toLowerCase().slice(0, 40);
}

/** Local-date stamp (yyyy-mm-dd) for export filenames. */
export function todayStamp(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export function downloadBlob(content: string, filename: string, type: string): void {
  downloadBinaryBlob(new Blob([content], { type }), filename);
}

/** Same trigger-a-download mechanism as downloadBlob, but for a Blob that
 * already came from a server response (e.g. a generated .xlsx) rather than
 * client-side content. */
export function downloadBinaryBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
