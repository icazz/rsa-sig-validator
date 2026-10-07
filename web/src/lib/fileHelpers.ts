/**
 * fileHelpers.ts
 * Utilities for reading files as ArrayBuffer / text, formatting sizes, etc.
 */

export function readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

export function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function downloadText(content: string, filename: string, mimeType = 'text/plain'): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadJSON(obj: unknown, filename: string): void {
  downloadText(JSON.stringify(obj, null, 2), filename, 'application/json');
}

export function getFileIcon(name: string): string {
  const ext = name.split('.').pop()?.toLowerCase() ?? '';
  if (!ext) return 'FILE';
  // Monochrome: return uppercase extension tag instead of colorful emoji
  return ext.length <= 4 ? ext.toUpperCase() : 'FILE';
}

export function parseJSONBundle(text: string): {
  fileName?: string;
  sha256Hash?: string;
  signature?: string;
  timestamp?: string;
} | null {
  try {
    const obj = JSON.parse(text) as Record<string, unknown>;
    if (typeof obj !== 'object' || obj === null) return null;
    // Normalise common field variants
    const signature =
      typeof obj.signature === 'string'
        ? obj.signature
        : typeof obj.signatureBase64 === 'string'
          ? obj.signatureBase64
          : undefined;
    const sha256Hash =
      typeof obj.sha256Hash === 'string'
        ? obj.sha256Hash
        : typeof obj.hash === 'string'
          ? obj.hash
          : typeof obj.sha256 === 'string'
            ? obj.sha256
            : undefined;
    const fileName = typeof obj.fileName === 'string' ? obj.fileName : undefined;
    const timestamp = typeof obj.timestamp === 'string' ? obj.timestamp : undefined;
    if (!signature && !sha256Hash) return null;
    return { fileName, sha256Hash, signature, timestamp };
  } catch {
    return null;
  }
}

/** Clipboard copy with fallback for non-secure contexts (file://, http). */
export async function copyTextToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}
