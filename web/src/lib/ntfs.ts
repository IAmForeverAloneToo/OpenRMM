/** Drive letters typed for an NTFS collection: [] for the system drive,
 * ["all"], or letters such as ["C:", "D:"]; null when not valid. */
export function ntfsVolumes(text: string): string[] | null {
  const parts = text.split(/[\s,]+/).filter(Boolean);
  if (parts.length === 1 && parts[0]?.toLowerCase() === "all") return ["all"];
  const out: string[] = [];
  for (const p of parts) {
    const letter = /^([a-zA-Z]):?$/.exec(p)?.[1];
    if (!letter) return null;
    const v = letter.toUpperCase() + ":";
    if (out.includes(v)) return null;
    out.push(v);
  }
  return out;
}
