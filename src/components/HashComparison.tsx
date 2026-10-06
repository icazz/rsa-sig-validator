/**
 * HashComparison.tsx — Side-by-side hash comparison table with bit-level diff
 * Monochrome edition: match = black badge, mismatch = inverted badge.
 */
import { ShieldCheck, ShieldX } from 'lucide-react';

interface Props {
  computedHash: string;
  /** Signing-time hash — from JSON bundle or Tab 2 handoff. NOT decrypted from sig (impossible with RSA-PSS). */
  originalHash: string;
  /** Cryptographic verify() result (may be null if not yet verified) */
  isValid: boolean | null;
}

function diffStats(a: string, b: string): { diffChars: number; total: number; pct: number } {
  const total = Math.max(a.length, b.length);
  if (total === 0) return { diffChars: 0, total: 0, pct: 0 };
  let diff = 0;
  for (let i = 0; i < total; i++) {
    if ((a[i] ?? '') !== (b[i] ?? '')) diff++;
  }
  return { diffChars: diff, total, pct: (diff / total) * 100 };
}

export default function HashComparison({ computedHash, originalHash, isValid }: Props) {
  if (!computedHash || !originalHash) return null;

  const hashMatch = computedHash.toLowerCase() === originalHash.toLowerCase();
  const stats = diffStats(originalHash.toLowerCase(), computedHash.toLowerCase());

  function renderHashDiff(reference: string, display: string) {
    const chars: React.ReactNode[] = [];
    const len = Math.max(reference.length, display.length);
    for (let i = 0; i < len; i += 2) {
      const refByte = reference.slice(i, i + 2).toLowerCase();
      const dispByte = display.slice(i, i + 2).toLowerCase();
      const match = refByte === dispByte;
      chars.push(
        <span key={i} className={match ? 'hex-same' : 'hex-changed'}>
          {display.slice(i, i + 2) || '--'}
        </span>,
      );
      if ((i / 2 + 1) % 16 === 0 && i < len - 2) {
        chars.push(<br key={`br-${i}`} />);
      }
    }
    return chars;
  }

  const solidBadge: React.CSSProperties = {
    padding: '0.25rem 0.7rem',
    borderRadius: 20,
    border: '1px solid #000',
    background: '#000',
    color: '#fff',
    fontWeight: 700,
  };
  const outlineBadge: React.CSSProperties = {
    padding: '0.25rem 0.7rem',
    borderRadius: 20,
    border: '1.5px solid #000',
    background: '#fff',
    color: '#000',
    fontWeight: 700,
  };
  const neutralBadge: React.CSSProperties = {
    padding: '0.25rem 0.7rem',
    borderRadius: 20,
    border: '1px solid #d4d4d4',
    background: '#fff',
    color: '#52525b',
  };

  return (
    <div className="section-card" style={{ marginTop: '1rem' }}>
      <div className="section-title">
        {hashMatch ? (
          <ShieldCheck size={14} style={{ color: '#000' }} />
        ) : (
          <ShieldX size={14} style={{ color: '#000' }} />
        )}
        Hash Comparison — Bit-for-Bit Analysis
      </div>

      {/* Summary strip */}
      <div
        style={{
          display: 'flex',
          gap: '0.6rem',
          flexWrap: 'wrap',
          marginBottom: '0.5rem',
          fontSize: '0.75rem',
        }}
      >
        <span style={hashMatch ? solidBadge : outlineBadge}>
          {hashMatch ? '✓ HASHES MATCH' : '✗ HASHES DIFFER'}
        </span>
        <span style={neutralBadge}>
          {stats.diffChars}/{stats.total} hex chars differ ({stats.pct.toFixed(1)}%)
        </span>
        {isValid !== null && (
          <span style={isValid ? solidBadge : outlineBadge}>
            {isValid ? '✓ SIGNATURE VALID' : '✗ SIGNATURE INVALID'}
          </span>
        )}
      </div>

      <table className="hash-compare-table" id="hash-compare-table">
        <thead>
          <tr>
            <th>Source</th>
            <th>SHA-256 Digest (Hex)</th>
            <th style={{ textAlign: 'center' }}>Match</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td className="hash-label">Signing-Time Hash<br /><span style={{ color: 'var(--text-muted)', fontSize: '0.68rem' }}>(from Tab 2 / bundle JSON)</span></td>
            <td>
              <div className="hex-chars">
                {renderHashDiff(computedHash, originalHash)}
              </div>
            </td>
            <td style={{ textAlign: 'center' }}>—</td>
          </tr>
          <tr>
            <td className="hash-label">Computed Hash<br /><span style={{ color: 'var(--text-muted)', fontSize: '0.68rem' }}>(from uploaded file now)</span></td>
            <td>
              <div className="hex-chars">
                {renderHashDiff(originalHash, computedHash)}
              </div>
            </td>
            <td style={{ textAlign: 'center' }}>
              {hashMatch ? (
                <span style={{ color: '#000', fontFamily: 'Inter', fontWeight: 800, fontSize: '0.8rem' }}>
                  ✓ MATCH
                </span>
              ) : (
                <span style={{ color: '#fff', background: '#000', padding: '0.15rem 0.5rem', borderRadius: 4, fontFamily: 'Inter', fontWeight: 800, fontSize: '0.8rem' }}>
                  ✗ MISMATCH
                </span>
              )}
            </td>
          </tr>
        </tbody>
      </table>

      {/* Legend */}
      <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.75rem', fontSize: '0.72rem', color: '#000' }}>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, background: '#a3a3a3', borderRadius: 2, marginRight: 6 }} />Matching bytes</span>
        <span><span style={{ display: 'inline-block', width: 10, height: 10, background: '#000', borderRadius: 2, marginRight: 6 }} />Differing bytes</span>
      </div>

      {!hashMatch && (
        <div className="info-row" style={{ marginTop: '0.5rem', color: '#525252' }}>
          Hashes differ — the file was modified after signing, or the wrong bundle was loaded.
          Cryptographic verification should report INVALID.
        </div>
      )}
    </div>
  );
}
