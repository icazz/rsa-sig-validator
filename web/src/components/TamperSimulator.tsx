/**
 * TamperSimulator.tsx — Interactive tamper demonstration (Avalanche Effect)
 * Flips one byte, re-hashes, and quantifies how much the digest changed.
 */
import { useState, useEffect, useMemo } from 'react';
import { Zap, RefreshCw, AlertTriangle } from 'lucide-react';
import { tamperBuffer } from '../lib/rsaCrypto';
import { computeHash } from '../lib/cryptoService';

interface Props {
  fileBuffer: ArrayBuffer | null;
  originalHash: string;
  onTamperedBuffer: (buf: ArrayBuffer, hash: string) => void;
  onReset: () => void;
  addToast: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

function avalancheStats(orig: string, tampered: string) {
  if (!orig || !tampered) return null;
  const totalBits = orig.length * 4; // 1 hex char = 4 bits
  let diffBits = 0;
  for (let i = 0; i < orig.length; i++) {
    const a = parseInt(orig[i], 16);
    const b = parseInt(tampered[i] ?? '0', 16);
    let xor = a ^ b;
    while (xor) {
      diffBits += xor & 1;
      xor >>= 1;
    }
  }
  let diffChars = 0;
  for (let i = 0; i < orig.length; i++) {
    if (orig[i]?.toLowerCase() !== tampered[i]?.toLowerCase()) diffChars++;
  }
  return {
    diffBits,
    totalBits,
    bitPct: (diffBits / totalBits) * 100,
    diffChars,
    totalChars: orig.length,
    charPct: (diffChars / orig.length) * 100,
  };
}

export default function TamperSimulator({
  fileBuffer,
  originalHash,
  onTamperedBuffer,
  onReset,
  addToast,
}: Props) {
  const [tamperedHash, setTamperedHash] = useState('');
  const [isTampered, setIsTampered] = useState(false);
  const [running, setRunning] = useState(false);
  const [tamperPos, setTamperPos] = useState<number | null>(null);

  // Reset tamper state whenever a *different* document is loaded.
  // fileBuffer identity changes on upload / handoff, so track its size + hash.
  const bufferKey = fileBuffer ? `${fileBuffer.byteLength}` : 'empty';
  useEffect(() => {
    setTamperedHash('');
    setIsTampered(false);
    setTamperPos(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bufferKey, originalHash]);

  async function handleTamper() {
    if (!fileBuffer || fileBuffer.byteLength === 0) {
      addToast('Load a document in the verify panel first.', 'error');
      return;
    }
    setRunning(true);
    try {
      const pos = Math.max(0, Math.floor(new Uint8Array(fileBuffer).length * 0.2));
      const tampered = tamperBuffer(fileBuffer);
      const { hash: h } = await computeHash(tampered);
      setTamperedHash(h);
      setTamperPos(pos);
      setIsTampered(true);
      onTamperedBuffer(tampered, h);
      addToast('File tampered! One byte flipped — observe the hash change.', 'error');
    } finally {
      setRunning(false);
    }
  }

  function handleReset() {
    setTamperedHash('');
    setIsTampered(false);
    setTamperPos(null);
    onReset();
    addToast('File restored to original.', 'success');
  }

  const stats = useMemo(
    () => (isTampered ? avalancheStats(originalHash, tamperedHash) : null),
    [isTampered, originalHash, tamperedHash],
  );

  // Render char-by-char diff between original and tampered hash
  function renderDiff(orig: string, tampered: string) {
    return tampered.split('').map((ch, i) => {
      const changed = ch.toLowerCase() !== orig[i]?.toLowerCase();
      return (
        <span key={i} className={changed ? 'hex-changed' : 'hex-same'}>
          {ch}
        </span>
      );
    });
  }

  return (
    <div className="tamper-zone" id="tamper-simulator">
      <div className="tamper-zone-header">
        <Zap size={18} style={{ color: '#000' }} />
        <span style={{ fontWeight: 800, fontSize: '0.95rem', color: '#000' }}>
          Tamper Simulator Playground
        </span>
        <span className="tamper-badge">Avalanche Effect Demo</span>
      </div>

      <p style={{ fontSize: '0.8rem', color: '#52525b', margin: '0 0 1rem', lineHeight: 1.6 }}>
        Click <strong>Simulate Tampering</strong> to flip a single byte in the document.
        Watch how even this minimal change produces a completely different SHA-256 hash,
        immediately invalidating the digital signature — this is the <em>Avalanche Effect</em>.
        After tampering, press <strong>Verify Integrity</strong> above to see the banner flip from VALID to INVALID.
      </p>

      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <button
          id="simulate-tamper-btn"
          className="btn btn-danger"
          onClick={() => void handleTamper()}
          disabled={!fileBuffer || isTampered || running}
          title={!fileBuffer ? 'Load a document first' : 'Flip one byte'}
        >
          {running ? (
            <>
              <div className="spinner" /> Tampering…
            </>
          ) : (
            <>
              <Zap size={15} /> Simulate File Tampering
            </>
          )}
        </button>

        {isTampered && (
          <button
            id="reset-tamper-btn"
            className="btn btn-secondary"
            onClick={handleReset}
          >
            <RefreshCw size={15} /> Restore Original
          </button>
        )}
      </div>

      {isTampered && originalHash && tamperedHash && (
        <>
          <div className="avalanche-grid" style={{ marginTop: '1.25rem' }}>
            <div className="avalanche-box">
              <div className="avalanche-label">Original File Hash</div>
              <div className="hex-chars hex-same">
                {originalHash}
              </div>
            </div>
            <div className="avalanche-box" style={{ border: '2px solid #000', background: '#fff' }}>
              <div className="avalanche-label" style={{ color: '#000' }}>
                Tampered File Hash {tamperPos !== null && `(byte #${tamperPos} flipped)`}
              </div>
              <div className="hex-chars">
                {renderDiff(originalHash, tamperedHash)}
              </div>
            </div>
          </div>

          {stats && (
            <div
              style={{
                marginTop: '1rem',
                display: 'flex',
                gap: '0.75rem',
                flexWrap: 'wrap',
                fontSize: '0.75rem',
              }}
            >
              <span
                style={{
                  padding: '0.3rem 0.8rem',
                  borderRadius: 20,
                  background: '#000',
                  border: '1px solid #000',
                  color: '#fff',
                  fontWeight: 700,
                }}
              >
                {stats.diffBits}/{stats.totalBits} bits flipped ({stats.bitPct.toFixed(1)}%)
              </span>
              <span
                style={{
                  padding: '0.3rem 0.8rem',
                  borderRadius: 20,
                  border: '1px solid #000',
                  background: '#fff',
                  color: '#000',
                }}
              >
                {stats.diffChars}/{stats.totalChars} hex chars differ ({stats.charPct.toFixed(1)}%)
              </span>
              <span
                style={{
                  padding: '0.3rem 0.8rem',
                  borderRadius: 20,
                  border: '1px solid #d4d4d4',
                  color: '#52525b',
                }}
              >
                Ideal avalanche ≈ 50% bits — SHA-256 behaves like a random mapping
              </span>
            </div>
          )}
        </>
      )}

      {isTampered && (
        <div
          style={{
            marginTop: '1rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            fontSize: '0.78rem',
            color: '#000',
            fontWeight: 600,
          }}
        >
          <AlertTriangle size={13} />
          Even a single bit flip changes ~50% of the hash bits — this is the Avalanche Effect!
        </div>
      )}
    </div>
  );
}
