/**
 * IntegrityVerifier.tsx — Tab 3: Verify Document Integrity
 * Compares signing-time hash (bundle / Tab 2) vs freshly computed hash,
 * and runs RSA-PSS cryptographic verification via Web Crypto.
 */
import { useState, useRef, useEffect } from 'react';
import {
  FileSearch,
  ShieldCheck,
  ShieldX,
  Upload,
  Key,
  X,
  CheckCircle2,
  Search,
  FileText,
  Copy,
} from 'lucide-react';
import {
  sha256Hex,
  verifySignature,
  importPublicKeyFromPEM,
} from '../lib/rsaCrypto';
import {
  readFileAsArrayBuffer,
  readFileAsText,
  formatFileSize,
  getFileIcon,
  parseJSONBundle,
  copyTextToClipboard,
} from '../lib/fileHelpers';
import HashComparison from './HashComparison';
import TamperSimulator from './TamperSimulator';

interface Props {
  publicKeyPEM: string;
  prefillSignature?: string;
  prefillHash?: string;
  prefillFileName?: string;
  prefillBuffer?: ArrayBuffer;
  addToast: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

export default function IntegrityVerifier({
  publicKeyPEM,
  prefillSignature,
  prefillHash,
  prefillFileName,
  prefillBuffer,
  addToast,
}: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [fileBuffer, setFileBuffer] = useState<ArrayBuffer | null>(prefillBuffer ?? null);
  const [computedHash, setComputedHash] = useState(prefillHash ?? '');
  const [originalHash, setOriginalHash] = useState(prefillHash ?? '');
  const [activeBuffer, setActiveBuffer] = useState<ArrayBuffer | null>(prefillBuffer ?? null);
  const [signature, setSignature] = useState(prefillSignature ?? '');
  const [pubKeyPEM, setPubKeyPEM] = useState(publicKeyPEM);
  const [verifyResult, setVerifyResult] = useState<boolean | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  const fileRef = useRef<HTMLInputElement>(null);
  const sigFileRef = useRef<HTMLInputElement>(null);
  const pubKeyFileRef = useRef<HTMLInputElement>(null);

  // Sync public key when (re)generated in Tab 1 — don't clobber manual edits
  useEffect(() => {
    if (publicKeyPEM && publicKeyPEM !== pubKeyPEM) {
      setPubKeyPEM((current) => (current.trim() === '' ? publicKeyPEM : current));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [publicKeyPEM]);

  useEffect(() => {
    if (prefillSignature) setSignature((cur) => cur || prefillSignature);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefillSignature]);

  useEffect(() => {
    if (prefillBuffer && prefillHash) {
      setFileBuffer((cur) => cur ?? prefillBuffer.slice(0));
      setActiveBuffer((cur) => cur ?? prefillBuffer.slice(0));
      setComputedHash((cur) => cur || prefillHash);
      setOriginalHash((cur) => cur || prefillHash);
      setVerifyResult(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefillBuffer, prefillHash]);

  async function handleFileSelect(selected: File) {
    setFile(selected);
    setVerifyResult(null);
    const buf = await readFileAsArrayBuffer(selected);
    setFileBuffer(buf);
    setActiveBuffer(buf);
    const h = await sha256Hex(buf);
    setComputedHash(h);
    // NOTE: do NOT overwrite originalHash here — it must stay as the
    // signing-time reference so tampering shows a mismatch.
  }

  async function loadSigFile(f: File) {
    const text = await readFileAsText(f);
    if (f.name.endsWith('.json')) {
      const bundle = parseJSONBundle(text);
      if (bundle?.signature) {
        setSignature(bundle.signature);
        if (bundle.sha256Hash) {
          setOriginalHash(bundle.sha256Hash);
          addToast(`Bundle loaded: signing-time hash ${bundle.sha256Hash.slice(0, 12)}… restored.`, 'info');
        } else {
          addToast('Signature loaded from JSON bundle.', 'info');
        }
        if (bundle.fileName) {
          addToast(`Expected file: ${bundle.fileName}`, 'info');
        }
        setVerifyResult(null);
        return;
      }
      addToast('Invalid bundle JSON — no signature field found.', 'error');
      return;
    }
    setSignature(text.trim());
    setVerifyResult(null);
    addToast('Signature loaded from file.', 'info');
  }

  async function handleVerify() {
    if (!activeBuffer || !signature.trim() || !pubKeyPEM.trim()) {
      addToast('Please provide a document, signature, and public key.', 'error');
      return;
    }
    setVerifying(true);
    try {
      const pubKey = await importPublicKeyFromPEM(pubKeyPEM);
      const result = await verifySignature(pubKey, signature.trim(), activeBuffer);
      setVerifyResult(result);
      if (result) {
        addToast('Signature VALID — Document is authentic!', 'success');
      } else {
        addToast('Signature INVALID — Integrity violation detected!', 'error');
      }
    } catch (err) {
      addToast('Verification error: ' + String(err), 'error');
      setVerifyResult(false);
    } finally {
      setVerifying(false);
    }
  }

  function handleTamperedBuffer(buf: ArrayBuffer, hash: string) {
    setActiveBuffer(buf);
    setComputedHash(hash);
    setVerifyResult(null);
  }

  function handleResetTamper() {
    if (fileBuffer) {
      setActiveBuffer(fileBuffer.slice(0));
      sha256Hex(fileBuffer).then(setComputedHash);
      setVerifyResult(null);
    } else if (prefillBuffer) {
      setActiveBuffer(prefillBuffer.slice(0));
      sha256Hex(prefillBuffer).then(setComputedHash);
      setVerifyResult(null);
    }
  }

  function handleClearAll() {
    setFile(null);
    setFileBuffer(null);
    setActiveBuffer(null);
    setComputedHash('');
    setOriginalHash('');
    setVerifyResult(null);
  }

  const canVerify = !!(activeBuffer && signature.trim() && pubKeyPEM.trim());
  const showComparison = !!(computedHash && originalHash);

  return (
    <div>
      {/* Prefill banner */}
      {prefillSignature && prefillHash && (
        <div
          className="info-row"
          style={{
            marginBottom: '1rem',
            color: '#fff',
            background: '#000',
            border: '1px solid #000',
            borderRadius: 8,
            padding: '0.6rem 0.9rem',
          }}
        >
          <CheckCircle2 size={13} />
          Signature + signing-time hash auto-loaded from Tab 2
          {prefillFileName ? ` (${prefillFileName})` : ''} — just upload the document (or use the
          pre-loaded buffer) and hit Verify.
        </div>
      )}

      {/* File Upload */}
      <div className="section-card">
        <div className="section-title">
          <FileSearch size={14} />
          Upload Document to Verify
        </div>

        <div
          className={`dropzone ${dragOver ? 'drag-over' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const f = e.dataTransfer.files[0];
            if (f) void handleFileSelect(f);
          }}
          onClick={() => fileRef.current?.click()}
        >
          <input
            ref={fileRef}
            type="file"
            id="verifier-file-input"
            style={{ display: 'none' }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleFileSelect(f);
            }}
          />
          <div className="dropzone-icon">
            <FileSearch size={22} />
          </div>
          <div className="dropzone-title">
            {file ? 'Drop a new file to replace' : 'Drop the received document here'}
          </div>
          <div className="dropzone-sub">Any file type supported</div>
        </div>

        {(file || activeBuffer) && (
          <div className="file-selected">
            <div className="file-selected-icon">
              {getFileIcon(file?.name ?? prefillFileName ?? '')}
            </div>
            <div className="file-selected-info">
              <div className="file-selected-name">{file?.name ?? prefillFileName ?? 'pre-loaded file (from Tab 2)'}</div>
              <div className="file-selected-size">
                {file ? formatFileSize(file.size) : `${activeBuffer?.byteLength ?? 0} bytes (in-memory)`}
              </div>
            </div>
            <button
              className="btn btn-secondary btn-sm btn-icon"
              onClick={(e) => {
                e.stopPropagation();
                handleClearAll();
              }}
              title="Clear document"
            >
              <X size={13} />
            </button>
          </div>
        )}

        {computedHash && (
          <div style={{ marginTop: '0.75rem' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.3rem' }}>
              Computed SHA-256 Hash (of current buffer)
            </div>
            <div className="hash-display" id="verifier-hash-display">
              {computedHash}
            </div>
          </div>
        )}

        {/* Signing-time reference hash — editable so bundle-less flows still work */}
        <div style={{ marginTop: '0.75rem' }}>
          <label className="form-label" htmlFor="verifier-original-hash">
            Signing-Time Reference Hash (from bundle JSON / Tab 2)
          </label>
          <input
            id="verifier-original-hash"
            className="form-textarea"
            style={{ minHeight: 'auto', height: 44, fontSize: '0.72rem' }}
            value={originalHash}
            onChange={(e) => { setOriginalHash(e.target.value.trim()); setVerifyResult(null); }}
            placeholder="Paste the sha256Hash from the bundle JSON…"
            spellCheck={false}
          />
          {!originalHash && computedHash && (
            <div className="info-row" style={{ color: '#525252' }}>
              No reference hash yet — paste one from the bundle JSON to enable bit-for-bit comparison.
            </div>
          )}
        </div>
      </div>

      {/* Signature Input */}
      <div className="section-card">
        <div className="section-title">
          <FileText size={14} />
          Digital Signature
        </div>
        <textarea
          id="verifier-signature-input"
          className="form-textarea"
          style={{ height: 110, fontFamily: 'JetBrains Mono', fontSize: '0.72rem' }}
          value={signature}
          onChange={(e) => { setSignature(e.target.value); setVerifyResult(null); }}
          placeholder="Paste Base64 RSA signature here…"
          spellCheck={false}
        />
        <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button className="btn btn-secondary btn-sm" onClick={() => sigFileRef.current?.click()}>
            <Upload size={12} /> Upload .sig / JSON bundle
          </button>
          {signature && (
            <>
              <button
                className="btn btn-secondary btn-sm"
                onClick={async () => {
                  const ok = await copyTextToClipboard(signature);
                  addToast(ok ? 'Signature copied!' : 'Copy failed.', ok ? 'success' : 'error');
                }}
              >
                <Copy size={12} /> Copy
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => { setSignature(''); setVerifyResult(null); }}>
                <X size={12} /> Clear
              </button>
            </>
          )}
          <input
            ref={sigFileRef}
            type="file"
            accept=".sig,.json"
            style={{ display: 'none' }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void loadSigFile(f);
            }}
          />
        </div>
      </div>

      {/* Public Key */}
      <div className="section-card">
        <div className="section-title">
          <Key size={14} />
          Public Key (Signer&apos;s)
        </div>
        {publicKeyPEM && (
          <div className="info-row" style={{ marginBottom: '0.75rem', color: '#000', fontWeight: 600 }}>
            <CheckCircle2 size={13} />
            Auto-populated from Key Management tab — or paste / upload below.
          </div>
        )}
        <textarea
          id="verifier-public-key-input"
          className="form-textarea"
          style={{ height: 120, fontFamily: 'JetBrains Mono', fontSize: '0.72rem' }}
          value={pubKeyPEM}
          onChange={(e) => { setPubKeyPEM(e.target.value); setVerifyResult(null); }}
          placeholder="-----BEGIN PUBLIC KEY-----&#10;Paste the signer's PEM public key…&#10;-----END PUBLIC KEY-----"
          spellCheck={false}
        />
        <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-secondary btn-sm" onClick={() => pubKeyFileRef.current?.click()}>
            <Upload size={12} /> Upload .pem
          </button>
          {pubKeyPEM && (
            <button className="btn btn-secondary btn-sm" onClick={() => setPubKeyPEM('')}>
              <X size={12} /> Clear
            </button>
          )}
          <input
            ref={pubKeyFileRef}
            type="file"
            accept=".pem"
            style={{ display: 'none' }}
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (f) {
                const text = await readFileAsText(f);
                setPubKeyPEM(text);
                addToast('Public key loaded.', 'info');
              }
            }}
          />
        </div>
      </div>

      {/* Verify Button */}
      <div style={{ textAlign: 'center', padding: '0.5rem 0 1.25rem' }}>
        <button
          id="verify-integrity-btn"
          className={`btn btn-lg ${verifyResult === null ? 'btn-primary' : verifyResult ? 'btn-success' : 'btn-danger'}`}
          onClick={() => void handleVerify()}
          disabled={!canVerify || verifying}
        >
          {verifying ? (
            <>
              <div className="spinner" /> Verifying…
            </>
          ) : (
            <>
              <Search size={17} /> Verify Integrity
            </>
          )}
        </button>
        {!canVerify && (
          <div className="info-row" style={{ justifyContent: 'center', marginTop: '0.5rem', color: '#525252' }}>
            Provide a document + signature + public key to enable verification.
          </div>
        )}
      </div>

      {/* Result Banner */}
      {verifyResult === true && (
        <div className="result-banner valid glow-pulse-success" id="verify-result-valid">
          <div className="result-banner-icon">
            <ShieldCheck size={22} />
          </div>
          <div>
            <div className="result-banner-title">Data Integrity Verified — VALID</div>
            <div className="result-banner-msg">
              Document is authentic and unmodified. The signature matches the public key perfectly.
            </div>
          </div>
        </div>
      )}

      {verifyResult === false && (
        <div className="result-banner invalid glow-pulse-danger" id="verify-result-invalid">
          <div className="result-banner-icon">
            <ShieldX size={22} />
          </div>
          <div>
            <div className="result-banner-title">Integrity Violation Detected — INVALID</div>
            <div className="result-banner-msg">
              The document has been altered, or the signature / key is mismatched. Do not trust this document.
            </div>
          </div>
        </div>
      )}

      {/* Hash Comparison — always visible once both hashes exist */}
      {showComparison && (
        <HashComparison
          computedHash={computedHash}
          originalHash={originalHash}
          isValid={verifyResult}
        />
      )}

      {/* Tamper Simulator */}
      <TamperSimulator
        fileBuffer={activeBuffer}
        originalHash={originalHash || computedHash}
        onTamperedBuffer={handleTamperedBuffer}
        onReset={handleResetTamper}
        addToast={addToast}
      />
    </div>
  );
}
