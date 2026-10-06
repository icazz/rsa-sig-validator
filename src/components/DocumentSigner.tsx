/**
 * DocumentSigner.tsx — Tab 2: Sign a Document
 */
import { useState, useRef, useEffect } from 'react';
import {
  FileUp,
  PenLine,
  Hash,
  Copy,
  Download,
  Package,
  Key,
  Upload,
  X,
  CheckCircle2,
  FileText,
  ArrowRight,
} from 'lucide-react';
import {
  sha256Hex,
  signData,
  importPrivateKeyFromPEM,
  createBundle,
} from '../lib/rsaCrypto';
import {
  readFileAsArrayBuffer,
  readFileAsText,
  formatFileSize,
  downloadText,
  downloadJSON,
  getFileIcon,
  copyTextToClipboard,
} from '../lib/fileHelpers';

interface Props {
  privateKeyPEM: string;
  addToast: (msg: string, type?: 'success' | 'error' | 'info') => void;
  onSigned?: (hash: string, sig: string, fileName: string, buffer: ArrayBuffer) => void;
  onGoVerify?: () => void;
  hasSignature?: boolean;
}

export default function DocumentSigner({ privateKeyPEM, addToast, onSigned, onGoVerify }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [fileBuffer, setFileBuffer] = useState<ArrayBuffer | null>(null);
  const [privKeyPEM, setPrivKeyPEM] = useState(privateKeyPEM);
  const [hash, setHash] = useState('');
  const [signature, setSignature] = useState('');
  const [signing, setSigning] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const privKeyFileRef = useRef<HTMLInputElement>(null);

  // Sync prop → state when keys are (re)generated in Tab 1.
  // Only overwrite if user hasn't manually edited the field.
  useEffect(() => {
    if (privateKeyPEM && privateKeyPEM !== privKeyPEM) {
      setPrivKeyPEM((current) => (current.trim() === '' ? privateKeyPEM : current));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [privateKeyPEM]);

  async function handleFileSelect(selected: File) {
    setFile(selected);
    setHash('');
    setSignature('');
    const buf = await readFileAsArrayBuffer(selected);
    setFileBuffer(buf);
    // Compute hash immediately
    const h = await sha256Hex(buf);
    setHash(h);
  }

  async function handleSign() {
    if (!fileBuffer || !privKeyPEM.trim()) {
      addToast('Please select a file and provide a private key.', 'error');
      return;
    }
    setSigning(true);
    try {
      const privKey = await importPrivateKeyFromPEM(privKeyPEM);
      const sig = await signData(privKey, fileBuffer);
      setSignature(sig);
      onSigned?.(hash, sig, file!.name, fileBuffer);
      addToast('Document signed successfully!', 'success');
    } catch (err) {
      addToast('Signing failed: ' + String(err), 'error');
    } finally {
      setSigning(false);
    }
  }

  async function loadPrivKeyFile(f: File) {
    const text = await readFileAsText(f);
    setPrivKeyPEM(text);
    addToast('Private key loaded from file.', 'info');
  }

  function handleExportBundle() {
    if (!file || !hash || !signature) return;
    const bundle = createBundle(file.name, hash, signature);
    downloadJSON(bundle, 'signature-bundle.json');
    addToast('Bundle exported as JSON!', 'success');
  }

  const canSign = !!fileBuffer && !!privKeyPEM.trim();
  const hasSig = !!signature;

  return (
    <div>
      {/* File Upload */}
      <div className="section-card">
        <div className="section-title">
          <FileUp size={14} />
          Select Document to Sign
        </div>

        <div
          className={`dropzone ${dragOver ? 'drag-over' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const f = e.dataTransfer.files[0];
            if (f) handleFileSelect(f);
          }}
          onClick={() => fileRef.current?.click()}
        >
          <input
            ref={fileRef}
            type="file"
            id="signer-file-input"
            style={{ display: 'none' }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) handleFileSelect(f);
            }}
          />
          <div className="dropzone-icon">
            <FileUp size={22} />
          </div>
          <div className="dropzone-title">
            {file ? 'Drop a new file to replace' : 'Drop your document here'}
          </div>
          <div className="dropzone-sub">
            Supports PDF, TXT, PNG, JPG, DOCX, JSON — any file type
          </div>
        </div>

        {file && (
          <div className="file-selected">
            <div className="file-selected-icon">
              {getFileIcon(file.name)}
            </div>
            <div className="file-selected-info">
              <div className="file-selected-name">{file.name}</div>
              <div className="file-selected-size">{formatFileSize(file.size)}</div>
            </div>
            <button
              className="btn btn-secondary btn-sm btn-icon"
              onClick={(e) => { e.stopPropagation(); setFile(null); setFileBuffer(null); setHash(''); setSignature(''); }}
            >
              <X size={13} />
            </button>
          </div>
        )}
      </div>

      {/* SHA-256 Hash */}
      <div className="section-card">
        <div className="section-title">
          <Hash size={14} />
          Document SHA-256 Hash
        </div>
        <div className={`hash-display ${!hash ? 'empty' : ''}`} id="doc-hash-display">
          {hash || 'Hash will appear here after selecting a file…'}
        </div>
        {hash && (
          <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem' }}>
            <button
              className="btn btn-secondary btn-sm"
              onClick={async () => {
                const ok = await copyTextToClipboard(hash);
                addToast(ok ? 'Hash copied!' : 'Copy failed.', ok ? 'success' : 'error');
              }}
            >
              <Copy size={12} /> Copy Hash
            </button>
          </div>
        )}
      </div>

      {/* Private Key */}
      <div className="section-card">
        <div className="section-title">
          <Key size={14} />
          Private Key
        </div>
        {privateKeyPEM && (
          <div
            className="info-row"
            style={{ marginBottom: '0.75rem', color: '#000', fontWeight: 600 }}
          >
            <CheckCircle2 size={13} />
            Auto-populated from Key Management tab — or paste / upload below.
          </div>
        )}
        <textarea
          id="signer-private-key-input"
          className="form-textarea"
          style={{ height: 120, fontFamily: 'JetBrains Mono', fontSize: '0.72rem' }}
          value={privKeyPEM}
          onChange={(e) => setPrivKeyPEM(e.target.value)}
          placeholder="-----BEGIN PRIVATE KEY-----&#10;Paste your PEM private key here…&#10;-----END PRIVATE KEY-----"
          spellCheck={false}
        />
        <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem' }}>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => privKeyFileRef.current?.click()}
          >
            <Upload size={12} />
            Upload .pem
          </button>
          {privKeyPEM && (
            <button className="btn btn-secondary btn-sm" onClick={() => setPrivKeyPEM('')}>
              <X size={12} /> Clear
            </button>
          )}
          <input
            ref={privKeyFileRef}
            type="file"
            accept=".pem"
            style={{ display: 'none' }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) loadPrivKeyFile(f);
            }}
          />
        </div>
      </div>

      {/* Action */}
      <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', justifyContent: 'center', padding: '0.5rem 0 1rem' }}>
        <button
          id="sign-document-btn"
          className="btn btn-primary btn-lg"
          onClick={handleSign}
          disabled={!canSign || signing}
        >
          {signing ? (
            <>
              <div className="spinner" />
              Signing…
            </>
          ) : (
            <>
              <PenLine size={17} />
              Sign Document
            </>
          )}
        </button>
      </div>

      {/* Signature Output */}
      {hasSig && (
        <div className="section-card" style={{ border: '1px solid #000' }}>
          <div className="section-title" style={{ color: '#000' }}>
            <PenLine size={14} />
            RSA-PSS Digital Signature (Base64)
          </div>
          <div className="sig-display" id="signature-output">
            {signature}
          </div>
          <div style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button
              id="copy-signature-btn"
              className="btn btn-secondary btn-sm"
              onClick={async () => {
                const ok = await copyTextToClipboard(signature);
                addToast(ok ? 'Signature copied!' : 'Copy failed.', ok ? 'success' : 'error');
              }}
            >
              <Copy size={12} /> Copy Signature
            </button>
            <button
              id="download-sig-btn"
              className="btn btn-secondary btn-sm"
              onClick={() => { downloadText(signature, 'signature.sig'); addToast('signature.sig downloaded!', 'success'); }}
            >
              <Download size={12} /> signature.sig
            </button>
            <button
              id="export-bundle-btn"
              className="btn btn-secondary btn-sm"
              onClick={handleExportBundle}
              style={{ borderColor: '#000', color: '#000' }}
            >
              <Package size={12} /> Export Bundle JSON
            </button>
            {onGoVerify && (
              <button
                id="goto-verify-btn"
                className="btn btn-success btn-sm"
                onClick={onGoVerify}
              >
                Verify Now <ArrowRight size={12} />
              </button>
            )}
          </div>

          {/* Bundle preview */}
          <div style={{ marginTop: '1rem' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
              <FileText size={11} style={{ display: 'inline', marginRight: '0.3rem' }} />
              Bundle JSON Preview
            </div>
            <pre
              style={{
                fontFamily: 'JetBrains Mono',
                fontSize: '0.7rem',
                color: 'var(--text-code)',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '0.75rem',
                overflow: 'auto',
                maxHeight: '160px',
                margin: 0,
              }}
            >
              {JSON.stringify(createBundle(file?.name ?? '', hash, signature), null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
