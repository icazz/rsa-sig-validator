/**
 * KeyGenerator.tsx — Tab 1: RSA Key Pair Management
 */
import { useState } from 'react';
import {
  Key,
  RefreshCw,
  Copy,
  Download,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import type { KeySize } from '../lib/rsaCrypto';
import {
  generateRSAKeyPair,
  exportPrivateKeyPEM,
  exportPublicKeyPEM,
} from '../lib/rsaCrypto';
import { downloadText, copyTextToClipboard } from '../lib/fileHelpers';

interface Props {
  onKeysGenerated: (priv: string, pub: string) => void;
  privateKeyPEM: string;
  publicKeyPEM: string;
  addToast: (msg: string, type?: 'success' | 'error' | 'info') => void;
}

export default function KeyGenerator({
  onKeysGenerated,
  privateKeyPEM,
  publicKeyPEM,
  addToast,
}: Props) {
  const [keySize, setKeySize] = useState<KeySize>(2048);
  const [generating, setGenerating] = useState(false);

  async function handleGenerate() {
    setGenerating(true);
    try {
      const pair = await generateRSAKeyPair(keySize);
      const [priv, pub] = await Promise.all([
        exportPrivateKeyPEM(pair.privateKey),
        exportPublicKeyPEM(pair.publicKey),
      ]);
      onKeysGenerated(priv, pub);
      addToast(`RSA-${keySize} key pair generated successfully!`, 'success');
    } catch (err) {
      addToast('Key generation failed: ' + String(err), 'error');
    } finally {
      setGenerating(false);
    }
  }

  async function copyToClipboard(text: string, label: string) {
    const ok = await copyTextToClipboard(text);
    addToast(ok ? `${label} copied to clipboard` : 'Copy failed — select the text manually.', ok ? 'success' : 'error');
  }

  const hasKeys = !!privateKeyPEM && !!publicKeyPEM;

  return (
    <div>
      {/* Controls */}
      <div className="section-card">
        <div className="section-title">
          <Key size={14} />
          Key Configuration
        </div>

        <div style={{ display: 'flex', alignItems: 'flex-end', gap: '1rem', flexWrap: 'wrap' }}>
          <div>
            <label className="form-label" htmlFor="key-size-select">
              RSA Key Size
            </label>
            <select
              id="key-size-select"
              className="form-select"
              value={keySize}
              onChange={(e) => setKeySize(Number(e.target.value) as KeySize)}
              disabled={generating}
            >
              <option value={2048}>2048-bit (Recommended)</option>
              <option value={4096}>4096-bit (High Security)</option>
            </select>
          </div>

          <button
            id="generate-keypair-btn"
            className="btn btn-primary btn-lg"
            onClick={handleGenerate}
            disabled={generating}
          >
            {generating ? (
              <>
                <div className="spinner" />
                Generating {keySize}-bit keys…
              </>
            ) : (
              <>
                <RefreshCw size={16} />
                Generate New RSA Key Pair
              </>
            )}
          </button>

          {hasKeys && (
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: '#000', fontWeight: 700, fontSize: '0.8rem' }}>
              <CheckCircle2 size={14} />
              Keys ready
            </span>
          )}
        </div>

        {keySize === 4096 && (
          <div className="info-row" style={{ marginTop: '0.75rem' }}>
            <AlertTriangle size={13} style={{ color: '#525252' }} />
            <span>4096-bit generation may take 5–15 seconds in the browser.</span>
          </div>
        )}
      </div>

      {/* Key Cards */}
      {!hasKeys && (
        <div
          style={{
            textAlign: 'center',
            padding: '3rem',
            color: 'var(--text-muted)',
            border: '2px dashed var(--border-subtle)',
            borderRadius: '16px',
          }}
        >
          <Key size={40} style={{ margin: '0 auto 1rem', opacity: 0.3 }} />
          <div style={{ fontSize: '0.9rem' }}>
            Click <strong style={{ color: 'var(--text-secondary)' }}>Generate New RSA Key Pair</strong> to create your cryptographic keys.
          </div>
          <div style={{ fontSize: '0.78rem', marginTop: '0.5rem', opacity: 0.7 }}>
            Keys are generated entirely in your browser — nothing leaves your device.
          </div>
        </div>
      )}

      {hasKeys && (
        <div className="two-col-grid">
          {/* Private Key */}
          <div className="key-card">
            <div className="key-card-header">
              <div className="key-card-title key-private-title">
                <Lock size={13} />
                Private Key
                <span style={{ fontFamily: 'JetBrains Mono', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'none', fontWeight: 400 }}>
                  (PKCS#8)
                </span>
              </div>
              <div className="key-actions">
                <button
                  id="copy-private-key-btn"
                  className="btn btn-secondary btn-sm"
                  onClick={() => copyToClipboard(privateKeyPEM, 'Private key')}
                  data-tooltip="Copy to clipboard"
                >
                  <Copy size={12} />
                  Copy
                </button>
                <button
                  id="download-private-key-btn"
                  className="btn btn-secondary btn-sm"
                  onClick={() => downloadText(privateKeyPEM, 'private_key.pem')}
                  data-tooltip="Download PEM file"
                >
                  <Download size={12} />
                  .pem
                </button>
              </div>
            </div>
            <textarea
              id="private-key-textarea"
              className="key-textarea"
              readOnly
              value={privateKeyPEM}
              spellCheck={false}
            />
            <div
              style={{
                padding: '0.5rem 1rem',
                background: '#f5f5f5',
                borderTop: '1px solid #e5e5e5',
                fontSize: '0.7rem',
                color: '#000',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
              }}
            >
              <Lock size={10} />
              Keep this secret — never share your private key
            </div>
          </div>

          {/* Public Key */}
          <div className="key-card">
            <div className="key-card-header">
              <div className="key-card-title key-public-title">
                <Unlock size={13} />
                Public Key
                <span style={{ fontFamily: 'JetBrains Mono', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'none', fontWeight: 400 }}>
                  (SPKI)
                </span>
              </div>
              <div className="key-actions">
                <button
                  id="copy-public-key-btn"
                  className="btn btn-secondary btn-sm"
                  onClick={() => copyToClipboard(publicKeyPEM, 'Public key')}
                  data-tooltip="Copy to clipboard"
                >
                  <Copy size={12} />
                  Copy
                </button>
                <button
                  id="download-public-key-btn"
                  className="btn btn-secondary btn-sm"
                  onClick={() => downloadText(publicKeyPEM, 'public_key.pem')}
                  data-tooltip="Download PEM file"
                >
                  <Download size={12} />
                  .pem
                </button>
              </div>
            </div>
            <textarea
              id="public-key-textarea"
              className="key-textarea"
              readOnly
              value={publicKeyPEM}
              spellCheck={false}
            />
            <div
              style={{
                padding: '0.5rem 1rem',
                background: '#f5f5f5',
                borderTop: '1px solid #e5e5e5',
                fontSize: '0.7rem',
                color: '#000',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
              }}
            >
              <Unlock size={10} />
              Safe to share — used by recipients to verify your signature
            </div>
          </div>
        </div>
      )}

      {/* Info Section */}
      <div
        style={{
          marginTop: '1.5rem',
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '1rem',
        }}
      >
        {[
          { label: 'Algorithm', value: 'RSA-PSS', icon: '01' },
          { label: 'Hash Function', value: 'SHA-256', icon: '02' },
          { label: 'Padding Scheme', value: 'PSS + Salt=32', icon: '03' },
        ].map((item) => (
          <div
            key={item.label}
            style={{
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '10px',
              padding: '0.875rem',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '1.3rem', marginBottom: '0.3rem' }}>{item.icon}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>
              {item.label}
            </div>
            <div
              style={{
                fontFamily: 'JetBrains Mono',
                fontSize: '0.8rem',
                fontWeight: 600,
                color: '#000',
              }}
            >
              {item.value}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
