/**
 * App.tsx — RSA Digital Signature & Data Integrity Verifier
 * 3-tab dashboard with shared key state persisted to localStorage.
 */
import { useState, useEffect } from 'react';
import { ShieldCheck, Trash2, ArrowRight } from 'lucide-react';
import KeyGenerator from './components/KeyGenerator';
import DocumentSigner from './components/DocumentSigner';
import IntegrityVerifier from './components/IntegrityVerifier';
import { useToast } from './lib/useToast';
import { detectEngine, type Engine } from './lib/cryptoService';
import './index.css';

type Tab = 'keys' | 'sign' | 'verify';

const LS_PRIV = 'rsa-validator.privateKey';
const LS_PUB = 'rsa-validator.publicKey';

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('keys');

  // Shared key state across all tabs — persisted so refresh doesn't wipe keys
  const [privateKeyPEM, setPrivateKeyPEM] = useState(() => {
    try {
      return localStorage.getItem(LS_PRIV) ?? '';
    } catch {
      return '';
    }
  });
  const [publicKeyPEM, setPublicKeyPEM] = useState(() => {
    try {
      return localStorage.getItem(LS_PUB) ?? '';
    } catch {
      return '';
    }
  });

  // Propagate signed data to verifier for one-click demo
  const [signedSig, setSignedSig] = useState('');
  const [signedHash, setSignedHash] = useState('');
  const [signedFileName, setSignedFileName] = useState('');
  const [signedBuffer, setSignedBuffer] = useState<ArrayBuffer | undefined>(undefined);

  const { toasts, addToast } = useToast();

  // Mesin kriptografi aktif: backend Python bila tersedia, bila tidak mesin lokal.
  const [engine, setEngine] = useState<Engine | null>(null);

  useEffect(() => {
    detectEngine().then(setEngine);
  }, []);

  // Persist keys on change
  useEffect(() => {
    try {
      if (privateKeyPEM) localStorage.setItem(LS_PRIV, privateKeyPEM);
      else localStorage.removeItem(LS_PRIV);
    } catch {
      /* storage unavailable — ignore */
    }
  }, [privateKeyPEM]);

  useEffect(() => {
    try {
      if (publicKeyPEM) localStorage.setItem(LS_PUB, publicKeyPEM);
      else localStorage.removeItem(LS_PUB);
    } catch {
      /* storage unavailable — ignore */
    }
  }, [publicKeyPEM]);

  function handleKeysGenerated(priv: string, pub: string) {
    setPrivateKeyPEM(priv);
    setPublicKeyPEM(pub);
  }

  function handleClearKeys() {
    setPrivateKeyPEM('');
    setPublicKeyPEM('');
    addToast('Keys cleared from this browser.', 'info');
  }

  function handleSigned(hash: string, sig: string, fileName: string, buffer: ArrayBuffer) {
    setSignedHash(hash);
    setSignedSig(sig);
    setSignedFileName(fileName);
    // Clone the buffer so later tampering in the verifier can't mutate the original
    setSignedBuffer(buffer.slice(0));
  }

  const hasKeys = !!privateKeyPEM && !!publicKeyPEM;
  const hasSignature = !!signedSig;

  // Workflow step: 1 = keys, 2 = signed, 3 = verified (verified tracked in verifier tab)
  const step = !hasKeys ? 1 : !hasSignature ? 2 : 3;

  const tabs: { id: Tab; emoji: string; label: string; stepNum: number }[] = [
    { id: 'keys', emoji: '01', label: 'Key Management', stepNum: 1 },
    { id: 'sign', emoji: '02', label: 'Sign Document', stepNum: 2 },
    { id: 'verify', emoji: '03', label: 'Verify Integrity', stepNum: 3 },
  ];

  return (
    <div className="app-shell">
      {/* ── Header ── */}
      <header className="app-header">
        <div className="header-inner">
          <div className="logo-mark">
            <div className="logo-icon">
              <ShieldCheck size={20} color="#fff" />
            </div>
            <div>
              <div className="logo-text">E-Sign Validator</div>
              <div className="logo-sub">RSA Digital Signature Suite</div>
            </div>
          </div>
          <span className="header-badge" title="Mesin kriptografi yang sedang dipakai">
            {engine === null
              ? 'Checking engine…'
              : engine === 'backend'
                ? 'Python Backend · Manual RSA'
                : 'Local Engine · Manual RSA'}
          </span>
        </div>
      </header>

      {/* ── Main ── */}
      <main className="main-content">
        {/* Hero */}
        <div className="hero-section">
          <h1 className="hero-title">RSA Digital Signature &amp; Data Integrity Verifier</h1>
          <p className="hero-sub">
            Generate cryptographic key pairs, sign digital documents, verify their authenticity,
            and simulate file tampering — all entirely in your browser. No data leaves your device.
          </p>
          <div className="hero-chips">
            {['2048 / 4096-bit RSA', 'SHA-256 Manual', 'PKCS#1 v1.5 Padding', 'Kode RSA Murni', 'Zero Server', 'Avalanche Effect Demo'].map((c) => (
              <span key={c} className="hero-chip">{c}</span>
            ))}
          </div>

          {/* Workflow progress */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              marginTop: '1.5rem',
              flexWrap: 'wrap',
            }}
            aria-label="Workflow progress"
          >
            {tabs.map((t, i) => {
              const done = step > t.stepNum || (t.stepNum === 1 && hasKeys) || (t.stepNum === 2 && hasSignature);
              const current = step === t.stepNum;
              return (
                <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <button
                    onClick={() => setActiveTab(t.id)}
                    className="btn btn-sm"
                    style={{
                      borderRadius: 20,
                      border: done || current ? '1px solid #000' : '1px solid var(--border-default)',
                      background: done || current ? '#000' : '#fff',
                      color: done || current ? '#fff' : 'var(--text-muted)',
                      cursor: 'pointer',
                    }}
                    title={`Go to ${t.label}`}
                  >
                    {done ? '✓ ' : `${t.stepNum}. `}{t.label}
                  </button>
                  {i < tabs.length - 1 && (
                    <ArrowRight size={13} style={{ color: 'var(--text-muted)', opacity: 0.6 }} />
                  )}
                </div>
              );
            })}
          </div>
          {hasKeys && (
            <div style={{ marginTop: '0.75rem' }}>
              <button
                onClick={handleClearKeys}
                className="btn btn-secondary btn-sm"
                title="Remove keys from this browser"
              >
                <Trash2 size={12} /> Clear saved keys
              </button>
            </div>
          )}
        </div>

        {/* ── Tab Navigation ── */}
        <nav className="tab-nav" role="tablist">
          {tabs.map((t) => (
            <button
              key={t.id}
              id={`tab-${t.id}`}
              role="tab"
              aria-selected={activeTab === t.id}
              className={`tab-btn ${activeTab === t.id ? 'active' : ''}`}
              onClick={() => setActiveTab(t.id)}
            >
              <span className="tab-emoji">{t.emoji}</span>
              <span className="tab-label">{t.label}</span>
              {t.id === 'keys' && hasKeys && (
                <span style={{ color: 'inherit', fontSize: '0.8rem', fontWeight: 800 }}>✓</span>
              )}
              {t.id === 'sign' && hasSignature && (
                <span style={{ color: 'inherit', fontSize: '0.8rem', fontWeight: 800 }}>✓</span>
              )}
              {t.id === 'verify' && signedSig && (
                <span
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: '50%',
                    background: 'currentColor',
                    boxShadow: 'none',
                  }}
                />
              )}
            </button>
          ))}
        </nav>

        {/* ── Tab Panels ── */}
        <div role="tabpanel">
          {activeTab === 'keys' && (
            <KeyGenerator
              privateKeyPEM={privateKeyPEM}
              publicKeyPEM={publicKeyPEM}
              onKeysGenerated={handleKeysGenerated}
              addToast={addToast}
            />
          )}

          {activeTab === 'sign' && (
            <DocumentSigner
              privateKeyPEM={privateKeyPEM}
              addToast={addToast}
              onSigned={handleSigned}
              onGoVerify={() => setActiveTab('verify')}
              hasSignature={hasSignature}
            />
          )}

          {activeTab === 'verify' && (
            <IntegrityVerifier
              publicKeyPEM={publicKeyPEM}
              prefillSignature={signedSig}
              prefillHash={signedHash}
              prefillFileName={signedFileName}
              prefillBuffer={signedBuffer}
              addToast={addToast}
            />
          )}
        </div>

        {/* ── How it works (educational) ── */}
        <section className="section-card" style={{ marginTop: '2rem' }}>
          <div className="section-title">📚 How RSA Digital Signatures Work</div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: '1rem',
              fontSize: '0.82rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.65,
            }}
          >
            <div>
              <strong style={{ color: 'var(--text-primary)' }}>1. Hash —</strong> the document
              is hashed with SHA-256 into a fixed 64-char digest. Even 1 flipped bit produces a
              totally different digest (<em>Avalanche Effect</em>).
            </div>
            <div>
              <strong style={{ color: 'var(--text-primary)' }}>2. Sign —</strong> the hash is
              signed with the sender&apos;s <em>private key</em> using manual BigInt
              modular exponentiation (s = m^d mod n, PKCS#1 v1.5 padding),
              producing a Base64 signature.
            </div>
            <div>
              <strong style={{ color: 'var(--text-primary)' }}>3. Verify —</strong> the receiver
              re-hashes the document and checks the signature with the sender&apos;s{' '}
              <em>public key</em>. Match = VALID (authentic); mismatch = INVALID (tampered).
            </div>
          </div>
          <div className="divider" />
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
            Note: the original hash <em>cannot</em> be decrypted back out of the
            signature. That&apos;s why this app compares the{' '}
            <strong>signing-time hash</strong> (stored in the bundle JSON) against the{' '}
            <strong>freshly computed hash</strong> — while cryptographic validity itself is proven
            by the manual <code>verifySignature()</code> routine in <code>rsaCrypto.ts</code>
            (modular exponentiation + PKCS#1 v1.5 unpadding, all hand-written BigInt code).
          </div>
        </section>
      </main>

      {/* ── Footer ── */}
      <footer className="app-footer">
        <span>
          Built with hand-written RSA (BigInt) · PKCS#1 v1.5 · SHA-256 manual · No crypto library · All operations run client-side.
        </span>
      </footer>

      {/* ── Toast Notifications ── */}
      <div style={{ position: 'fixed', bottom: '1.5rem', right: '1.5rem', zIndex: 9999, display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.type}`}>
            {t.type === 'success' && '✓'}
            {t.type === 'error' && '✕'}
            {t.type === 'info' && 'i'}
            {t.message}
          </div>
        ))}
      </div>
    </div>
  );
}
