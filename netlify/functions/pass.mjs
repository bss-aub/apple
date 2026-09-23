/**
 * BSS membership card — Apple Wallet signing service.
 *
 * The sheet and the form stay in Apps Script. Apps Script cannot make the
 * PKCS#7 signature Apple requires, so this small function does that one job:
 * it is handed a signed note from the form saying who the card is for, and it
 * gives back a finished .pkpass file for the iPhone to open.
 *
 * Nothing here is remembered between requests. Nothing here talks to the sheet.
 *
 * Two addresses:
 *   /pass?t=<note>              the member's card
 *   /pass?check=<SHARED_SECRET> a settings report, so a problem can be found
 *                               without deploying again to investigate
 */

import forge from 'node-forge';
import JSZip from 'jszip';
import crypto from 'node:crypto';

/* ------------------------------------------------------------------ *
 * Settings — all set in Netlify, never in this file.                  *
 * ------------------------------------------------------------------ */
const PASS_TYPE_ID  = process.env.PASS_TYPE_ID;    // pass.com.bss.membership
const TEAM_ID       = process.env.TEAM_ID;         // the OU from the certificate
const P12_BASE64    = process.env.P12_BASE64;      // bss-pass.p12, as one long line
const P12_PASSWORD  = process.env.P12_PASSWORD;    // the password chosen for it
const SHARED_SECRET = process.env.SHARED_SECRET;   // same text as the sheet's APPLE_SECRET
const IMAGE_BASE    = process.env.IMAGE_BASE;      // GitHub folder holding the pictures

const ORG_NAME  = 'Business Student Society';
const PASS_DESC = 'BSS Membership Card';

const ART = [
  'icon.png', 'icon@2x.png', 'icon@3x.png',
  'logo.png', 'logo@2x.png', 'logo@3x.png',
  'strip.png', 'strip@2x.png', 'strip@3x.png'
];

/* Kept between requests so a warm instance does no extra work. */
let artCache = null;
let signerCache = null;

/**
 * The folder the pictures live in.
 *
 * A GitHub page address (github.com/…/blob/…) is turned into the direct file
 * address (raw.githubusercontent.com/…), because only the second kind serves
 * the file itself. Pasting either one works.
 */
function base() {
  if (!IMAGE_BASE) throw new Error('IMAGE_BASE is not set.');
  let url = IMAGE_BASE.trim();
  const m = /^https:\/\/github\.com\/([^/]+)\/([^/]+)\/(?:blob|raw)\/(.+)$/.exec(url);
  if (m) url = 'https://raw.githubusercontent.com/' + m[1] + '/' + m[2] + '/' + m[3];
  return url.endsWith('/') ? url : url + '/';
}

async function fetchBytes(name) {
  const res = await fetch(base() + name);
  if (!res.ok) throw new Error('Could not fetch ' + name + ' — the address gave ' + res.status);
  return Buffer.from(await res.arrayBuffer());
}

async function loadArt() {
  if (artCache) return artCache;
  const out = {};
  const got = await Promise.all(ART.map(n => fetchBytes(n)));
  ART.forEach((n, i) => { out[n] = got[i]; });
  artCache = out;
  return out;
}

/* Apple's intermediate certificate. Public, so it sits beside the pictures. */
async function loadWwdr() {
  const buf = await fetchBytes('AppleWWDRCAG4.cer');
  const text = buf.toString('utf8');
  if (text.includes('BEGIN CERTIFICATE')) return forge.pki.certificateFromPem(text);
  // Downloaded from Apple it is DER, not PEM.
  return forge.pki.certificateFromAsn1(
    forge.asn1.fromDer(forge.util.createBuffer(buf.toString('binary')))
  );
}

async function loadSigner() {
  if (signerCache) return signerCache;
  if (!P12_BASE64) throw new Error('P12_BASE64 is not set.');
  if (!P12_PASSWORD) throw new Error('P12_PASSWORD is not set.');

  let p12;
  try {
    const der = forge.util.createBuffer(Buffer.from(P12_BASE64, 'base64').toString('binary'));
    p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(der), P12_PASSWORD);
  } catch (err) {
    throw new Error('The certificate would not open — P12_BASE64 or P12_PASSWORD is wrong. (' + err.message + ')');
  }

  let key = null, cert = null;
  p12.safeContents.forEach(sc => sc.safeBags.forEach(bag => {
    if (bag.type === forge.pki.oids.pkcs8ShroudedKeyBag || bag.type === forge.pki.oids.keyBag) {
      key = bag.key;
    } else if (bag.type === forge.pki.oids.certBag) {
      const cn = bag.cert.subject.getField('CN');
      if (!cert || (cn && cn.value.indexOf('Pass Type ID') === 0)) cert = bag.cert;
    }
  }));
  if (!key || !cert) throw new Error('The .p12 did not contain both a key and a certificate.');

  signerCache = { key, cert, wwdr: await loadWwdr() };
  return signerCache;
}

/* ------------------------------------------------------------------ *
 * The note from the form.                                             *
 * ------------------------------------------------------------------ */
function b64urlToBuf(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function readToken(token) {
  if (!SHARED_SECRET) throw new Error('SHARED_SECRET is not set.');
  const parts = String(token || '').split('.');
  if (parts.length !== 2) throw new Error('This link is not complete.');

  const expected = crypto.createHmac('sha256', SHARED_SECRET).update(parts[0]).digest();
  const given = b64urlToBuf(parts[1]);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
    throw new Error('This link was not issued by the membership form.');
  }

  const claim = JSON.parse(b64urlToBuf(parts[0]).toString('utf8'));
  if (!claim.e || Date.now() / 1000 > claim.e) {
    throw new Error('This link has expired. Open the membership form again.');
  }
  if (!claim.n || !claim.s) throw new Error('This link is missing the member details.');
  return claim;
}

/* ------------------------------------------------------------------ *
 * Building the card.                                                  *
 * ------------------------------------------------------------------ */
function buildPassJson(claim) {
  return {
    formatVersion: 1,
    passTypeIdentifier: PASS_TYPE_ID,
    teamIdentifier: TEAM_ID,
    serialNumber: String(claim.s),
    organizationName: ORG_NAME,
    description: PASS_DESC,
    logoText: ORG_NAME,
    backgroundColor: 'rgb(46,15,18)',
    foregroundColor: 'rgb(255,255,255)',
    labelColor: 'rgb(216,170,150)',
    /* Stops the card being passed on to somebody else from the phone. */
    sharingProhibited: true,
    storeCard: {
      secondaryFields: [
        { key: 'member', label: 'MEMBER', value: String(claim.n) },
        { key: 'aubid',  label: 'AUB ID', value: String(claim.i || '') }
      ],
      backFields: [
        { key: 'about', label: 'About',
          value: 'This card shows that you are a member of the AUB Business Student Society. ' +
                 'It is personal to you and is not transferable.' },
        { key: 'help', label: 'Lost your card?',
          value: 'Write to the BSS committee and they will reissue it.' }
      ]
    }
  };
}

const sha1 = buf => crypto.createHash('sha1').update(buf).digest('hex');

function signManifest(manifestBuf, signer) {
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(manifestBuf.toString('binary'));
  p7.addCertificate(signer.cert);
  p7.addCertificate(signer.wwdr);
  p7.addSigner({
    key: signer.key,
    certificate: signer.cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() }
    ]
  });
  p7.sign({ detached: true });
  return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
}

async function buildPkpass(claim) {
  const [art, signer] = await Promise.all([loadArt(), loadSigner()]);

  const files = { ...art };
  files['pass.json'] = Buffer.from(JSON.stringify(buildPassJson(claim)), 'utf8');

  const manifest = {};
  for (const name of Object.keys(files)) manifest[name] = sha1(files[name]);
  const manifestBuf = Buffer.from(JSON.stringify(manifest), 'utf8');

  files['manifest.json'] = manifestBuf;
  files['signature'] = signManifest(manifestBuf, signer);

  const zip = new JSZip();
  for (const name of Object.keys(files)) zip.file(name, files[name]);
  return zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
}

/* ------------------------------------------------------------------ *
 * The settings report.                                                *
 *                                                                     *
 * Every setting is exercised here — the certificate is opened, the    *
 * pictures are fetched, a card is built and signed end to end — so a  *
 * single visit says what is wrong instead of costing another deploy.  *
 * ------------------------------------------------------------------ */
async function selfCheck() {
  const out = { ok: true, checked: new Date().toISOString(), settings: {}, steps: {} };

  const seen = v => (v ? 'set' : 'MISSING');
  out.settings = {
    PASS_TYPE_ID: PASS_TYPE_ID || 'MISSING',
    TEAM_ID: TEAM_ID || 'MISSING',
    IMAGE_BASE: IMAGE_BASE || 'MISSING',
    IMAGE_BASE_used: (() => { try { return base(); } catch { return 'MISSING'; } })(),
    P12_BASE64: seen(P12_BASE64),
    P12_PASSWORD: seen(P12_PASSWORD),
    SHARED_SECRET: seen(SHARED_SECRET)
  };

  try {
    const art = await loadArt();
    out.steps.pictures = Object.fromEntries(
      Object.entries(art).map(([n, b]) => [n, b.length + ' bytes'])
    );
  } catch (e) { out.ok = false; out.steps.pictures = 'FAILED — ' + e.message; }

  try {
    const s = await loadSigner();
    out.steps.certificate = {
      pass: s.cert.subject.getField('CN')?.value,
      team: s.cert.subject.getField('OU')?.value,
      expires: s.cert.validity.notAfter.toISOString().slice(0, 10),
      apple: s.wwdr.subject.getField('CN')?.value
    };
    const days = Math.round((s.cert.validity.notAfter - Date.now()) / 86400000);
    out.steps.certificate.daysLeft = days;
    if (days < 0) { out.ok = false; out.steps.certificate.warning = 'EXPIRED — new cards cannot be issued'; }
    else if (days < 30) out.steps.certificate.warning = 'expires soon — renew it';
  } catch (e) { out.ok = false; out.steps.certificate = 'FAILED — ' + e.message; }

  try {
    /* Sign a note exactly as the sheet would, then read it back. */
    const claim = Buffer.from(JSON.stringify({
      n: 'Test Member', i: '202300000', s: 'self-check', e: Math.floor(Date.now() / 1000) + 60
    })).toString('base64url');
    const sig = crypto.createHmac('sha256', SHARED_SECRET || '').update(claim).digest('base64url');
    readToken(claim + '.' + sig);
    out.steps.links = 'the shared secret signs and verifies correctly';
  } catch (e) { out.ok = false; out.steps.links = 'FAILED — ' + e.message; }

  try {
    const pkpass = await buildPkpass({ n: 'Test Member', i: '202300000', s: 'self-check' });
    out.steps.card = 'built and signed, ' + pkpass.length + ' bytes';
  } catch (e) { out.ok = false; out.steps.card = 'FAILED — ' + e.message; }

  out.verdict = out.ok
    ? 'Everything is in place. Put this address in APPLE_SERVICE_URL (without the ?check part) and try it on an iPhone.'
    : 'Something above says FAILED. Fix every setting it names before deploying again — Netlify only picks up ' +
      'changed settings on a new deploy, so one careful pass is cheaper than several.';
  return out;
}

/* ------------------------------------------------------------------ *
 * What the iPhone actually asks for.                                  *
 * ------------------------------------------------------------------ */
export default async (req) => {
  const url = new URL(req.url);
  const check = url.searchParams.get('check');

  /* The report is behind the shared secret, so it is not open to the world. */
  if (check !== null) {
    if (!SHARED_SECRET || check !== SHARED_SECRET) {
      return new Response('Not found', { status: 404 });
    }
    const report = await selfCheck();
    return new Response(JSON.stringify(report, null, 2), {
      status: report.ok ? 200 : 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
    });
  }

  try {
    const claim = readToken(url.searchParams.get('t'));
    const pkpass = await buildPkpass(claim);
    return new Response(pkpass, {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.apple.pkpass',
        'Content-Disposition': 'attachment; filename="bss-membership.pkpass"',
        'Cache-Control': 'no-store'
      }
    });
  } catch (err) {
    const known = /link/i.test(err.message);
    console.error(err);
    return new Response(
      '<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<body style="font-family:-apple-system,Helvetica,Arial;background:#2E0F12;color:#fff;margin:0;' +
      'display:flex;align-items:center;justify-content:center;height:100vh;padding:24px">' +
      '<p style="max-width:22em;text-align:center;line-height:1.5">' +
      (known ? err.message : 'The card could not be made just now. Try again, and tell the committee if it keeps happening.') +
      '</p></body>',
      { status: known ? 400 : 500, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  }
};

export const config = { path: '/pass' };
