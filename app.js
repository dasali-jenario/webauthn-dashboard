/* ==========================================================================
   WebAuthn Explorer - Application Logic
   ========================================================================== */

// ==========================================================================
// Element References
// ==========================================================================
const envPill = document.getElementById("envPill");
const envText = document.getElementById("envText");
const browserPill = document.getElementById("browserPill");

// Capabilities Section
const runCapabilitiesBtn = document.getElementById("runCapabilitiesBtn");
const copyCapabilitiesBtn = document.getElementById("copyCapabilitiesBtn");
const capStatusBadge = document.getElementById("capStatusBadge");
const capStatusText = document.getElementById("capStatusText");
const capSummaryStats = document.getElementById("capSummaryStats");
const capStatSupported = document.getElementById("capStatSupported");
const capStatUnsupported = document.getElementById("capStatUnsupported");
const capStatUnknown = document.getElementById("capStatUnknown");
const capabilitiesList = document.getElementById("capabilitiesList");
const capLog = document.getElementById("capLog");
const capLogLabel = document.getElementById("capLogLabel");
const capLogMeta = document.getElementById("capLogMeta");

const pkcIndicator = document.getElementById("pkcIndicator");
const pkcText = document.getElementById("pkcText");
const gccIndicator = document.getElementById("gccIndicator");
const gccText = document.getElementById("gccText");
const uvpaaIndicator = document.getElementById("uvpaaIndicator");
const uvpaaText = document.getElementById("uvpaaText");
const conditionalIndicator = document.getElementById("conditionalIndicator");
const conditionalText = document.getElementById("conditionalText");

// Hints Section
const hintOptions = document.getElementById("hintOptions");
const hintCode = document.getElementById("hintCode");
const testHintsCreateBtn = document.getElementById("testHintsCreateBtn");
const testHintsGetBtn = document.getElementById("testHintsGetBtn");
const hintTestResult = document.getElementById("hintTestResult");
const hintTestResultContent = document.getElementById("hintTestResultContent");

// Extensions Section
const testExtensionsBtn = document.getElementById("testExtensionsBtn");
const extensionResults = document.getElementById("extensionResults");
const extensionRawResults = document.getElementById("extensionRawResults");
const extensionResultsLog = document.getElementById("extensionResultsLog");
const extTestBadge = document.getElementById("extTestBadge");
const extTestStatus = document.getElementById("extTestStatus");

// PRF Section
const testPrfSupportBtn = document.getElementById("testPrfSupportBtn");
const prfSupportBadge = document.getElementById("prfSupportBadge");
const prfSupportStatus = document.getElementById("prfSupportStatus");
const prfTestResults = document.getElementById("prfTestResults");
const prfDemoSection = document.getElementById("prfDemoSection");
const prfSaltInput = document.getElementById("prfSaltInput");
const derivePrfKeyBtn = document.getElementById("derivePrfKeyBtn");
const prfDerivedKeyResult = document.getElementById("prfDerivedKeyResult");
const prfDerivedKeyHex = document.getElementById("prfDerivedKeyHex");

// Store credential for PRF demo
let prfCredentialId = null;

// Conditional UI Section
const testConditionalSupportBtn = document.getElementById("testConditionalSupportBtn");
const conditionalSupportBadge = document.getElementById("conditionalSupportBadge");
const conditionalSupportStatus = document.getElementById("conditionalSupportStatus");
const conditionalTestResults = document.getElementById("conditionalTestResults");
const conditionalDemoInput = document.getElementById("conditionalDemoInput");
const startConditionalGetBtn = document.getElementById("startConditionalGetBtn");
const abortConditionalGetBtn = document.getElementById("abortConditionalGetBtn");
const conditionalGetStatus = document.getElementById("conditionalGetStatus");

// Store abort controller for conditional get demo
let conditionalAbortController = null;

// Backup State Section
const testBackupStateBtn = document.getElementById("testBackupStateBtn");
const testBackupAuthBtn = document.getElementById("testBackupAuthBtn");
const backupSupportBadge = document.getElementById("backupSupportBadge");
const backupSupportStatus = document.getElementById("backupSupportStatus");
const backupTestResults = document.getElementById("backupTestResults");

// Signal API Section
const testSignalSupportBtn = document.getElementById("testSignalSupportBtn");
const signalSupportBadge = document.getElementById("signalSupportBadge");
const signalSupportStatus = document.getElementById("signalSupportStatus");
const signalTestResults = document.getElementById("signalTestResults");
const signalLiveTestSection = document.getElementById("signalLiveTestSection");
const signalLog = document.getElementById("signalLog");
const signalLogLabel = document.getElementById("signalLogLabel");
const signalLogMeta = document.getElementById("signalLogMeta");
const testSignalUnknownBtn = document.getElementById("testSignalUnknownBtn");
const testSignalAllAcceptedBtn = document.getElementById("testSignalAllAcceptedBtn");
const testSignalUserDetailsBtn = document.getElementById("testSignalUserDetailsBtn");
const signalUnknownBadge = document.getElementById("signalUnknownBadge");
const signalAllAcceptedBadge = document.getElementById("signalAllAcceptedBadge");
const signalUserDetailsBadge = document.getElementById("signalUserDetailsBadge");
const signalUnknownResult = document.getElementById("signalUnknownResult");
const signalAllAcceptedResult = document.getElementById("signalAllAcceptedResult");
const signalUserDetailsResult = document.getElementById("signalUserDetailsResult");

// ==========================================================================
// Capability Definitions (WebAuthn L3) - Rich Educational Content
// ==========================================================================
const CAPABILITY_INFO = {
  conditionalCreate: {
    name: "Conditional Create",
    icon: "✨",
    summary: "Allows websites to prepare passkey creation without immediately triggering browser UI, waiting for a real user gesture.",
    details: [
      {
        icon: "✔",
        title: "Check whether the device can create passkeys",
        explanation: "…without triggering a popup or system UI."
      },
      {
        icon: "✔",
        title: "Prepare all the WebAuthn parameters",
        explanation: "…so everything is ready behind the scenes."
      },
      {
        icon: "✔",
        title: "Wait for a real user gesture",
        explanation: "…like clicking \"Create account\" or \"Save passkey\"."
      }
    ],
    useCase: "Perfect for onboarding flows where you want to check passkey availability first, then prompt the user at the right moment — not immediately on page load.",
    codeExample: "mediation: \"conditional\""
  },
  conditionalGet: {
    name: "Conditional Get (Autofill)",
    icon: "🔑",
    summary: "Enables passkeys to appear in the browser's autofill suggestions, just like saved passwords.",
    details: [
      {
        icon: "✔",
        title: "Passkeys appear in autofill dropdown",
        explanation: "…alongside saved passwords when user focuses a login field."
      },
      {
        icon: "✔",
        title: "No modal popup required",
        explanation: "…the authentication flow feels native and non-intrusive."
      },
      {
        icon: "✔",
        title: "User selects which passkey to use",
        explanation: "…from a familiar UI they already know from password autofill."
      }
    ],
    useCase: "The key to seamless passkey adoption. Users can authenticate with a single tap from the autofill menu, making passkeys feel as easy as saved passwords.",
    codeExample: "mediation: \"conditional\", autocomplete: \"username webauthn\""
  },
  hybridTransport: {
    name: "Hybrid Transport",
    icon: "📱",
    summary: "Use your phone or tablet as an authenticator for another device via QR code and Bluetooth.",
    details: [
      {
        icon: "✔",
        title: "Scan a QR code on the desktop",
        explanation: "…to initiate cross-device authentication."
      },
      {
        icon: "✔",
        title: "Authenticate on your phone",
        explanation: "…using Face ID, Touch ID, or fingerprint."
      },
      {
        icon: "✔",
        title: "Bluetooth verifies proximity",
        explanation: "…ensuring the phone is physically nearby for security."
      }
    ],
    useCase: "Essential for users on shared/public computers or when the current device lacks biometrics. Your phone becomes a portable authenticator.",
    codeExample: "transports: [\"hybrid\"]"
  },
  passkeyPlatformAuthenticator: {
    name: "Passkey Platform Authenticator",
    icon: "☁️",
    summary: "Supports synced passkeys that automatically sync across your devices via cloud (iCloud Keychain, Google Password Manager, etc.).",
    details: [
      {
        icon: "✔",
        title: "Create a passkey on one device",
        explanation: "…and it automatically syncs to your other devices."
      },
      {
        icon: "✔",
        title: "Lost device? No problem",
        explanation: "…your passkeys are backed up and recoverable."
      },
      {
        icon: "✔",
        title: "Works across the ecosystem",
        explanation: "…iPhone ↔ iPad ↔ Mac, or Android ↔ Chrome on any device."
      }
    ],
    useCase: "The modern passkey experience. Users don't lose access when they get a new phone — their passkeys follow them automatically.",
    codeExample: "residentKey: \"required\", authenticatorAttachment: \"platform\""
  },
  userVerifyingPlatformAuthenticator: {
    name: "User Verifying Platform Authenticator",
    icon: "👆",
    summary: "The device has built-in biometrics or PIN for user verification (Face ID, Touch ID, Windows Hello, fingerprint).",
    details: [
      {
        icon: "✔",
        title: "Biometric authentication available",
        explanation: "…like Face ID, Touch ID, or fingerprint sensor."
      },
      {
        icon: "✔",
        title: "Fallback to device PIN/password",
        explanation: "…when biometrics aren't available or fail."
      },
      {
        icon: "✔",
        title: "No external hardware required",
        explanation: "…authentication happens entirely on this device."
      }
    ],
    useCase: "The foundation for passkeys on modern devices. This is the legacy API that tells you if the device can do passwordless auth locally.",
    codeExample: "PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()"
  },
  relatedOrigins: {
    name: "Related Origins",
    icon: "🔗",
    summary: "Use passkeys across related domains (e.g., example.com and app.example.com) without re-registration.",
    details: [
      {
        icon: "✔",
        title: "Share credentials across subdomains",
        explanation: "…and even across related domain names."
      },
      {
        icon: "✔",
        title: "Configure via .well-known file",
        explanation: "…with a JSON file listing allowed origins."
      },
      {
        icon: "✔",
        title: "Seamless multi-domain experience",
        explanation: "…users authenticate once, use everywhere."
      }
    ],
    useCase: "Perfect for enterprises with multiple domains or apps that span web and native platforms but want unified authentication.",
    codeExample: "/.well-known/webauthn → { \"origins\": [\"https://app.example.com\"] }"
  },
  signalAllAcceptedCredentials: {
    name: "Signal All Accepted Credentials",
    icon: "📋",
    summary: "Tell the authenticator which credentials your server actually accepts, so it can clean up stale entries.",
    details: [
      {
        icon: "✔",
        title: "Server sends list of valid credential IDs",
        explanation: "…so the authenticator knows what's still active."
      },
      {
        icon: "✔",
        title: "Authenticator can hide/remove old credentials",
        explanation: "…keeping the user's credential list clean."
      },
      {
        icon: "✔",
        title: "Prevents confusion from stale passkeys",
        explanation: "…users only see credentials that will actually work."
      }
    ],
    useCase: "Crucial for good UX. When users delete their account or you rotate credentials server-side, this lets their device know.",
    codeExample: "PublicKeyCredential.signalAllAcceptedCredentials({...})"
  },
  signalCurrentUserDetails: {
    name: "Signal Current User Details",
    icon: "👤",
    summary: "Update the display name and user info stored with a passkey without re-registering.",
    details: [
      {
        icon: "✔",
        title: "User changes their display name",
        explanation: "…update it on the passkey without re-enrollment."
      },
      {
        icon: "✔",
        title: "Fix typos or outdated info",
        explanation: "…the passkey's metadata stays current."
      },
      {
        icon: "✔",
        title: "Better credential picker UX",
        explanation: "…users see accurate, recognizable names."
      }
    ],
    useCase: "When a user updates their profile name or email, you can push that change to their stored passkey so it displays correctly.",
    codeExample: "PublicKeyCredential.signalCurrentUserDetails({...})"
  },
  signalUnknownCredential: {
    name: "Signal Unknown Credential",
    icon: "❓",
    summary: "Tell the authenticator when a credential it offers is unknown to your server, enabling cleanup.",
    details: [
      {
        icon: "✔",
        title: "User tries a deleted passkey",
        explanation: "…your server doesn't recognize it."
      },
      {
        icon: "✔",
        title: "Signal back that it's unknown",
        explanation: "…the authenticator can mark or remove it."
      },
      {
        icon: "✔",
        title: "Self-healing credential lists",
        explanation: "…stale passkeys automatically get cleaned up."
      }
    ],
    useCase: "Handles the case where a user has a passkey their device remembers, but your server has deleted. Prevents repeated failed attempts.",
    codeExample: "PublicKeyCredential.signalUnknownCredential({...})"
  },

  // ==========================================================================
  // WebAuthn Extensions
  // ==========================================================================
  
  "extension:credProps": {
    name: "Credential Properties (credProps)",
    icon: "📝",
    summary: "Get information about the credential that was just created, including whether it's discoverable (resident).",
    details: [
      {
        icon: "✔",
        title: "Know if credential is discoverable",
        explanation: "…the rk (resident key) property tells you if it's stored on the authenticator."
      },
      {
        icon: "✔",
        title: "Verify authenticator compliance",
        explanation: "…confirm the authenticator respected your residentKey preference."
      },
      {
        icon: "✔",
        title: "Adjust your UX accordingly",
        explanation: "…show different flows for discoverable vs. server-side credentials."
      }
    ],
    useCase: "Essential when you request residentKey: 'preferred'. The authenticator might not support it, so credProps tells you what actually happened.",
    codeExample: "extensions: { credProps: true }\n// Response: { rk: true }"
  },

  "extension:largeBlob": {
    name: "Large Blob Storage (largeBlob)",
    icon: "💾",
    summary: "Store and retrieve arbitrary data (up to ~4KB) alongside a credential on the authenticator.",
    details: [
      {
        icon: "✔",
        title: "Store data with the credential",
        explanation: "…like encryption keys, certificates, or user preferences."
      },
      {
        icon: "✔",
        title: "Data travels with the credential",
        explanation: "…if passkeys sync, the blob syncs too."
      },
      {
        icon: "✔",
        title: "Read data during authentication",
        explanation: "…retrieve the blob when the user signs in."
      }
    ],
    useCase: "Advanced use case: store a wrapped encryption key so users can decrypt data on any device where their passkey syncs. Also useful for offline-first apps.",
    codeExample: "extensions: { largeBlob: { write: new Uint8Array([...]) } }\n// Or read: { largeBlob: { read: true } }"
  },

  "extension:prf": {
    name: "Pseudo-Random Function (PRF)",
    icon: "🎲",
    summary: "Derive deterministic secret keys from a credential — the same input always produces the same output.",
    details: [
      {
        icon: "✔",
        title: "Generate encryption keys",
        explanation: "…derive keys for encrypting user data client-side."
      },
      {
        icon: "✔",
        title: "Deterministic output",
        explanation: "…same credential + same input = same derived key, every time."
      },
      {
        icon: "✔",
        title: "No server storage needed",
        explanation: "…the key is derived on-demand, never stored."
      }
    ],
    useCase: "End-to-end encryption without key escrow. Derive encryption keys from the passkey itself — if the passkey syncs, the encryption capability follows.",
    codeExample: "extensions: {\n  prf: { eval: { first: new Uint8Array(32) } }\n}"
  },

  "extension:minPinLength": {
    name: "Minimum PIN Length (minPinLength)",
    icon: "🔢",
    summary: "Request authenticators enforce a minimum PIN length for added security.",
    details: [
      {
        icon: "✔",
        title: "Enforce PIN complexity",
        explanation: "…require PINs of at least N characters."
      },
      {
        icon: "✔",
        title: "Query current PIN length policy",
        explanation: "…check what minimum the authenticator currently enforces."
      },
      {
        icon: "✔",
        title: "Meet compliance requirements",
        explanation: "…satisfy enterprise security policies."
      }
    ],
    useCase: "Enterprise deployments where security policies require PINs of a certain length. Useful for FIDO2 security key rollouts.",
    codeExample: "extensions: { minPinLength: true }"
  },

  "extension:credProtect": {
    name: "Credential Protection (credProtect)",
    icon: "🛡️",
    summary: "Control when and how a credential can be used — restrict to user verification or specific use cases.",
    details: [
      {
        icon: "✔",
        title: "Level 1: userVerificationOptional",
        explanation: "…credential usable with or without UV (default)."
      },
      {
        icon: "✔",
        title: "Level 2: userVerificationOptionalWithCredentialIDList",
        explanation: "…discoverable only if credential ID is provided."
      },
      {
        icon: "✔",
        title: "Level 3: userVerificationRequired",
        explanation: "…credential ONLY works with user verification."
      }
    ],
    useCase: "High-security scenarios where you want to ensure the credential can't be used without biometric/PIN verification, even if the RP doesn't request it.",
    codeExample: "extensions: {\n  credentialProtectionPolicy: \"userVerificationRequired\",\n  enforceCredentialProtectionPolicy: true\n}"
  },

  "extension:appid": {
    name: "App ID (U2F Compatibility)",
    icon: "🔄",
    summary: "Allow WebAuthn to authenticate with credentials originally registered via the legacy U2F API.",
    details: [
      {
        icon: "✔",
        title: "Migrate from U2F to WebAuthn",
        explanation: "…existing U2F credentials keep working."
      },
      {
        icon: "✔",
        title: "Specify the original App ID",
        explanation: "…the U2F appId used during registration."
      },
      {
        icon: "✔",
        title: "Gradual migration path",
        explanation: "…no need to re-register all users at once."
      }
    ],
    useCase: "If you previously used U2F (chrome.runtime.sendMessage or the u2f-api.js polyfill), use appid to let those old credentials work with WebAuthn.",
    codeExample: "extensions: { appid: \"https://example.com\" }"
  },

  "extension:appidExclude": {
    name: "App ID Exclude",
    icon: "🚫",
    summary: "Prevent registration if the user already has a U2F credential for the specified App ID.",
    details: [
      {
        icon: "✔",
        title: "Check for existing U2F credentials",
        explanation: "…during WebAuthn registration."
      },
      {
        icon: "✔",
        title: "Avoid duplicate registrations",
        explanation: "…user can't register same authenticator twice."
      },
      {
        icon: "✔",
        title: "Clean migration from U2F",
        explanation: "…prevents confusion during transition."
      }
    ],
    useCase: "During U2F → WebAuthn migration, exclude authenticators that already have U2F credentials to prevent duplicate entries.",
    codeExample: "extensions: { appidExclude: \"https://example.com\" }"
  },

  "extension:uvm": {
    name: "User Verification Method (uvm)",
    icon: "🔍",
    summary: "Learn which method the user used to verify their identity — fingerprint, face, PIN, etc.",
    details: [
      {
        icon: "✔",
        title: "Know how the user authenticated",
        explanation: "…fingerprint, face recognition, PIN, or presence."
      },
      {
        icon: "✔",
        title: "Audit and compliance logging",
        explanation: "…record the verification method for security audits."
      },
      {
        icon: "✔",
        title: "Adaptive security decisions",
        explanation: "…require stronger UV for sensitive operations."
      }
    ],
    useCase: "Security auditing and compliance. Know if the user used a biometric (stronger) vs. PIN (weaker) so you can make risk-based decisions.",
    codeExample: "extensions: { uvm: true }\n// Response: [[0x02, 0x04, 0x02]] → fingerprint"
  },

  "extension:devicePubKey": {
    name: "Device Public Key (devicePubKey)",
    icon: "🔐",
    summary: "Get a device-bound key in addition to the credential, enabling device binding for synced passkeys.",
    details: [
      {
        icon: "✔",
        title: "Separate device-bound key",
        explanation: "…doesn't sync, stays on this specific device."
      },
      {
        icon: "✔",
        title: "Detect new devices",
        explanation: "…know when a synced passkey is used from a new device."
      },
      {
        icon: "✔",
        title: "Step-up authentication trigger",
        explanation: "…prompt additional verification for unknown devices."
      }
    ],
    useCase: "Banks and high-security apps: even with synced passkeys, detect when authentication comes from a new device and trigger additional verification.",
    codeExample: "extensions: { devicePubKey: { attestation: \"direct\" } }"
  },

  "extension:payment": {
    name: "Secure Payment Confirmation (SPC)",
    icon: "💳",
    summary: "Streamlined payment authentication that shows transaction details in the WebAuthn prompt.",
    details: [
      {
        icon: "✔",
        title: "Display transaction details",
        explanation: "…amount, merchant, currency shown in browser UI."
      },
      {
        icon: "✔",
        title: "User confirms with biometric",
        explanation: "…one gesture to authenticate and confirm payment."
      },
      {
        icon: "✔",
        title: "Cryptographic proof of consent",
        explanation: "…the signature covers the transaction details."
      }
    ],
    useCase: "Online checkout flows. Replace SMS OTP or card CVV with a single biometric confirmation that proves the user saw and approved the exact transaction.",
    codeExample: "const payment = new PaymentRequest([{\n  supportedMethods: \"secure-payment-confirmation\",\n  data: { credentialIds, challenge, ... }\n}], details);"
  }
};

// Extensions to test during credential creation
const EXTENSIONS_TO_TEST = [
  {
    key: "credProps",
    name: "credProps",
    icon: "📝",
    description: "Credential properties (discoverable check)",
    createOptions: { credProps: true },
    checkResult: (result) => result?.credProps !== undefined
  },
  {
    key: "largeBlob",
    name: "largeBlob",
    icon: "💾",
    description: "Large blob storage support check",
    createOptions: { largeBlob: { support: "preferred" } },
    checkResult: (result) => result?.largeBlob !== undefined
  },
  {
    key: "prf",
    name: "prf",
    icon: "🎲",
    description: "Pseudo-random function for key derivation",
    createOptions: { prf: { } },
    checkResult: (result) => result?.prf !== undefined
  },
  {
    key: "minPinLength",
    name: "minPinLength",
    icon: "🔢",
    description: "Minimum PIN length policy",
    createOptions: { minPinLength: true },
    checkResult: (result) => result?.minPinLength !== undefined
  },
  {
    key: "credProtect",
    name: "credProtect",
    icon: "🛡️",
    description: "Credential protection level",
    createOptions: { credentialProtectionPolicy: "userVerificationOptional" },
    checkResult: (result) => result?.credProtect !== undefined
  },
  {
    key: "hmacCreateSecret",
    name: "hmac-secret",
    icon: "🔐",
    description: "HMAC secret extension (CTAP2)",
    createOptions: { hmacCreateSecret: true },
    checkResult: (result) => result?.hmacCreateSecret !== undefined
  }
];

// ==========================================================================
// Utility Functions
// ==========================================================================
function setDotState(el, state) {
  el.classList.remove("ok", "no", "maybe");
  el.classList.add(state === "ok" ? "ok" : state === "no" ? "no" : "maybe");
}

function setBadgeState(badge, textEl, state, text) {
  badge.classList.remove("ok", "warn", "error");
  badge.classList.add(state);
  textEl.textContent = text;
}

function detectBrowser() {
  const ua = navigator.userAgent;
  let browser = "Unknown", version = "", os = "Unknown";

  if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Mac OS X")) os = "macOS";
  else if (ua.includes("iPhone") || ua.includes("iPad")) os = "iOS";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("Linux")) os = "Linux";
  else if (ua.includes("CrOS")) os = "ChromeOS";

  if (ua.includes("Firefox/")) { browser = "Firefox"; version = ua.match(/Firefox\/(\d+)/)?.[1] || ""; }
  else if (ua.includes("Edg/")) { browser = "Edge"; version = ua.match(/Edg\/(\d+)/)?.[1] || ""; }
  else if (ua.includes("Chrome/")) { browser = "Chrome"; version = ua.match(/Chrome\/(\d+)/)?.[1] || ""; }
  else if (ua.includes("Safari/") && !ua.includes("Chrome")) { browser = "Safari"; version = ua.match(/Version\/(\d+)/)?.[1] || ""; }

  return { browser, version, os, ua };
}

// ==========================================================================
// Navigation
// ==========================================================================
function initNavigation() {
  const navTabs = document.querySelectorAll(".nav-tab");
  const sections = document.querySelectorAll(".check-section");
  
  // Navigate to a specific section
  function navigateToSection(sectionId, updateHash = true) {
    const targetTab = document.querySelector(`.nav-tab[data-section="${sectionId}"]`);
    const targetSection = document.getElementById(`section-${sectionId}`);
    
    if (!targetTab || !targetSection) return false;
    
    // Update active states
    navTabs.forEach(t => t.classList.remove("active"));
    sections.forEach(s => s.classList.remove("active"));
    targetTab.classList.add("active");
    targetSection.classList.add("active");
    
    // Update URL hash (without triggering hashchange event loop)
    if (updateHash && window.location.hash !== `#${sectionId}`) {
      history.pushState(null, '', `#${sectionId}`);
    }
    
    return true;
  }
  
  // Handle tab clicks
  navTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      navigateToSection(tab.dataset.section);
    });
  });
  
  // Handle browser back/forward navigation
  window.addEventListener("hashchange", () => {
    const hash = window.location.hash.slice(1); // Remove the # symbol
    if (hash) {
      navigateToSection(hash, false);
    }
  });
  
  // On initial load, check for hash in URL
  const initialHash = window.location.hash.slice(1);
  if (initialHash) {
    // Navigate to the section specified in the URL
    const success = navigateToSection(initialHash, false);
    if (!success) {
      // Invalid hash, default to capabilities
      navigateToSection('capabilities', true);
    }
  }
}

// ==========================================================================
// Environment Detection
// ==========================================================================
async function updateEnvironment() {
  const { browser, version, os } = detectBrowser();
  const hasPKC = typeof PublicKeyCredential !== "undefined";
  const hasGCC = hasPKC && typeof PublicKeyCredential.getClientCapabilities === "function";

  browserPill.textContent = `${browser} ${version} on ${os}`;

  pkcText.textContent = hasPKC ? "Available" : "Not available";
  setDotState(pkcIndicator, hasPKC ? "ok" : "no");

  gccText.textContent = hasGCC ? "Available" : "Not implemented";
  setDotState(gccIndicator, hasGCC ? "ok" : "no");

  if (!hasPKC) {
    envText.textContent = "No WebAuthn";
    envPill.style.borderColor = "#ef4444";
  } else if (!hasGCC) {
    envText.textContent = "WebAuthn OK, L3 partial";
    envPill.style.borderColor = "#eab308";
  } else {
    envText.textContent = "Full L3 Support";
    envPill.style.borderColor = "#22c55e";
  }

  // UVPAA
  if (hasPKC && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
    try {
      const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      uvpaaText.textContent = available ? "Available" : "Not available";
      setDotState(uvpaaIndicator, available ? "ok" : "no");
    } catch { uvpaaText.textContent = "Error"; setDotState(uvpaaIndicator, "maybe"); }
  } else {
    uvpaaText.textContent = "Not implemented";
    setDotState(uvpaaIndicator, "no");
  }

  // Conditional UI
  if (hasPKC && typeof PublicKeyCredential.isConditionalMediationAvailable === "function") {
    try {
      const available = await PublicKeyCredential.isConditionalMediationAvailable();
      conditionalText.textContent = available ? "Available" : "Not available";
      setDotState(conditionalIndicator, available ? "ok" : "no");
    } catch { conditionalText.textContent = "Error"; setDotState(conditionalIndicator, "maybe"); }
  } else {
    conditionalText.textContent = "Not implemented";
    setDotState(conditionalIndicator, "no");
  }
}

// ==========================================================================
// Capabilities Section
// ==========================================================================
function renderCapabilities(caps) {
  capabilitiesList.innerHTML = "";
  let supported = 0, unsupported = 0, unknown = 0;

  Object.keys(caps).forEach((key, i) => {
    const value = caps[key];
    const info = CAPABILITY_INFO[key] || { 
      name: key, 
      icon: "📌",
      summary: `Capability: ${key}`,
      details: [],
      useCase: "",
      codeExample: ""
    };

    if (value === true) supported++;
    else if (value === false) unsupported++;
    else unknown++;

    const item = document.createElement("div");
    item.className = "check-item animated";
    item.style.animationDelay = `${i * 0.04}s`;

    const statusClass = value === true ? "supported" : value === false ? "not-supported" : "unknown";
    const statusLabel = value === true ? "✓ Supported" : value === false ? "✗ Not Supported" : "? Unknown";
    const dotClass = value === true ? "ok" : value === false ? "no" : "maybe";

    // Build details HTML
    let detailsHTML = "";
    if (info.details && info.details.length > 0) {
      detailsHTML = info.details.map(d => `
        <div class="detail-point">
          <span class="detail-icon">${d.icon}</span>
          <div class="detail-content">
            <div class="detail-title">${d.title}</div>
            <div class="detail-explanation">${d.explanation}</div>
          </div>
        </div>
      `).join("");
    }

    // Build use case HTML
    let useCaseHTML = "";
    if (info.useCase) {
      useCaseHTML = `
        <div class="use-case-box">
          <div class="use-case-title">💡 When to use</div>
          <div class="use-case-text">${info.useCase}</div>
        </div>
      `;
    }

    // Build code example HTML
    let codeHTML = "";
    if (info.codeExample) {
      codeHTML = `<div class="code-example">${info.codeExample}</div>`;
    }

    item.innerHTML = `
      <div class="check-item-header">
        <span class="check-item-name">
          <span class="dot-indicator ${dotClass}"></span>
          <span>${info.icon || ""} ${info.name}</span>
        </span>
        <span class="check-item-status ${statusClass}">${statusLabel}</span>
      </div>
      <div class="check-item-summary">${info.summary}</div>
      ${(info.details && info.details.length > 0) ? `
        <div class="check-item-toggle" onclick="this.parentElement.classList.toggle('expanded')">
          <span>▶</span>
          <span class="toggle-text">Learn more</span>
          <span class="toggle-text-collapse">Show less</span>
        </div>
        <div class="check-item-details">
          ${detailsHTML}
          ${useCaseHTML}
          ${codeHTML}
        </div>
      ` : ''}
    `;
    capabilitiesList.appendChild(item);
  });

  capSummaryStats.style.display = "flex";
  capStatSupported.textContent = supported;
  capStatUnsupported.textContent = unsupported;
  capStatUnknown.textContent = unknown;

  if (Object.keys(caps).length === 0) {
    capabilitiesList.innerHTML = `<div class="check-item" style="opacity:0.6"><div class="check-item-description">Empty capabilities object returned.</div></div>`;
  }
}

async function runCapabilitiesCheck() {
  if (typeof PublicKeyCredential === "undefined") {
    setBadgeState(capStatusBadge, capStatusText, "error", "No WebAuthn");
    capLog.textContent = JSON.stringify({ error: "PublicKeyCredential not available" }, null, 2);
    return;
  }

  if (typeof PublicKeyCredential.getClientCapabilities !== "function") {
    setBadgeState(capStatusBadge, capStatusText, "error", "API missing");
    capLog.textContent = JSON.stringify({
      error: "getClientCapabilities() not implemented",
      hint: "Try Chrome 128+, Safari 18+, or recent Edge"
    }, null, 2);
    return;
  }

  runCapabilitiesBtn.disabled = true;
  runCapabilitiesBtn.innerHTML = "<span class='loading'>⏳</span><span>Running…</span>";
  setBadgeState(capStatusBadge, capStatusText, "warn", "Detecting…");

  try {
    const caps = await PublicKeyCredential.getClientCapabilities();
    capLog.textContent = JSON.stringify(caps, null, 2);
    capLogLabel.textContent = "Capabilities result";
    capLogMeta.textContent = new Date().toLocaleTimeString();

    renderCapabilities(caps);

    const total = Object.keys(caps).length;
    const supported = Object.values(caps).filter(v => v === true).length;
    setBadgeState(capStatusBadge, capStatusText, "ok", `${supported}/${total} supported`);
    copyCapabilitiesBtn.disabled = false;
  } catch (err) {
    setBadgeState(capStatusBadge, capStatusText, "error", "Error");
    capLog.textContent = JSON.stringify({ error: err.message, name: err.name }, null, 2);
  } finally {
    runCapabilitiesBtn.disabled = false;
    runCapabilitiesBtn.innerHTML = "<span>▶</span><span>Run Check</span>";
  }
}

async function copyCapabilitiesJSON() {
  try {
    await navigator.clipboard.writeText(capLog.textContent);
    copyCapabilitiesBtn.innerHTML = "<span>✓</span><span>Copied!</span>";
    setTimeout(() => { copyCapabilitiesBtn.innerHTML = "<span>⧉</span><span>Copy JSON</span>"; }, 1200);
  } catch {
    copyCapabilitiesBtn.innerHTML = "<span>✗</span><span>Failed</span>";
    setTimeout(() => { copyCapabilitiesBtn.innerHTML = "<span>⧉</span><span>Copy JSON</span>"; }, 1200);
  }
}

function initCapabilities() {
  runCapabilitiesBtn.addEventListener("click", runCapabilitiesCheck);
  copyCapabilitiesBtn.addEventListener("click", copyCapabilitiesJSON);
}

// ==========================================================================
// Hints Section
// ==========================================================================
let selectedHints = [];

function updateHintCode() {
  if (selectedHints.length === 0) {
    hintCode.textContent = "hints: []";
  } else {
    hintCode.textContent = `hints: [${selectedHints.map(h => `"${h}"`).join(", ")}]`;
  }
}

function showHintTestResult(success, message, details = null) {
  hintTestResult.style.display = "block";
  hintTestResultContent.innerHTML = `
    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
      <span class="dot-indicator ${success ? 'ok' : 'no'}"></span>
      <strong style="color: ${success ? 'var(--success)' : 'var(--danger)'}">
        ${success ? 'Success' : 'Error / Cancelled'}
      </strong>
    </div>
    <p style="margin: 0; font-size: 0.82rem; color: var(--text-muted);">${message}</p>
    ${details ? `<pre style="margin: 8px 0 0; padding: 8px; background: rgba(0,0,0,0.3); border-radius: 8px; font-size: 0.75rem; overflow: auto;">${details}</pre>` : ''}
  `;
}

async function testHintsWithCreate() {
  if (typeof PublicKeyCredential === "undefined") {
    showHintTestResult(false, "WebAuthn is not available on this platform.");
    return;
  }

  testHintsCreateBtn.disabled = true;
  testHintsCreateBtn.innerHTML = "<span class='loading'>⏳</span><span>Testing…</span>";

  // Generate random values for the test
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  const userId = new Uint8Array(16);
  crypto.getRandomValues(userId);

  const createOptions = {
    publicKey: {
      challenge: challenge,
      rp: {
        name: "WebAuthn Explorer Test",
        id: window.location.hostname
      },
      user: {
        id: userId,
        name: "test@example.com",
        displayName: "Test User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 }  // RS256
      ],
      authenticatorSelection: {
        userVerification: "preferred"
      },
      timeout: 60000,
      hints: selectedHints.length > 0 ? selectedHints : undefined
    }
  };

  try {
    const credential = await navigator.credentials.create(createOptions);
    showHintTestResult(
      true,
      `Credential created successfully with hints: [${selectedHints.join(", ") || "none"}]`,
      `Credential ID: ${btoa(String.fromCharCode(...new Uint8Array(credential.rawId))).slice(0, 40)}...`
    );
  } catch (err) {
    showHintTestResult(
      false,
      `${err.name}: ${err.message}`,
      `Hints used: [${selectedHints.join(", ") || "none"}]`
    );
  } finally {
    testHintsCreateBtn.disabled = false;
    testHintsCreateBtn.innerHTML = "<span>✨</span><span>Test with Create</span>";
  }
}

async function testHintsWithGet() {
  if (typeof PublicKeyCredential === "undefined") {
    showHintTestResult(false, "WebAuthn is not available on this platform.");
    return;
  }

  testHintsGetBtn.disabled = true;
  testHintsGetBtn.innerHTML = "<span class='loading'>⏳</span><span>Testing…</span>";

  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  const getOptions = {
    publicKey: {
      challenge: challenge,
      rpId: window.location.hostname,
      userVerification: "preferred",
      timeout: 60000,
      hints: selectedHints.length > 0 ? selectedHints : undefined
    }
  };

  try {
    const assertion = await navigator.credentials.get(getOptions);
    showHintTestResult(
      true,
      `Authentication successful with hints: [${selectedHints.join(", ") || "none"}]`,
      `Credential ID: ${btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))).slice(0, 40)}...`
    );
  } catch (err) {
    showHintTestResult(
      false,
      `${err.name}: ${err.message}`,
      `Hints used: [${selectedHints.join(", ") || "none"}]\n\nNote: "Get" requires an existing credential for this origin.`
    );
  } finally {
    testHintsGetBtn.disabled = false;
    testHintsGetBtn.innerHTML = "<span>🔓</span><span>Test with Get</span>";
  }
}

function initHints() {
  hintOptions.querySelectorAll(".hint-option").forEach(option => {
    option.addEventListener("click", (e) => {
      e.preventDefault(); // Prevent default label behavior (double-toggle)
      const hint = option.dataset.hint;
      const input = option.querySelector("input");

      if (selectedHints.includes(hint)) {
        selectedHints = selectedHints.filter(h => h !== hint);
        option.classList.remove("selected");
        input.checked = false;
      } else {
        selectedHints.push(hint);
        option.classList.add("selected");
        input.checked = true;
      }

      updateHintCode();
    });
  });

  testHintsCreateBtn.addEventListener("click", testHintsWithCreate);
  testHintsGetBtn.addEventListener("click", testHintsWithGet);
}

// ==========================================================================
// Extension Support Testing
// ==========================================================================
function setExtBadgeState(state, text) {
  extTestBadge.classList.remove("ok", "warn", "error");
  extTestBadge.classList.add(state);
  extTestStatus.textContent = text;
}

function renderExtensionResults(results, rawResult) {
  extensionResults.innerHTML = "";
  
  let supported = 0;
  let unsupported = 0;

  results.forEach((ext, i) => {
    if (ext.supported) supported++;
    else unsupported++;

    const item = document.createElement("div");
    item.className = "check-item animated";
    item.style.animationDelay = `${i * 0.05}s`;

    const dotClass = ext.supported ? "ok" : "no";
    const statusClass = ext.supported ? "supported" : "not-supported";
    const statusLabel = ext.supported ? "✓ Supported" : "✗ Not detected";

    let resultDetail = "";
    if (ext.supported && ext.resultData) {
      resultDetail = `<div class="code-example" style="margin-top: 8px; font-size: 0.7rem;">${JSON.stringify(ext.resultData, null, 2)}</div>`;
    }

    item.innerHTML = `
      <div class="check-item-header">
        <span class="check-item-name">
          <span class="dot-indicator ${dotClass}"></span>
          <span>${ext.icon} ${ext.name}</span>
        </span>
        <span class="check-item-status ${statusClass}">${statusLabel}</span>
      </div>
      <div class="check-item-summary">${ext.description}</div>
      ${resultDetail}
    `;
    extensionResults.appendChild(item);
  });

  // Show raw results
  extensionRawResults.style.display = "block";
  extensionResultsLog.textContent = JSON.stringify(rawResult, null, 2);

  // Update badge
  if (supported > 0) {
    setExtBadgeState("ok", `${supported}/${results.length} supported`);
  } else {
    setExtBadgeState("warn", "Limited support");
  }
}

async function testExtensionSupport() {
  if (typeof PublicKeyCredential === "undefined") {
    setExtBadgeState("error", "No WebAuthn");
    extensionResults.innerHTML = `<div class="check-item"><div class="check-item-description" style="color: var(--danger);">WebAuthn is not available on this platform.</div></div>`;
    return;
  }

  testExtensionsBtn.disabled = true;
  testExtensionsBtn.innerHTML = "<span class='loading'>⏳</span><span>Testing…</span>";
  setExtBadgeState("warn", "Testing…");

  // Build combined extensions object
  const allExtensions = {};
  EXTENSIONS_TO_TEST.forEach(ext => {
    Object.assign(allExtensions, ext.createOptions);
  });

  // Generate random values
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  const userId = new Uint8Array(16);
  crypto.getRandomValues(userId);

  const createOptions = {
    publicKey: {
      challenge: challenge,
      rp: {
        name: "WebAuthn Explorer - Extension Test",
        id: window.location.hostname
      },
      user: {
        id: userId,
        name: "extension-test@example.com",
        displayName: "Extension Test User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 }  // RS256
      ],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred"
      },
      timeout: 120000,
      extensions: allExtensions
    }
  };

  try {
    const credential = await navigator.credentials.create(createOptions);
    const extResults = credential.getClientExtensionResults();

    // Check each extension
    const results = EXTENSIONS_TO_TEST.map(ext => {
      const supported = ext.checkResult(extResults);
      return {
        ...ext,
        supported: supported,
        resultData: supported ? extResults[ext.key] : null
      };
    });

    renderExtensionResults(results, extResults);

  } catch (err) {
    console.error("Extension test error:", err);
    
    if (err.name === "NotAllowedError") {
      setExtBadgeState("warn", "Cancelled");
      extensionResults.innerHTML = `
        <div class="check-item">
          <div class="check-item-description">
            <strong>Test cancelled.</strong> You need to complete the WebAuthn prompt to test extension support.
          </div>
        </div>
      `;
    } else {
      setExtBadgeState("error", "Error");
      extensionResults.innerHTML = `
        <div class="check-item">
          <div class="check-item-description" style="color: var(--danger);">
            <strong>${err.name}:</strong> ${err.message}
          </div>
        </div>
      `;
    }
    extensionRawResults.style.display = "block";
    extensionResultsLog.textContent = JSON.stringify({ error: err.message, name: err.name }, null, 2);
  } finally {
    testExtensionsBtn.disabled = false;
    testExtensionsBtn.innerHTML = "<span>🧪</span><span>Test Extension Support</span>";
  }
}

function initExtensions() {
  testExtensionsBtn.addEventListener("click", testExtensionSupport);
}

// ==========================================================================
// PRF Support Testing
// ==========================================================================
function setPrfBadgeState(state, text) {
  prfSupportBadge.classList.remove("ok", "warn", "error");
  prfSupportBadge.classList.add(state);
  prfSupportStatus.textContent = text;
}

function arrayBufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function createPrfSalt(saltString) {
  // Create a 32-byte salt from the input string
  const encoder = new TextEncoder();
  const encoded = encoder.encode(saltString);
  const salt = new Uint8Array(32);
  
  // Copy the encoded string into the salt, padding with zeros if needed
  for (let i = 0; i < 32; i++) {
    salt[i] = encoded[i] || 0;
  }
  
  return salt;
}

function renderPrfResults(supported, prfEnabled, details) {
  prfTestResults.innerHTML = "";
  
  // Support status item
  const supportItem = document.createElement("div");
  supportItem.className = "check-item animated";
  supportItem.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span class="dot-indicator ${supported ? 'ok' : 'no'}"></span>
        <span>🎲 PRF Extension</span>
      </span>
      <span class="check-item-status ${supported ? 'supported' : 'not-supported'}">
        ${supported ? '✓ Supported' : '✗ Not Supported'}
      </span>
    </div>
    <div class="check-item-summary">
      ${supported 
        ? 'Your browser and authenticator support the PRF extension! You can derive cryptographic keys from this passkey.'
        : 'PRF is not supported by your current browser/authenticator combination. Try Chrome 109+, Edge 109+, or Safari 17+ with a compatible authenticator.'}
    </div>
  `;
  prfTestResults.appendChild(supportItem);

  // PRF Enabled status
  if (supported) {
    const enabledItem = document.createElement("div");
    enabledItem.className = "check-item animated";
    enabledItem.style.animationDelay = "0.05s";
    enabledItem.innerHTML = `
      <div class="check-item-header">
        <span class="check-item-name">
          <span class="dot-indicator ${prfEnabled ? 'ok' : 'maybe'}"></span>
          <span>✅ PRF Enabled</span>
        </span>
        <span class="check-item-status ${prfEnabled ? 'supported' : 'unknown'}">
          ${prfEnabled ? '✓ Ready' : '? Check response'}
        </span>
      </div>
      <div class="check-item-summary">
        ${prfEnabled 
          ? 'The PRF extension is enabled and ready to derive keys during authentication.'
          : 'PRF was detected but the enabled flag was not set. Key derivation may still work.'}
      </div>
    `;
    prfTestResults.appendChild(enabledItem);
  }

  // Raw response details
  if (details) {
    const detailsItem = document.createElement("div");
    detailsItem.className = "check-item animated";
    detailsItem.style.animationDelay = "0.1s";
    detailsItem.innerHTML = `
      <div class="check-item-header">
        <span class="check-item-name">
          <span>📋</span>
          <span>Extension Response</span>
        </span>
      </div>
      <div class="code-example" style="margin-top: 8px;">
${JSON.stringify(details, null, 2)}
      </div>
    `;
    prfTestResults.appendChild(detailsItem);
  }

  // Show live demo section if supported
  if (supported) {
    prfDemoSection.style.display = "block";
  }
}

async function testPrfSupport() {
  if (typeof PublicKeyCredential === "undefined") {
    setPrfBadgeState("error", "No WebAuthn");
    prfTestResults.innerHTML = `
      <div class="check-item">
        <div class="check-item-description" style="color: var(--danger);">
          WebAuthn is not available on this platform.
        </div>
      </div>
    `;
    return;
  }

  testPrfSupportBtn.disabled = true;
  testPrfSupportBtn.innerHTML = "<span class='loading'>⏳</span><span>Testing…</span>";
  setPrfBadgeState("warn", "Testing…");

  // Generate random values
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  const userId = new Uint8Array(16);
  crypto.getRandomValues(userId);

  const createOptions = {
    publicKey: {
      challenge: challenge,
      rp: {
        name: "WebAuthn Explorer - PRF Test",
        id: window.location.hostname
      },
      user: {
        id: userId,
        name: "prf-test@example.com",
        displayName: "PRF Test User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 }  // RS256
      ],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred"
      },
      timeout: 120000,
      extensions: {
        prf: {}  // Empty object to check for support
      }
    }
  };

  try {
    const credential = await navigator.credentials.create(createOptions);
    const extResults = credential.getClientExtensionResults();
    
    // Store credential ID for the live demo
    prfCredentialId = credential.rawId;

    const prfSupported = extResults.prf !== undefined;
    const prfEnabled = extResults.prf?.enabled === true;

    if (prfSupported) {
      setPrfBadgeState("ok", prfEnabled ? "Supported & Ready" : "Supported");
    } else {
      setPrfBadgeState("warn", "Not detected");
    }

    renderPrfResults(prfSupported, prfEnabled, extResults.prf || { note: "PRF not in extension results" });

  } catch (err) {
    console.error("PRF test error:", err);
    
    if (err.name === "NotAllowedError") {
      setPrfBadgeState("warn", "Cancelled");
      prfTestResults.innerHTML = `
        <div class="check-item">
          <div class="check-item-description">
            <strong>Test cancelled.</strong> You need to complete the WebAuthn prompt to test PRF support.
          </div>
        </div>
      `;
    } else {
      setPrfBadgeState("error", "Error");
      prfTestResults.innerHTML = `
        <div class="check-item">
          <div class="check-item-description" style="color: var(--danger);">
            <strong>${err.name}:</strong> ${err.message}
          </div>
        </div>
      `;
    }
  } finally {
    testPrfSupportBtn.disabled = false;
    testPrfSupportBtn.innerHTML = "<span>🎲</span><span>Test PRF Support</span>";
  }
}

async function derivePrfKey() {
  if (!prfCredentialId) {
    alert("Please run the PRF support test first to create a credential.");
    return;
  }

  const saltValue = prfSaltInput.value || "default-salt-value";
  const salt = createPrfSalt(saltValue);

  derivePrfKeyBtn.disabled = true;
  derivePrfKeyBtn.innerHTML = "<span class='loading'>⏳</span><span>Deriving…</span>";

  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  const getOptions = {
    publicKey: {
      challenge: challenge,
      rpId: window.location.hostname,
      userVerification: "preferred",
      timeout: 120000,
      allowCredentials: [{
        type: "public-key",
        id: prfCredentialId
      }],
      extensions: {
        prf: {
          eval: {
            first: salt
          }
        }
      }
    }
  };

  try {
    const assertion = await navigator.credentials.get(getOptions);
    const extResults = assertion.getClientExtensionResults();
    
    if (extResults.prf?.results?.first) {
      const derivedKey = extResults.prf.results.first;
      const hexKey = arrayBufferToHex(derivedKey);
      
      prfDerivedKeyHex.textContent = hexKey;
      prfDerivedKeyResult.style.display = "block";
    } else {
      prfDerivedKeyHex.textContent = "No PRF result returned. PRF may not be fully supported.";
      prfDerivedKeyHex.style.color = "var(--warning)";
      prfDerivedKeyResult.style.display = "block";
    }
  } catch (err) {
    console.error("PRF derivation error:", err);
    prfDerivedKeyHex.textContent = `Error: ${err.message}`;
    prfDerivedKeyHex.style.color = "var(--danger)";
    prfDerivedKeyResult.style.display = "block";
  } finally {
    derivePrfKeyBtn.disabled = false;
    derivePrfKeyBtn.innerHTML = "<span>🔑</span><span>Derive Key</span>";
  }
}

function initPrf() {
  testPrfSupportBtn.addEventListener("click", testPrfSupport);
  derivePrfKeyBtn.addEventListener("click", derivePrfKey);
}

// ==========================================================================
// Conditional UI Support Testing
// ==========================================================================
function setConditionalBadgeState(state, text) {
  conditionalSupportBadge.classList.remove("ok", "warn", "error");
  conditionalSupportBadge.classList.add(state);
  conditionalSupportStatus.textContent = text;
}

function renderConditionalResults(conditionalGetSupported, conditionalCreateSupported, details) {
  conditionalTestResults.innerHTML = "";
  
  // Conditional Get support item
  const getItem = document.createElement("div");
  getItem.className = "check-item animated";
  getItem.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span class="dot-indicator ${conditionalGetSupported ? 'ok' : 'no'}"></span>
        <span>🔑 Conditional Get (Autofill)</span>
      </span>
      <span class="check-item-status ${conditionalGetSupported ? 'supported' : 'not-supported'}">
        ${conditionalGetSupported ? '✓ Supported' : '✗ Not Supported'}
      </span>
    </div>
    <div class="check-item-summary">
      ${conditionalGetSupported 
        ? 'Passkeys can appear in the browser autofill menu! Use <code>mediation: "conditional"</code> with credentials.get().'
        : 'Conditional Get is not supported. Users will need to use the traditional WebAuthn modal prompt.'}
    </div>
  `;
  conditionalTestResults.appendChild(getItem);

  // Conditional Create support item
  const createItem = document.createElement("div");
  createItem.className = "check-item animated";
  createItem.style.animationDelay = "0.05s";
  createItem.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span class="dot-indicator ${conditionalCreateSupported ? 'ok' : conditionalCreateSupported === null ? 'maybe' : 'no'}"></span>
        <span>✨ Conditional Create</span>
      </span>
      <span class="check-item-status ${conditionalCreateSupported ? 'supported' : conditionalCreateSupported === null ? 'unknown' : 'not-supported'}">
        ${conditionalCreateSupported ? '✓ Supported' : conditionalCreateSupported === null ? '? Unknown' : '✗ Not Supported'}
      </span>
    </div>
    <div class="check-item-summary">
      ${conditionalCreateSupported 
        ? 'Passkey creation can be deferred until user action! Use <code>mediation: "conditional"</code> with credentials.create().'
        : conditionalCreateSupported === null
          ? 'Could not determine Conditional Create support. The getClientCapabilities() API may not be available.'
          : 'Conditional Create is not supported. Passkey registration will show a modal prompt immediately.'}
    </div>
  `;
  conditionalTestResults.appendChild(createItem);

  // API availability item
  const apiItem = document.createElement("div");
  apiItem.className = "check-item animated";
  apiItem.style.animationDelay = "0.1s";
  apiItem.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span>📋</span>
        <span>API Detection Methods</span>
      </span>
    </div>
    <div class="code-example" style="margin-top: 8px;">
${JSON.stringify(details, null, 2)}
    </div>
  `;
  conditionalTestResults.appendChild(apiItem);

  // Show demo section if conditional get is supported
  if (conditionalGetSupported) {
    startConditionalGetBtn.disabled = false;
  }
}

async function testConditionalSupport() {
  if (typeof PublicKeyCredential === "undefined") {
    setConditionalBadgeState("error", "No WebAuthn");
    conditionalTestResults.innerHTML = `
      <div class="check-item">
        <div class="check-item-description" style="color: var(--danger);">
          WebAuthn is not available on this platform.
        </div>
      </div>
    `;
    return;
  }

  testConditionalSupportBtn.disabled = true;
  testConditionalSupportBtn.innerHTML = "<span class='loading'>⏳</span><span>Testing…</span>";
  setConditionalBadgeState("warn", "Testing…");

  const details = {
    isConditionalMediationAvailable: "checking...",
    getClientCapabilities: "checking..."
  };

  let conditionalGetSupported = false;
  let conditionalCreateSupported = null;

  // Check Conditional Get support via isConditionalMediationAvailable
  if (typeof PublicKeyCredential.isConditionalMediationAvailable === "function") {
    try {
      conditionalGetSupported = await PublicKeyCredential.isConditionalMediationAvailable();
      details.isConditionalMediationAvailable = conditionalGetSupported;
    } catch (err) {
      details.isConditionalMediationAvailable = `Error: ${err.message}`;
    }
  } else {
    details.isConditionalMediationAvailable = "Not implemented";
  }

  // Check Conditional Create support via getClientCapabilities
  if (typeof PublicKeyCredential.getClientCapabilities === "function") {
    try {
      const caps = await PublicKeyCredential.getClientCapabilities();
      conditionalCreateSupported = caps.conditionalCreate === true;
      details.getClientCapabilities = {
        conditionalCreate: caps.conditionalCreate,
        conditionalGet: caps.conditionalGet
      };
    } catch (err) {
      details.getClientCapabilities = `Error: ${err.message}`;
    }
  } else {
    details.getClientCapabilities = "Not implemented";
  }

  // Determine overall status
  const supportCount = [conditionalGetSupported, conditionalCreateSupported].filter(v => v === true).length;
  if (supportCount === 2) {
    setConditionalBadgeState("ok", "Full Support");
  } else if (supportCount === 1) {
    setConditionalBadgeState("ok", "Partial Support");
  } else if (conditionalGetSupported || conditionalCreateSupported) {
    setConditionalBadgeState("warn", "Limited");
  } else {
    setConditionalBadgeState("warn", "Not Supported");
  }

  renderConditionalResults(conditionalGetSupported, conditionalCreateSupported, details);

  testConditionalSupportBtn.disabled = false;
  testConditionalSupportBtn.innerHTML = "<span>✨</span><span>Test Conditional Support</span>";
}

async function startConditionalGet() {
  if (conditionalAbortController) {
    conditionalAbortController.abort();
  }

  conditionalAbortController = new AbortController();
  
  startConditionalGetBtn.disabled = true;
  abortConditionalGetBtn.disabled = false;
  conditionalGetStatus.innerHTML = `
    <span class="dot-indicator ok" style="display: inline-block; vertical-align: middle;"></span>
    <span style="color: var(--success);">Listening for passkey selection...</span><br>
    <span style="font-size: 0.72rem;">Focus the input field above and check your browser's autofill menu.</span>
  `;
  conditionalDemoInput.focus();

  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  try {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: challenge,
        rpId: window.location.hostname,
        userVerification: "preferred",
        timeout: 300000 // 5 minutes
      },
      mediation: "conditional",
      signal: conditionalAbortController.signal
    });

    // Success - user selected a passkey
    conditionalGetStatus.innerHTML = `
      <span class="dot-indicator ok" style="display: inline-block; vertical-align: middle;"></span>
      <span style="color: var(--success);"><strong>Success!</strong> Passkey selected from autofill.</span><br>
      <span style="font-size: 0.72rem;">Credential ID: ${btoa(String.fromCharCode(...new Uint8Array(credential.rawId))).slice(0, 30)}...</span>
    `;
    
  } catch (err) {
    if (err.name === "AbortError") {
      conditionalGetStatus.innerHTML = `
        <span class="dot-indicator maybe" style="display: inline-block; vertical-align: middle;"></span>
        <span style="color: var(--warning);">Conditional Get aborted.</span>
      `;
    } else {
      conditionalGetStatus.innerHTML = `
        <span class="dot-indicator no" style="display: inline-block; vertical-align: middle;"></span>
        <span style="color: var(--danger);"><strong>${err.name}:</strong> ${err.message}</span>
      `;
    }
  } finally {
    startConditionalGetBtn.disabled = false;
    abortConditionalGetBtn.disabled = true;
    conditionalAbortController = null;
  }
}

function abortConditionalGet() {
  if (conditionalAbortController) {
    conditionalAbortController.abort();
  }
}

function initConditional() {
  testConditionalSupportBtn.addEventListener("click", testConditionalSupport);
  startConditionalGetBtn.addEventListener("click", startConditionalGet);
  abortConditionalGetBtn.addEventListener("click", abortConditionalGet);
}

// ==========================================================================
// Backup State Testing
// ==========================================================================
function setBackupBadgeState(state, text) {
  backupSupportBadge.classList.remove("ok", "warn", "error");
  backupSupportBadge.classList.add(state);
  backupSupportStatus.textContent = text;
}

function parseAuthenticatorFlags(authData) {
  // authData is an ArrayBuffer
  // Flags byte is at index 32 (after 32 bytes of RP ID hash)
  const flags = new Uint8Array(authData)[32];
  
  return {
    userPresent: (flags & 0x01) !== 0,       // Bit 0
    userVerified: (flags & 0x04) !== 0,      // Bit 2
    backupEligible: (flags & 0x10) !== 0,    // Bit 4 (BE)
    backupState: (flags & 0x08) !== 0,       // Bit 3 (BS)
    attestedCredentialData: (flags & 0x40) !== 0, // Bit 6
    extensionData: (flags & 0x80) !== 0,     // Bit 7
    rawFlags: flags
  };
}

function getBackupStateDescription(be, bs) {
  if (!be && !bs) {
    return {
      type: "device-bound",
      icon: "🔑",
      title: "Device-Bound Credential",
      description: "This passkey is locked to this device and cannot be synced. It provides the highest security assurance but will be lost if the device is lost.",
      security: "high"
    };
  }
  if (be && bs) {
    return {
      type: "synced",
      icon: "☁️",
      title: "Synced Passkey",
      description: "This passkey is backed up and available on your other devices. You can recover it if you lose this device.",
      security: "standard"
    };
  }
  if (be && !bs) {
    return {
      type: "pending-sync",
      icon: "⏳",
      title: "Sync Pending",
      description: "This passkey can be synced but hasn't been backed up yet. This might happen if the device is offline or sync is temporarily disabled.",
      security: "warning"
    };
  }
  // be=0, bs=1 - Invalid state
  return {
    type: "invalid",
    icon: "⚠️",
    title: "Invalid State",
    description: "This is an unexpected flag combination. A credential cannot be backed up if it's not backup-eligible.",
    security: "error"
  };
}

function renderBackupResults(flags, credentialType) {
  backupTestResults.innerHTML = "";
  
  const description = getBackupStateDescription(flags.backupEligible, flags.backupState);
  
  // Main result item
  const mainItem = document.createElement("div");
  mainItem.className = "check-item animated";
  mainItem.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span class="dot-indicator ${description.security === 'high' ? 'ok' : description.security === 'standard' ? 'ok' : description.security === 'warning' ? 'maybe' : 'no'}"></span>
        <span>${description.icon} ${description.title}</span>
      </span>
    </div>
    <div class="check-item-summary">${description.description}</div>
  `;
  backupTestResults.appendChild(mainItem);

  // Flag details grid
  const gridContainer = document.createElement("div");
  gridContainer.className = "backup-result-grid";
  
  // BE Flag
  const beItem = document.createElement("div");
  beItem.className = "backup-result-item";
  beItem.innerHTML = `
    <div class="backup-result-label">Backup Eligible (BE)</div>
    <div class="backup-result-value ${flags.backupEligible ? 'eligible' : 'device-bound'}">
      <span class="dot-indicator ${flags.backupEligible ? 'ok' : 'maybe'}"></span>
      ${flags.backupEligible ? 'Yes — Syncable' : 'No — Device-Bound'}
    </div>
  `;
  gridContainer.appendChild(beItem);
  
  // BS Flag
  const bsItem = document.createElement("div");
  bsItem.className = "backup-result-item";
  bsItem.innerHTML = `
    <div class="backup-result-label">Backup State (BS)</div>
    <div class="backup-result-value ${flags.backupState ? 'backed-up' : 'not-backed-up'}">
      <span class="dot-indicator ${flags.backupState ? 'ok' : flags.backupEligible ? 'maybe' : 'no'}"></span>
      ${flags.backupState ? 'Yes — Backed Up' : 'No — Not Backed Up'}
    </div>
  `;
  gridContainer.appendChild(bsItem);
  
  // UV Flag
  const uvItem = document.createElement("div");
  uvItem.className = "backup-result-item";
  uvItem.innerHTML = `
    <div class="backup-result-label">User Verified (UV)</div>
    <div class="backup-result-value" style="color: ${flags.userVerified ? 'var(--success)' : 'var(--text-muted)'}">
      <span class="dot-indicator ${flags.userVerified ? 'ok' : 'no'}"></span>
      ${flags.userVerified ? 'Yes — Biometric/PIN Used' : 'No'}
    </div>
  `;
  gridContainer.appendChild(uvItem);
  
  // UP Flag
  const upItem = document.createElement("div");
  upItem.className = "backup-result-item";
  upItem.innerHTML = `
    <div class="backup-result-label">User Present (UP)</div>
    <div class="backup-result-value" style="color: ${flags.userPresent ? 'var(--success)' : 'var(--text-muted)'}">
      <span class="dot-indicator ${flags.userPresent ? 'ok' : 'no'}"></span>
      ${flags.userPresent ? 'Yes — User Interacted' : 'No'}
    </div>
  `;
  gridContainer.appendChild(upItem);
  
  backupTestResults.appendChild(gridContainer);
  
  // Raw flags
  const rawItem = document.createElement("div");
  rawItem.className = "check-item animated";
  rawItem.style.animationDelay = "0.15s";
  rawItem.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span>📋</span>
        <span>Raw Flags Byte</span>
      </span>
    </div>
    <div class="code-example" style="margin-top: 8px;">
Flags byte: 0x${flags.rawFlags.toString(16).padStart(2, '0').toUpperCase()} (binary: ${flags.rawFlags.toString(2).padStart(8, '0')})

Bit breakdown:
  Bit 0 (UP - User Present): ${flags.userPresent ? '1' : '0'}
  Bit 2 (UV - User Verified): ${flags.userVerified ? '1' : '0'}
  Bit 3 (BS - Backup State): ${flags.backupState ? '1' : '0'}
  Bit 4 (BE - Backup Eligible): ${flags.backupEligible ? '1' : '0'}
  Bit 6 (AT - Attested Credential): ${flags.attestedCredentialData ? '1' : '0'}
  Bit 7 (ED - Extension Data): ${flags.extensionData ? '1' : '0'}
    </div>
  `;
  backupTestResults.appendChild(rawItem);
  
  // Security recommendation
  const recommendationItem = document.createElement("div");
  recommendationItem.className = "check-item animated";
  recommendationItem.style.animationDelay = "0.2s";
  
  let recommendationContent = "";
  if (description.type === "device-bound") {
    recommendationContent = `
      <div class="use-case-box">
        <div class="use-case-title">🛡️ Security Recommendation</div>
        <div class="use-case-text">
          This credential provides the highest security assurance. It's ideal for:
          <br>• Banking and financial applications
          <br>• Enterprise admin access
          <br>• Regulatory compliance (NIST, PCI-DSS)
          <br><br>
          <strong>Caution:</strong> Register a backup credential — this one can't be recovered if the device is lost.
        </div>
      </div>
    `;
  } else if (description.type === "synced") {
    recommendationContent = `
      <div class="use-case-box">
        <div class="use-case-title">✅ Good for Most Applications</div>
        <div class="use-case-text">
          This synced passkey offers excellent balance of security and convenience:
          <br>• User can recover on new devices
          <br>• End-to-end encrypted in cloud
          <br>• Great for consumer apps
          <br><br>
          For high-value operations, you may want to consider additional verification (step-up auth).
        </div>
      </div>
    `;
  } else if (description.type === "pending-sync") {
    recommendationContent = `
      <div class="use-case-box" style="border-color: rgba(234, 179, 8, 0.3); background: rgba(234, 179, 8, 0.08);">
        <div class="use-case-title" style="color: var(--warning);">⚠️ Sync Not Complete</div>
        <div class="use-case-text">
          This passkey is eligible for backup but hasn't synced yet. Consider:
          <br>• Prompting user to check their sync settings
          <br>• Suggesting they add a backup authentication method
          <br>• Re-checking BS flag on next login
        </div>
      </div>
    `;
  }
  
  if (recommendationContent) {
    recommendationItem.innerHTML = recommendationContent;
    backupTestResults.appendChild(recommendationItem);
  }
}

async function testBackupState() {
  if (typeof PublicKeyCredential === "undefined") {
    setBackupBadgeState("error", "No WebAuthn");
    backupTestResults.innerHTML = `
      <div class="check-item">
        <div class="check-item-description" style="color: var(--danger);">
          WebAuthn is not available on this platform.
        </div>
      </div>
    `;
    return;
  }

  testBackupStateBtn.disabled = true;
  testBackupStateBtn.innerHTML = "<span class='loading'>⏳</span><span>Testing…</span>";
  setBackupBadgeState("warn", "Testing…");

  // Generate random values
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  const userId = new Uint8Array(16);
  crypto.getRandomValues(userId);

  const createOptions = {
    publicKey: {
      challenge: challenge,
      rp: {
        name: "WebAuthn Explorer - Backup Test",
        id: window.location.hostname
      },
      user: {
        id: userId,
        name: "backup-test@example.com",
        displayName: "Backup Test User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 }  // RS256
      ],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred"
      },
      timeout: 120000
    }
  };

  try {
    const credential = await navigator.credentials.create(createOptions);
    
    // Get authenticator data from the attestation response
    const authData = credential.response.getAuthenticatorData 
      ? credential.response.getAuthenticatorData() 
      : credential.response.authenticatorData;
    
    if (!authData) {
      throw new Error("Could not access authenticator data");
    }
    
    const flags = parseAuthenticatorFlags(authData);
    
    // Set badge based on backup state
    if (flags.backupEligible && flags.backupState) {
      setBackupBadgeState("ok", "Synced Passkey");
    } else if (flags.backupEligible && !flags.backupState) {
      setBackupBadgeState("warn", "Sync Pending");
    } else {
      setBackupBadgeState("ok", "Device-Bound");
    }
    
    renderBackupResults(flags, flags.backupEligible ? "synced" : "device-bound");

  } catch (err) {
    console.error("Backup state test error:", err);
    
    if (err.name === "NotAllowedError") {
      setBackupBadgeState("warn", "Cancelled");
      backupTestResults.innerHTML = `
        <div class="check-item">
          <div class="check-item-description">
            <strong>Test cancelled.</strong> You need to complete the WebAuthn prompt to check backup state.
          </div>
        </div>
      `;
    } else {
      setBackupBadgeState("error", "Error");
      backupTestResults.innerHTML = `
        <div class="check-item">
          <div class="check-item-description" style="color: var(--danger);">
            <strong>${err.name}:</strong> ${err.message}
          </div>
        </div>
      `;
    }
  } finally {
    testBackupStateBtn.disabled = false;
    testBackupStateBtn.innerHTML = "<span>✨</span><span>Create & Check</span>";
  }
}

async function testBackupStateAuth() {
  if (typeof PublicKeyCredential === "undefined") {
    setBackupBadgeState("error", "No WebAuthn");
    backupTestResults.innerHTML = `
      <div class="check-item">
        <div class="check-item-description" style="color: var(--danger);">
          WebAuthn is not available on this platform.
        </div>
      </div>
    `;
    return;
  }

  testBackupAuthBtn.disabled = true;
  testBackupAuthBtn.innerHTML = "<span class='loading'>⏳</span><span>Authenticating…</span>";
  setBackupBadgeState("warn", "Authenticating…");

  // Generate random challenge
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  const getOptions = {
    publicKey: {
      challenge: challenge,
      rpId: window.location.hostname,
      userVerification: "preferred",
      timeout: 120000
      // No allowCredentials - let user pick any discoverable credential
    }
  };

  try {
    const assertion = await navigator.credentials.get(getOptions);
    
    // Get authenticator data from the assertion response
    const authData = assertion.response.authenticatorData;
    
    if (!authData) {
      throw new Error("Could not access authenticator data");
    }
    
    const flags = parseAuthenticatorFlags(authData);
    
    // Set badge based on backup state
    if (flags.backupEligible && flags.backupState) {
      setBackupBadgeState("ok", "Synced Passkey");
    } else if (flags.backupEligible && !flags.backupState) {
      setBackupBadgeState("warn", "Sync Pending");
    } else {
      setBackupBadgeState("ok", "Device-Bound");
    }
    
    renderBackupAuthResults(flags, assertion);

  } catch (err) {
    console.error("Backup auth test error:", err);
    
    if (err.name === "NotAllowedError") {
      setBackupBadgeState("warn", "Cancelled");
      backupTestResults.innerHTML = `
        <div class="check-item">
          <div class="check-item-description">
            <strong>Authentication cancelled.</strong> You need to complete the WebAuthn prompt to check the passkey's backup state.
          </div>
        </div>
      `;
    } else {
      setBackupBadgeState("error", "Error");
      backupTestResults.innerHTML = `
        <div class="check-item">
          <div class="check-item-description" style="color: var(--danger);">
            <strong>${err.name}:</strong> ${err.message}
          </div>
        </div>
      `;
    }
  } finally {
    testBackupAuthBtn.disabled = false;
    testBackupAuthBtn.innerHTML = "<span>🔓</span><span>Authenticate & Check</span>";
  }
}

function renderBackupAuthResults(flags, assertion) {
  backupTestResults.innerHTML = "";
  
  const description = getBackupStateDescription(flags.backupEligible, flags.backupState);
  
  // Extract user identifier from userHandle
  let userIdentifier = null;
  let userIdHex = null;
  if (assertion.response.userHandle && assertion.response.userHandle.byteLength > 0) {
    const userHandleBytes = new Uint8Array(assertion.response.userHandle);
    userIdHex = Array.from(userHandleBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Try to decode as UTF-8 text (many implementations store email/username as the user ID)
    try {
      const decoder = new TextDecoder('utf-8', { fatal: true });
      const decoded = decoder.decode(userHandleBytes);
      // Check if it looks like readable text (not binary garbage)
      if (/^[\x20-\x7E]+$/.test(decoded) && decoded.length > 0) {
        userIdentifier = decoded;
      }
    } catch (e) {
      // Not valid UTF-8, will show hex
    }
  }
  
  // Auth success header with user identifier
  const authHeader = document.createElement("div");
  authHeader.className = "check-item animated";
  
  let userInfoHtml = '';
  if (userIdentifier) {
    userInfoHtml = `
      <div class="passkey-user-info">
        <span class="passkey-user-icon">👤</span>
        <span class="passkey-user-name">${userIdentifier}</span>
      </div>
    `;
  } else if (userIdHex) {
    userInfoHtml = `
      <div class="passkey-user-info">
        <span class="passkey-user-icon">🪪</span>
        <span class="passkey-user-id">User ID: ${userIdHex.substring(0, 16)}${userIdHex.length > 16 ? '...' : ''}</span>
      </div>
    `;
  }
  
  authHeader.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span class="dot-indicator ok"></span>
        <span>🔓 Authentication Successful</span>
      </span>
    </div>
    ${userInfoHtml}
    <div class="check-item-summary">
      ${userIdentifier ? `Authenticated as <strong>${userIdentifier}</strong>. ` : ''}Here are the passkey's backup flags:
    </div>
  `;
  backupTestResults.appendChild(authHeader);

  // Main result item
  const mainItem = document.createElement("div");
  mainItem.className = "check-item animated";
  mainItem.style.animationDelay = "0.05s";
  mainItem.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span class="dot-indicator ${description.security === 'high' ? 'ok' : description.security === 'standard' ? 'ok' : description.security === 'warning' ? 'maybe' : 'no'}"></span>
        <span>${description.icon} ${description.title}</span>
      </span>
    </div>
    <div class="check-item-summary">${description.description}</div>
  `;
  backupTestResults.appendChild(mainItem);

  // Flag details grid
  const gridContainer = document.createElement("div");
  gridContainer.className = "backup-result-grid";
  gridContainer.style.animationDelay = "0.1s";
  
  // BE Flag
  const beItem = document.createElement("div");
  beItem.className = "backup-result-item";
  beItem.innerHTML = `
    <div class="backup-result-label">Backup Eligible (BE)</div>
    <div class="backup-result-value ${flags.backupEligible ? 'eligible' : 'device-bound'}">
      <span class="dot-indicator ${flags.backupEligible ? 'ok' : 'maybe'}"></span>
      ${flags.backupEligible ? 'Yes — Syncable' : 'No — Device-Bound'}
    </div>
  `;
  gridContainer.appendChild(beItem);
  
  // BS Flag
  const bsItem = document.createElement("div");
  bsItem.className = "backup-result-item";
  bsItem.innerHTML = `
    <div class="backup-result-label">Backup State (BS)</div>
    <div class="backup-result-value ${flags.backupState ? 'backed-up' : 'not-backed-up'}">
      <span class="dot-indicator ${flags.backupState ? 'ok' : flags.backupEligible ? 'maybe' : 'no'}"></span>
      ${flags.backupState ? 'Yes — Backed Up' : 'No — Not Backed Up'}
    </div>
  `;
  gridContainer.appendChild(bsItem);
  
  // UV Flag
  const uvItem = document.createElement("div");
  uvItem.className = "backup-result-item";
  uvItem.innerHTML = `
    <div class="backup-result-label">User Verified (UV)</div>
    <div class="backup-result-value" style="color: ${flags.userVerified ? 'var(--success)' : 'var(--text-muted)'}">
      <span class="dot-indicator ${flags.userVerified ? 'ok' : 'no'}"></span>
      ${flags.userVerified ? 'Yes — Biometric/PIN Used' : 'No'}
    </div>
  `;
  gridContainer.appendChild(uvItem);
  
  // UP Flag
  const upItem = document.createElement("div");
  upItem.className = "backup-result-item";
  upItem.innerHTML = `
    <div class="backup-result-label">User Present (UP)</div>
    <div class="backup-result-value" style="color: ${flags.userPresent ? 'var(--success)' : 'var(--text-muted)'}">
      <span class="dot-indicator ${flags.userPresent ? 'ok' : 'no'}"></span>
      ${flags.userPresent ? 'Yes — User Interacted' : 'No'}
    </div>
  `;
  gridContainer.appendChild(upItem);
  
  backupTestResults.appendChild(gridContainer);
  
  // Credential ID info
  const credIdItem = document.createElement("div");
  credIdItem.className = "check-item animated";
  credIdItem.style.animationDelay = "0.15s";
  const credIdBase64 = btoa(String.fromCharCode(...new Uint8Array(assertion.rawId)));
  
  // Build user handle info for display
  let userHandleDisplay = 'Not provided';
  if (assertion.response.userHandle && assertion.response.userHandle.byteLength > 0) {
    if (userIdentifier) {
      userHandleDisplay = userIdentifier;
    } else {
      userHandleDisplay = `(hex) ${userIdHex}`;
    }
  }
  
  credIdItem.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span>🪪</span>
        <span>Credential Info</span>
      </span>
    </div>
    <div class="code-example" style="margin-top: 8px; word-break: break-all;">
User Handle: ${userHandleDisplay}
Credential ID: ${credIdBase64.substring(0, 32)}...
Type: ${assertion.type}
Authenticator Attachment: ${assertion.authenticatorAttachment || 'not reported'}
    </div>
  `;
  backupTestResults.appendChild(credIdItem);

  // Raw flags
  const rawItem = document.createElement("div");
  rawItem.className = "check-item animated";
  rawItem.style.animationDelay = "0.2s";
  rawItem.innerHTML = `
    <div class="check-item-header">
      <span class="check-item-name">
        <span>📋</span>
        <span>Raw Flags Byte</span>
      </span>
    </div>
    <div class="code-example" style="margin-top: 8px;">
Flags byte: 0x${flags.rawFlags.toString(16).padStart(2, '0').toUpperCase()} (binary: ${flags.rawFlags.toString(2).padStart(8, '0')})

Bit breakdown:
  Bit 0 (UP - User Present): ${flags.userPresent ? '1' : '0'}
  Bit 2 (UV - User Verified): ${flags.userVerified ? '1' : '0'}
  Bit 3 (BS - Backup State): ${flags.backupState ? '1' : '0'}
  Bit 4 (BE - Backup Eligible): ${flags.backupEligible ? '1' : '0'}
  Bit 6 (AT - Attested Credential): ${flags.attestedCredentialData ? '1' : '0'}
  Bit 7 (ED - Extension Data): ${flags.extensionData ? '1' : '0'}
    </div>
  `;
  backupTestResults.appendChild(rawItem);

  // Tip about monitoring
  const tipItem = document.createElement("div");
  tipItem.className = "check-item animated";
  tipItem.style.animationDelay = "0.25s";
  tipItem.innerHTML = `
    <div class="use-case-box">
      <div class="use-case-title">💡 Monitoring Tip</div>
      <div class="use-case-text">
        The BS (Backup State) flag can change over time. A passkey that was <code>BS=0</code> (not yet backed up) 
        may later become <code>BS=1</code> once it syncs to the cloud. Monitor this flag on each authentication 
        to track backup status changes.
      </div>
    </div>
  `;
  backupTestResults.appendChild(tipItem);
}

function initBackup() {
  testBackupStateBtn.addEventListener("click", testBackupState);
  testBackupAuthBtn.addEventListener("click", testBackupStateAuth);
  
  // Initialize education sub-tabs
  initEducationTabs();
}

// ==========================================================================
// Signal API Testing
// ==========================================================================
function setSignalBadgeState(state, text) {
  signalSupportBadge.classList.remove("ok", "warn", "error");
  signalSupportBadge.classList.add(state);
  signalSupportStatus.textContent = text;
}

function updateSignalLog(data) {
  signalLog.textContent = JSON.stringify(data, null, 2);
  signalLogMeta.textContent = new Date().toLocaleTimeString();
}

function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateTestUserId() {
  const userId = new Uint8Array(16);
  crypto.getRandomValues(userId);
  return arrayBufferToBase64url(userId);
}

function generateTestCredentialId() {
  const credId = new Uint8Array(32);
  crypto.getRandomValues(credId);
  return arrayBufferToBase64url(credId);
}

function renderSignalDetectionResults(results) {
  signalTestResults.innerHTML = "";
  
  const methods = [
    {
      key: "signalUnknownCredential",
      name: "signalUnknownCredential()",
      icon: "❓",
      description: "Signal that a credential is unknown to your server",
      supported: results.signalUnknownCredential
    },
    {
      key: "signalAllAcceptedCredentials",
      name: "signalAllAcceptedCredentials()",
      icon: "📋",
      description: "Signal the list of valid credential IDs for a user",
      supported: results.signalAllAcceptedCredentials
    },
    {
      key: "signalCurrentUserDetails",
      name: "signalCurrentUserDetails()",
      icon: "👤",
      description: "Signal updated username and display name",
      supported: results.signalCurrentUserDetails
    }
  ];

  let supported = 0;
  let unsupported = 0;

  methods.forEach((method, i) => {
    if (method.supported) supported++;
    else unsupported++;

    const item = document.createElement("div");
    item.className = "check-item animated";
    item.style.animationDelay = `${i * 0.05}s`;

    const dotClass = method.supported ? "ok" : "no";
    const statusClass = method.supported ? "supported" : "not-supported";
    const statusLabel = method.supported ? "✓ Available" : "✗ Not Available";

    item.innerHTML = `
      <div class="check-item-header">
        <span class="check-item-name">
          <span class="dot-indicator ${dotClass}"></span>
          <span>${method.icon} ${method.name}</span>
        </span>
        <span class="check-item-status ${statusClass}">${statusLabel}</span>
      </div>
      <div class="check-item-summary">${method.description}</div>
    `;
    signalTestResults.appendChild(item);
  });

  // Update overall badge
  if (supported === 3) {
    setSignalBadgeState("ok", "Full Support");
  } else if (supported > 0) {
    setSignalBadgeState("warn", `${supported}/3 Available`);
  } else {
    setSignalBadgeState("error", "Not Supported");
  }

  // Show live test section if any methods are available
  if (supported > 0) {
    signalLiveTestSection.style.display = "block";
    
    // Enable/disable individual test buttons
    testSignalUnknownBtn.disabled = !results.signalUnknownCredential;
    testSignalAllAcceptedBtn.disabled = !results.signalAllAcceptedCredentials;
    testSignalUserDetailsBtn.disabled = !results.signalCurrentUserDetails;
  }

  updateSignalLog({
    detection: results,
    summary: {
      supported,
      unsupported,
      browserInfo: detectBrowser()
    }
  });
}

async function testSignalSupport() {
  if (typeof PublicKeyCredential === "undefined") {
    setSignalBadgeState("error", "No WebAuthn");
    signalTestResults.innerHTML = `
      <div class="check-item">
        <div class="check-item-description" style="color: var(--danger);">
          WebAuthn is not available on this platform.
        </div>
      </div>
    `;
    return;
  }

  testSignalSupportBtn.disabled = true;
  testSignalSupportBtn.innerHTML = "<span class='loading'>⏳</span><span>Detecting…</span>";
  setSignalBadgeState("warn", "Detecting…");

  const results = {
    signalUnknownCredential: typeof PublicKeyCredential.signalUnknownCredential === "function",
    signalAllAcceptedCredentials: typeof PublicKeyCredential.signalAllAcceptedCredentials === "function",
    signalCurrentUserDetails: typeof PublicKeyCredential.signalCurrentUserDetails === "function"
  };

  // Also check via getClientCapabilities if available
  let capsResults = null;
  if (typeof PublicKeyCredential.getClientCapabilities === "function") {
    try {
      const caps = await PublicKeyCredential.getClientCapabilities();
      capsResults = {
        signalAllAcceptedCredentials: caps.signalAllAcceptedCredentials,
        signalCurrentUserDetails: caps.signalCurrentUserDetails,
        signalUnknownCredential: caps.signalUnknownCredential
      };
    } catch (err) {
      capsResults = { error: err.message };
    }
  }

  signalLogLabel.textContent = "Signal API Detection Results";
  
  renderSignalDetectionResults(results);
  
  // Update log with both detection methods
  updateSignalLog({
    methodDetection: results,
    getClientCapabilities: capsResults || "Not available",
    browserInfo: detectBrowser(),
    timestamp: new Date().toISOString()
  });

  testSignalSupportBtn.disabled = false;
  testSignalSupportBtn.innerHTML = "<span>🔍</span><span>Detect Signal API Support</span>";
}

async function testSignalUnknownCredential() {
  testSignalUnknownBtn.disabled = true;
  testSignalUnknownBtn.innerHTML = "<span class='loading'>⏳</span><span>Testing…</span>";
  signalUnknownBadge.textContent = "Testing…";
  signalUnknownBadge.className = "check-item-status unknown";

  const testCredentialId = generateTestCredentialId();
  const rpId = window.location.hostname;

  try {
    await PublicKeyCredential.signalUnknownCredential({
      rpId: rpId,
      credentialId: testCredentialId
    });

    signalUnknownBadge.textContent = "✓ Success";
    signalUnknownBadge.className = "check-item-status supported";
    
    signalUnknownResult.textContent = `✅ signalUnknownCredential() completed successfully

Parameters used:
  rpId: "${rpId}"
  credentialId: "${testCredentialId}"

The passkey provider received the signal. If a matching passkey existed, it would be marked for removal or hidden.`;
    signalUnknownResult.style.display = "block";
    signalUnknownResult.style.color = "var(--success)";

    updateSignalLog({
      method: "signalUnknownCredential",
      status: "success",
      params: { rpId, credentialId: testCredentialId },
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    signalUnknownBadge.textContent = "✗ Error";
    signalUnknownBadge.className = "check-item-status not-supported";
    
    signalUnknownResult.textContent = `❌ signalUnknownCredential() failed

Error: ${err.name}: ${err.message}

Parameters used:
  rpId: "${rpId}"
  credentialId: "${testCredentialId}"`;
    signalUnknownResult.style.display = "block";
    signalUnknownResult.style.color = "var(--danger)";

    updateSignalLog({
      method: "signalUnknownCredential",
      status: "error",
      error: { name: err.name, message: err.message },
      params: { rpId, credentialId: testCredentialId },
      timestamp: new Date().toISOString()
    });
  } finally {
    testSignalUnknownBtn.disabled = false;
    testSignalUnknownBtn.innerHTML = "<span>▶</span><span>Test signalUnknownCredential</span>";
  }
}

async function testSignalAllAcceptedCredentials() {
  testSignalAllAcceptedBtn.disabled = true;
  testSignalAllAcceptedBtn.innerHTML = "<span class='loading'>⏳</span><span>Testing…</span>";
  signalAllAcceptedBadge.textContent = "Testing…";
  signalAllAcceptedBadge.className = "check-item-status unknown";

  const testUserId = generateTestUserId();
  const testCredentialIds = [generateTestCredentialId(), generateTestCredentialId()];
  const rpId = window.location.hostname;

  try {
    await PublicKeyCredential.signalAllAcceptedCredentials({
      rpId: rpId,
      userId: testUserId,
      allAcceptedCredentialIds: testCredentialIds
    });

    signalAllAcceptedBadge.textContent = "✓ Success";
    signalAllAcceptedBadge.className = "check-item-status supported";
    
    signalAllAcceptedResult.textContent = `✅ signalAllAcceptedCredentials() completed successfully

Parameters used:
  rpId: "${rpId}"
  userId: "${testUserId}"
  allAcceptedCredentialIds: [
    "${testCredentialIds[0]}",
    "${testCredentialIds[1]}"
  ]

The passkey provider received the list. Any passkeys for this user not on the list would be removed.`;
    signalAllAcceptedResult.style.display = "block";
    signalAllAcceptedResult.style.color = "var(--success)";

    updateSignalLog({
      method: "signalAllAcceptedCredentials",
      status: "success",
      params: { rpId, userId: testUserId, credentialCount: testCredentialIds.length },
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    signalAllAcceptedBadge.textContent = "✗ Error";
    signalAllAcceptedBadge.className = "check-item-status not-supported";
    
    signalAllAcceptedResult.textContent = `❌ signalAllAcceptedCredentials() failed

Error: ${err.name}: ${err.message}

Parameters used:
  rpId: "${rpId}"
  userId: "${testUserId}"
  allAcceptedCredentialIds: [2 test IDs]`;
    signalAllAcceptedResult.style.display = "block";
    signalAllAcceptedResult.style.color = "var(--danger)";

    updateSignalLog({
      method: "signalAllAcceptedCredentials",
      status: "error",
      error: { name: err.name, message: err.message },
      params: { rpId, userId: testUserId },
      timestamp: new Date().toISOString()
    });
  } finally {
    testSignalAllAcceptedBtn.disabled = false;
    testSignalAllAcceptedBtn.innerHTML = "<span>▶</span><span>Test signalAllAcceptedCredentials</span>";
  }
}

async function testSignalCurrentUserDetails() {
  testSignalUserDetailsBtn.disabled = true;
  testSignalUserDetailsBtn.innerHTML = "<span class='loading'>⏳</span><span>Testing…</span>";
  signalUserDetailsBadge.textContent = "Testing…";
  signalUserDetailsBadge.className = "check-item-status unknown";

  const testUserId = generateTestUserId();
  const rpId = window.location.hostname;
  const testName = "test-user@example.com";
  const testDisplayName = "WebAuthn Test User";

  try {
    await PublicKeyCredential.signalCurrentUserDetails({
      rpId: rpId,
      userId: testUserId,
      name: testName,
      displayName: testDisplayName
    });

    signalUserDetailsBadge.textContent = "✓ Success";
    signalUserDetailsBadge.className = "check-item-status supported";
    
    signalUserDetailsResult.textContent = `✅ signalCurrentUserDetails() completed successfully

Parameters used:
  rpId: "${rpId}"
  userId: "${testUserId}"
  name: "${testName}"
  displayName: "${testDisplayName}"

The passkey provider received the updated user details. Matching passkeys would be updated to show this info.`;
    signalUserDetailsResult.style.display = "block";
    signalUserDetailsResult.style.color = "var(--success)";

    updateSignalLog({
      method: "signalCurrentUserDetails",
      status: "success",
      params: { rpId, userId: testUserId, name: testName, displayName: testDisplayName },
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    signalUserDetailsBadge.textContent = "✗ Error";
    signalUserDetailsBadge.className = "check-item-status not-supported";
    
    signalUserDetailsResult.textContent = `❌ signalCurrentUserDetails() failed

Error: ${err.name}: ${err.message}

Parameters used:
  rpId: "${rpId}"
  userId: "${testUserId}"
  name: "${testName}"
  displayName: "${testDisplayName}"`;
    signalUserDetailsResult.style.display = "block";
    signalUserDetailsResult.style.color = "var(--danger)";

    updateSignalLog({
      method: "signalCurrentUserDetails",
      status: "error",
      error: { name: err.name, message: err.message },
      params: { rpId, userId: testUserId },
      timestamp: new Date().toISOString()
    });
  } finally {
    testSignalUserDetailsBtn.disabled = false;
    testSignalUserDetailsBtn.innerHTML = "<span>▶</span><span>Test signalCurrentUserDetails</span>";
  }
}

function initSignal() {
  testSignalSupportBtn.addEventListener("click", testSignalSupport);
  testSignalUnknownBtn.addEventListener("click", testSignalUnknownCredential);
  testSignalAllAcceptedBtn.addEventListener("click", testSignalAllAcceptedCredentials);
  testSignalUserDetailsBtn.addEventListener("click", testSignalCurrentUserDetails);
  
  // Initialize education sub-tabs for signal section
  initSignalEducationTabs();
}

function initSignalEducationTabs() {
  const eduTabs = document.querySelectorAll('#section-signal .edu-tab');
  const eduContents = document.querySelectorAll('#section-signal .edu-tab-content');
  
  eduTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetTab = tab.dataset.eduTab;
      
      // Remove active from all tabs and contents in signal section
      eduTabs.forEach(t => t.classList.remove('active'));
      eduContents.forEach(c => c.classList.remove('active'));
      
      // Add active to clicked tab
      tab.classList.add('active');
      
      // Show corresponding content
      const targetContent = document.getElementById(`edu-${targetTab}`);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });
}

// ==========================================================================
// Education Sub-Tabs (Backup Section - scoped to prevent cross-section issues)
// ==========================================================================
function initEducationTabs() {
  // Scope to Backup section only to prevent cross-section tab contamination
  const eduTabs = document.querySelectorAll('#section-backup .edu-tab');
  const eduContents = document.querySelectorAll('#section-backup .edu-tab-content');
  
  eduTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetTab = tab.dataset.eduTab;
      
      // Remove active from all tabs and contents
      eduTabs.forEach(t => t.classList.remove('active'));
      eduContents.forEach(c => c.classList.remove('active'));
      
      // Add active to clicked tab
      tab.classList.add('active');
      
      // Show corresponding content
      const targetContent = document.getElementById(`edu-${targetTab}`);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });
}

// ==========================================================================
// Initialize Application
// ==========================================================================
function init() {
  initNavigation();
  initCapabilities();
  initHints();
  initExtensions();
  initPrf();
  initConditional();
  initBackup();
  initSignal();
  updateEnvironment();
}

// Run when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}