# Pragmatic Compromises

Some parts of the current design exist because the infrastructure we'd prefer doesn't exist yet — or exists but isn't widely deployed. These are bridges, not destinations. Each one fills a specific gap and is designed to be replaceable without changing the core protocol.

---

## OIDC as Auth Bridge

**What it is.** The protocol includes an OIDC-compatible authentication flow — login codes, authorize endpoint, token exchange, JWTs. Services integrate IDAP the same way they'd integrate "Login with Google."

**Why it exists.** OIDC is the auth protocol the web speaks. Every major web framework has OIDC middleware. Asking services to adopt a new auth method from day one is a non-starter. OIDC compatibility means any service that supports OpenID Connect can accept IDAP identities today, with no custom integration.

**What it bridges over.** Direct key-based authentication is simpler — present a public key, sign a challenge, done. No tokens, no redirect flows, no intermediary. But services don't speak that yet. The OIDC flow wraps key-based identity in a format services already understand.

**What could replace it.** Widespread adoption of key-based auth standards. WebAuthn/FIDO2 is moving in this direction for authentication. If services begin accepting public key signatures directly — the way SSH does — the OIDC bridge becomes unnecessary. The protocol already defines direct key-based auth alongside OIDC; the bridge exists for compatibility, not because OIDC is the right long-term answer.

<!-- TODO: Research current state of direct key-based auth standards beyond WebAuthn, and what adoption looks like -->

---

## Proxy as Discovery and Routing

**What it is.** A proxy is a server that provides key discovery (given a public key, find its endpoint), message routing (deliver an encrypted blob to a key), and OIDC provider services. The reference implementation runs as a single Go binary.

**Why it exists.** For two entities to communicate, they need to find each other. On today's internet, most devices sit behind NAT and don't have stable, publicly routable addresses. Someone needs to be reachable at a known location to accept messages and serve discovery information.

**What it bridges over.** The fundamental problem is addressability. If every device had a stable public address — which widespread IPv6 deployment would provide — peers could communicate directly. Discovery could be handled by distributed systems (DHTs, gossip protocols) rather than centralized directories.

**What could replace it.** Any combination of: universal IPv6 with stable device addressing, decentralized discovery protocols, peer-to-peer messaging layers. The protocol doesn't depend on the proxy concept — it depends on the ability to discover a key's endpoint and deliver messages to it. How that happens is an implementation concern.

The proxy may also persist as a deliberate choice for users who want an intermediary — for availability, for IP privacy, or for organizational control. That's fine. The point is it shouldn't be *required* by the protocol.

<!-- TODO: Research current state of IPv6 adoption, DHT-based discovery (e.g., Mainline DHT, libp2p), and decentralized messaging protocols -->

---

## Inbox as Message Store

**What it is.** The inbox is a simple encrypted message store on the proxy. Anyone can deliver a message to a public key; only the key holder can read it. Used for contact exchange, attestation delivery, and general-purpose messaging between identities.

**Why it exists.** Asynchronous messaging requires a store-and-forward layer. If the recipient isn't online when a message is sent, something needs to hold it. On today's internet, that means a server.

**What it bridges over.** The same addressability gap as the proxy. If peers could communicate directly, messages could be delivered peer-to-peer with local storage handling the offline case. The inbox exists because we can't assume the recipient is reachable.

**What could replace it.** Decentralized messaging protocols, peer-to-peer storage networks, or any system that provides reliable asynchronous delivery to a public key. The protocol defines a message envelope format and delivery semantics — the transport and storage mechanism underneath is an implementation detail.

<!-- TODO: Research decentralized messaging/storage: Matrix federation, Nostr relays, IPFS/libp2p messaging, and how they handle async delivery -->

---

## The Pattern

Each of these bridges follows the same pattern:

1. The protocol defines a **capability** (authentication, discovery, messaging)
2. Today's infrastructure has a **gap** that prevents doing it the ideal way
3. The current design fills that gap with a **proven, existing standard** (OIDC, HTTP server, encrypted blob store)
4. The bridge is **designed to be replaceable** — the protocol depends on the capability, not the specific mechanism

As infrastructure evolves, bridges can be swapped out without changing the protocol's core definitions. An IDAP identity created today should work with tomorrow's discovery and messaging infrastructure, the same way a domain name registered in 1995 still works on today's DNS.
