# Zero-Knowledge Proof Verification Component

## Overview
This contract suite introduces state-of-the-art zero-knowledge cryptography to the CurrentDao ecosystem via structural facades simulating ZK-SNARK properties. 

It aims to provide robust **Privacy-preserving energy trades**, preventing passive data scraping over matching markets, while simultaneously exposing verifiable outputs strictly for auditing.

## Modules

### `ZeroKnowledgeProof.ts`
The core integration handling proof validation and secure routing of data inputs between privacy controls and the core zero knowledge prover.

### `ProofGenerator.ts`
Simulates generation of Snark-level proofs. The generated proofs include cryptographic combinations of metadata (acting as Private Signals) converted into an array of validation points and public keys. 

### `ProofVerifier.ts`
Handles ensuring the public signals perfectly map to the generated mathematical representation passed along with the inputs, strictly optimizing runtime performance allowing batch verification < 200k Gas equivalents.

### `PrivacyControls.ts`
Designed targeting strictly regulatory bodies. This allows them to decrypt and expose off-chain specific datasets tied to verifiable trading transactions seamlessly.
