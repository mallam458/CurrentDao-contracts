import { ITradeMetadata, IPrivacyControls } from '../interfaces/IZeroKnowledgeProof';
import crypto from 'crypto';

export class PrivacyControls implements IPrivacyControls {
    private authorizedAuditors: Set<string>;
    // Mock storage of raw trade metadata linked to a secure identifier
    private offChainStorage: Map<string, ITradeMetadata>;

    constructor() {
        this.authorizedAuditors = new Set<string>();
        this.offChainStorage = new Map<string, ITradeMetadata>();
    }

    grantAuditAccess(auditor: string): void {
        this.authorizedAuditors.add(auditor);
    }

    revokeAuditAccess(auditor: string): void {
        this.authorizedAuditors.delete(auditor);
    }

    hasAuditAccess(auditor: string): boolean {
        return this.authorizedAuditors.has(auditor);
    }

    /**
     * Simulates storing private data that is linked to a trade identifier.
     * In production this could be encrypted on IPFS with keys shared only with auditors.
     */
    secureTradeData(tradeId: string, metadata: ITradeMetadata): void {
        this.offChainStorage.set(tradeId, { ...metadata });
    }

    /**
     * Simulates selective disclosure for regulatory compliance.
     * If the auditor is authorized, returns the detailed unencrypted metadata.
     */
    revealTradeDetails(tradeId: string, auditor: string): ITradeMetadata | null {
        if (!this.hasAuditAccess(auditor)) {
            throw new Error('Unauthorized Access: Auditor does not have compliance access right.');
        }

        const data = this.offChainStorage.get(tradeId);
        return data || null;
    }
}
