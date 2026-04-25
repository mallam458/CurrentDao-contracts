/**
 * @title SecurityStructs
 * @dev Data structures for advanced security features including ZK proofs and privacy mechanisms
 * @dev Provides optimized structs for gas-efficient storage and computation
 */

import {
  ZKCircuitType,
  SMPCComputationType,
  QuantumResistantKeyType,
  HomomorphicScheme,
  PrivacyLevel,
  ComplianceSeverity
} from '../interfaces/IAdvancedSecurity';

// Zero-Knowledge Proof Structures

export class ZKStatementStruct {
  constructor(
    public circuitType: ZKCircuitType,
    public publicInputs: string[],
    public constraints: ZKConstraintStruct[]
  ) {}

  static serialize(statement: ZKStatementStruct): string {
    return JSON.stringify({
      circuitType: statement.circuitType,
      publicInputs: statement.publicInputs,
      constraints: statement.constraints.map(c => ZKConstraintStruct.serialize(c))
    });
  }

  static deserialize(data: string): ZKStatementStruct {
    const parsed = JSON.parse(data);
    return new ZKStatementStruct(
      parsed.circuitType,
      parsed.publicInputs,
      parsed.constraints.map((c: any) => ZKConstraintStruct.deserialize(c))
    );
  }

  getHash(): string {
    return this.generateHash();
  }

  private generateHash(): string {
    const data = this.serialize();
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  }
}

export class ZKConstraintStruct {
  constructor(
    public constraintId: string,
    public type: string,
    public parameters: Map<string, any>
  ) {}

  static serialize(constraint: ZKConstraintStruct): string {
    return JSON.stringify({
      constraintId: constraint.constraintId,
      type: constraint.type,
      parameters: Object.fromEntries(constraint.parameters)
    });
  }

  static deserialize(data: string): ZKConstraintStruct {
    const parsed = JSON.parse(data);
    return new ZKConstraintStruct(
      parsed.constraintId,
      parsed.type,
      new Map(Object.entries(parsed.parameters))
    );
  }
}

export class ZKProofStruct {
  constructor(
    public proof: string,
    public publicInputs: string[],
    public verificationHash: string,
    public circuitType: ZKCircuitType,
    public timestamp: number,
    public gasUsed: number
  ) {}

  static serialize(proof: ZKProofStruct): string {
    return JSON.stringify({
      proof: proof.proof,
      publicInputs: proof.publicInputs,
      verificationHash: proof.verificationHash,
      circuitType: proof.circuitType,
      timestamp: proof.timestamp,
      gasUsed: proof.gasUsed
    });
  }

  static deserialize(data: string): ZKProofStruct {
    const parsed = JSON.parse(data);
    return new ZKProofStruct(
      parsed.proof,
      parsed.publicInputs,
      parsed.verificationHash,
      parsed.circuitType,
      parsed.timestamp,
      parsed.gasUsed
    );
  }

  isValid(): boolean {
    return this.proof.length > 0 && 
           this.verificationHash.length > 0 && 
           this.timestamp > 0;
  }
}

// Privacy-Preserving Transaction Structures

export class PrivateTransactionStruct {
  constructor(
    public transactionId: string,
    public inputs: PrivateInputStruct[],
    public outputs: PrivateOutputStruct[],
    public proof: ZKProofStruct,
    public privacyLevel: PrivacyLevel,
    public timestamp: number
  ) {}

  static serialize(tx: PrivateTransactionStruct): string {
    return JSON.stringify({
      transactionId: tx.transactionId,
      inputs: tx.inputs.map(i => PrivateInputStruct.serialize(i)),
      outputs: tx.outputs.map(o => PrivateOutputStruct.serialize(o)),
      proof: ZKProofStruct.serialize(tx.proof),
      privacyLevel: tx.privacyLevel,
      timestamp: tx.timestamp
    });
  }

  static deserialize(data: string): PrivateTransactionStruct {
    const parsed = JSON.parse(data);
    return new PrivateTransactionStruct(
      parsed.transactionId,
      parsed.inputs.map((i: any) => PrivateInputStruct.deserialize(i)),
      parsed.outputs.map((o: any) => PrivateOutputStruct.deserialize(o)),
      ZKProofStruct.deserialize(parsed.proof),
      parsed.privacyLevel,
      parsed.timestamp
    );
  }

  getTotalInputValue(): number {
    return this.inputs.reduce((sum, input) => sum + input.value, 0);
  }

  getTotalOutputValue(): number {
    return this.outputs.reduce((sum, output) => sum + output.value, 0);
  }

  isBalanced(): boolean {
    return this.getTotalInputValue() === this.getTotalOutputValue();
  }
}

export class PrivateInputStruct {
  constructor(
    public commitment: string,
    public nullifier: string,
    public value: number,
    public merkleProof: string
  ) {}

  static serialize(input: PrivateInputStruct): string {
    return JSON.stringify({
      commitment: input.commitment,
      nullifier: input.nullifier,
      value: input.value,
      merkleProof: input.merkleProof
    });
  }

  static deserialize(data: string): PrivateInputStruct {
    const parsed = JSON.parse(data);
    return new PrivateInputStruct(
      parsed.commitment,
      parsed.nullifier,
      parsed.value,
      parsed.merkleProof
    );
  }
}

export class PrivateOutputStruct {
  constructor(
    public commitment: string,
    public encryptedValue: string,
    public value: number,
    public merkleProof: string
  ) {}

  static serialize(output: PrivateOutputStruct): string {
    return JSON.stringify({
      commitment: output.commitment,
      encryptedValue: output.encryptedValue,
      value: output.value,
      merkleProof: output.merkleProof
    });
  }

  static deserialize(data: string): PrivateOutputStruct {
    const parsed = JSON.parse(data);
    return new PrivateOutputStruct(
      parsed.commitment,
      parsed.encryptedValue,
      parsed.value,
      parsed.merkleProof
    );
  }
}

// Energy Trading Structures

export class PrivateEnergyTradeStruct {
  constructor(
    public tradeId: string,
    public seller: string,
    public buyer: string,
    public energyAmount: number,
    public price: number,
    public proof: ZKProofStruct,
    public status: TradeStatus,
    public timestamp: number
  ) {}

  static serialize(trade: PrivateEnergyTradeStruct): string {
    return JSON.stringify({
      tradeId: trade.tradeId,
      seller: trade.seller,
      buyer: trade.buyer,
      energyAmount: trade.energyAmount,
      price: trade.price,
      proof: ZKProofStruct.serialize(trade.proof),
      status: trade.status,
      timestamp: trade.timestamp
    });
  }

  static deserialize(data: string): PrivateEnergyTradeStruct {
    const parsed = JSON.parse(data);
    return new PrivateEnergyTradeStruct(
      parsed.tradeId,
      parsed.seller,
      parsed.buyer,
      parsed.energyAmount,
      parsed.price,
      ZKProofStruct.deserialize(parsed.proof),
      parsed.status,
      parsed.timestamp
    );
  }

  getTotalValue(): number {
    return this.energyAmount * this.price;
  }

  isMatchable(): boolean {
    return this.status === TradeStatus.PENDING;
  }
}

export enum TradeStatus {
  PENDING = "PENDING",
  MATCHED = "MATCHED",
  EXECUTED = "EXECUTED",
  CANCELLED = "CANCELLED",
  FAILED = "FAILED"
}

// Secure Multi-Party Computation Structures

export class SMPCComputationStruct {
  constructor(
    public computationId: string,
    public participants: string[],
    public computationType: SMPCComputationType,
    public status: SMPCStatus,
    public encryptedInputs: EncryptedInputStruct[],
    public shares: Map<string, string>,
    public result?: SMPCResultStruct,
    public createdAt: number,
    public completedAt?: number
  ) {}

  static serialize(computation: SMPCComputationStruct): string {
    return JSON.stringify({
      computationId: computation.computationId,
      participants: computation.participants,
      computationType: computation.computationType,
      status: computation.status,
      encryptedInputs: computation.encryptedInputs.map(i => EncryptedInputStruct.serialize(i)),
      shares: Object.fromEntries(computation.shares),
      result: computation.result ? SMPCResultStruct.serialize(computation.result) : null,
      createdAt: computation.createdAt,
      completedAt: computation.completedAt
    });
  }

  static deserialize(data: string): SMPCComputationStruct {
    const parsed = JSON.parse(data);
    return new SMPCComputationStruct(
      parsed.computationId,
      parsed.participants,
      parsed.computationType,
      parsed.status,
      parsed.encryptedInputs.map((i: any) => EncryptedInputStruct.deserialize(i)),
      new Map(Object.entries(parsed.shares)),
      parsed.result ? SMPCResultStruct.deserialize(parsed.result) : undefined,
      parsed.createdAt,
      parsed.completedAt
    );
  }

  isComplete(): boolean {
    return this.status === SMPCStatus.COMPLETED && this.result !== undefined;
  }

  hasAllShares(): boolean {
    return this.shares.size === this.participants.length;
  }
}

export enum SMPCStatus {
  INITIATED = "INITIATED",
  COLLECTING_SHARES = "COLLECTING_SHARES",
  COMPUTING = "COMPUTING",
  COMPLETED = "COMPLETED",
  FAILED = "FAILED"
}

export class EncryptedInputStruct {
  constructor(
    public participant: string,
    public encryptedData: string,
    public keyShare: string,
    public checksum: string
  ) {}

  static serialize(input: EncryptedInputStruct): string {
    return JSON.stringify({
      participant: input.participant,
      encryptedData: input.encryptedData,
      keyShare: input.keyShare,
      checksum: input.checksum
    });
  }

  static deserialize(data: string): EncryptedInputStruct {
    const parsed = JSON.parse(data);
    return new EncryptedInputStruct(
      parsed.participant,
      parsed.encryptedData,
      parsed.keyShare,
      parsed.checksum
    );
  }

  verifyIntegrity(): boolean {
    const computedChecksum = this.computeChecksum();
    return computedChecksum === this.checksum;
  }

  private computeChecksum(): string {
    const data = this.participant + this.encryptedData + this.keyShare;
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  }
}

export class SMPCResultStruct {
  constructor(
    public result: string,
    public proof: string,
    public participants: string[],
    public computationType: SMPCComputationType,
    public timestamp: number,
    public confidence: number
  ) {}

  static serialize(result: SMPCResultStruct): string {
    return JSON.stringify({
      result: result.result,
      proof: result.proof,
      participants: result.participants,
      computationType: result.computationType,
      timestamp: result.timestamp,
      confidence: result.confidence
    });
  }

  static deserialize(data: string): SMPCResultStruct {
    const parsed = JSON.parse(data);
    return new SMPCResultStruct(
      parsed.result,
      parsed.proof,
      parsed.participants,
      parsed.computationType,
      parsed.timestamp,
      parsed.confidence
    );
  }

  isValid(): boolean {
    return this.result.length > 0 && 
           this.proof.length > 0 && 
           this.confidence >= 0 && 
           this.confidence <= 1;
  }
}

// Quantum-Resistant Cryptography Structures

export class QuantumResistantKeyStruct {
  constructor(
    public keyId: string,
    public keyType: QuantumResistantKeyType,
    public publicKey: string,
    public privateKey?: string,
    public parameters: Map<string, string>,
    public createdAt: number,
    public expiresAt?: number
  ) {}

  static serialize(key: QuantumResistantKeyStruct): string {
    return JSON.stringify({
      keyId: key.keyId,
      keyType: key.keyType,
      publicKey: key.publicKey,
      privateKey: key.privateKey || null,
      parameters: Object.fromEntries(key.parameters),
      createdAt: key.createdAt,
      expiresAt: key.expiresAt || null
    });
  }

  static deserialize(data: string): QuantumResistantKeyStruct {
    const parsed = JSON.parse(data);
    return new QuantumResistantKeyStruct(
      parsed.keyId,
      parsed.keyType,
      parsed.publicKey,
      parsed.privateKey || undefined,
      new Map(Object.entries(parsed.parameters)),
      parsed.createdAt,
      parsed.expiresAt || undefined
    );
  }

  isExpired(): boolean {
    if (!this.expiresAt) return false;
    return Date.now() > this.expiresAt;
  }

  isValid(): boolean {
    return this.publicKey.length > 0 && !this.isExpired();
  }
}

export class HomomorphicCiphertextStruct {
  constructor(
    public ciphertext: string,
    public randomness: string,
    public scheme: HomomorphicScheme,
    public operationsPerformed: number,
    public maxOperations: number
  ) {}

  static serialize(ct: HomomorphicCiphertextStruct): string {
    return JSON.stringify({
      ciphertext: ct.ciphertext,
      randomness: ct.randomness,
      scheme: ct.scheme,
      operationsPerformed: ct.operationsPerformed,
      maxOperations: ct.maxOperations
    });
  }

  static deserialize(data: string): HomomorphicCiphertextStruct {
    const parsed = JSON.parse(data);
    return new HomomorphicCiphertextStruct(
      parsed.ciphertext,
      parsed.randomness,
      parsed.scheme,
      parsed.operationsPerformed,
      parsed.maxOperations
    );
  }

  canPerformOperation(): boolean {
    return this.operationsPerformed < this.maxOperations;
  }

  getRemainingOperations(): number {
    return Math.max(0, this.maxOperations - this.operationsPerformed);
  }
}

// Compliance and Audit Structures

export class PrivacyAuditEntryStruct {
  constructor(
    public entryId: string,
    public action: string,
    public actor: string,
    public privacyLevel: PrivacyLevel,
    public complianceMetadata: ComplianceMetadataStruct,
    public timestamp: number,
    public verified: boolean
  ) {}

  static serialize(entry: PrivacyAuditEntryStruct): string {
    return JSON.stringify({
      entryId: entry.entryId,
      action: entry.action,
      actor: entry.actor,
      privacyLevel: entry.privacyLevel,
      complianceMetadata: ComplianceMetadataStruct.serialize(entry.complianceMetadata),
      timestamp: entry.timestamp,
      verified: entry.verified
    });
  }

  static deserialize(data: string): PrivacyAuditEntryStruct {
    const parsed = JSON.parse(data);
    return new PrivacyAuditEntryStruct(
      parsed.entryId,
      parsed.action,
      parsed.actor,
      parsed.privacyLevel,
      ComplianceMetadataStruct.deserialize(parsed.complianceMetadata),
      parsed.timestamp,
      parsed.verified
    );
  }

  isCompliant(): boolean {
    return this.complianceMetadata.complianceScore >= 0.8 && this.verified;
  }
}

export class ComplianceMetadataStruct {
  constructor(
    public regulation: string,
    public jurisdiction: string,
    public complianceScore: number,
    public requiredApprovals: string[],
    public auditTrail: string[]
  ) {}

  static serialize(metadata: ComplianceMetadataStruct): string {
    return JSON.stringify({
      regulation: metadata.regulation,
      jurisdiction: metadata.jurisdiction,
      complianceScore: metadata.complianceScore,
      requiredApprovals: metadata.requiredApprovals,
      auditTrail: metadata.auditTrail
    });
  }

  static deserialize(data: string): ComplianceMetadataStruct {
    const parsed = JSON.parse(data);
    return new ComplianceMetadataStruct(
      parsed.regulation,
      parsed.jurisdiction,
      parsed.complianceScore,
      parsed.requiredApprovals,
      parsed.auditTrail
    );
  }

  hasRequiredApprovals(approvals: string[]): boolean {
    return this.requiredApprovals.every(required => 
      approvals.includes(required)
    );
  }
}

export class ComplianceViolationStruct {
  constructor(
    public violationId: string,
    public type: string,
    public severity: ComplianceSeverity,
    public description: string,
    public timestamp: number,
    public resolved: boolean,
    public resolutionNotes?: string
  ) {}

  static serialize(violation: ComplianceViolationStruct): string {
    return JSON.stringify({
      violationId: violation.violationId,
      type: violation.type,
      severity: violation.severity,
      description: violation.description,
      timestamp: violation.timestamp,
      resolved: violation.resolved,
      resolutionNotes: violation.resolutionNotes || null
    });
  }

  static deserialize(data: string): ComplianceViolationStruct {
    const parsed = JSON.parse(data);
    return new ComplianceViolationStruct(
      parsed.violationId,
      parsed.type,
      parsed.severity,
      parsed.description,
      parsed.timestamp,
      parsed.resolved,
      parsed.resolutionNotes || undefined
    );
  }

  isCritical(): boolean {
    return this.severity === ComplianceSeverity.CRITICAL;
  }

  resolve(notes: string): void {
    this.resolved = true;
    this.resolutionNotes = notes;
  }
}

// Gas Optimization Structures

export class GasOptimizationMetrics {
  constructor(
    public originalGasEstimate: number,
    public optimizedGasEstimate: number,
    public optimizationTechniques: string[],
    public gasSavings: number,
    public savingsPercentage: number
  ) {}

  static calculateSavings(original: number, optimized: number): number {
    return original - optimized;
  }

  static calculateSavingsPercentage(original: number, optimized: number): number {
    if (original === 0) return 0;
    return ((original - optimized) / original) * 100;
  }

  isOptimized(): boolean {
    return this.gasSavings > 0 && this.savingsPercentage >= 10;
  }
}

// Utility Functions

export class StructUtils {
  static generateId(prefix: string = ''): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 9);
    return prefix ? `${prefix}_${timestamp}_${random}` : `${timestamp}_${random}`;
  }

  static validateTimestamp(timestamp: number): boolean {
    const now = Date.now();
    const oneYearAgo = now - (365 * 24 * 60 * 60 * 1000);
    const oneYearFromNow = now + (365 * 24 * 60 * 60 * 1000);
    return timestamp >= oneYearAgo && timestamp <= oneYearFromNow;
  }

  static calculateHash(data: string): string {
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  }

  static validateAddress(address: string): boolean {
    return /^[0-9a-fA-F]{40}$/.test(address);
  }

  static validateCommitment(commitment: string): boolean {
    return commitment.length === 64 && /^[0-9a-fA-F]+$/.test(commitment);
  }

  static validateProof(proof: string): boolean {
    return proof.length > 0 && /^[0-9a-fA-F]+$/.test(proof);
  }
}
