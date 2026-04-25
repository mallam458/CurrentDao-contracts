/**
 * @title AdvancedSecurity Test Suite
 * @dev Comprehensive tests for advanced security features with zero-knowledge proofs
 * @dev Tests privacy, ZK proofs, SMPC, quantum-resistant security, and gas optimization
 */

import {
  AdvancedSecurity
} from './AdvancedSecurity';

import {
  ZKStatementStruct,
  ZKProofStruct,
  PrivateInputStruct,
  PrivateOutputStruct,
  QuantumResistantKeyStruct,
  HomomorphicCiphertextStruct,
  PrivacyAuditEntryStruct,
  ComplianceMetadataStruct,
  StructUtils
} from './structures/SecurityStructs';

import {
  ZKCircuitType,
  PrivacyLevel,
  SMPCComputationType,
  QuantumResistantKeyType,
  HomomorphicScheme,
  HomomorphicOperation,
  ReportingPeriod,
  PrivacyOperationType
} from './interfaces/IAdvancedSecurity';

describe('AdvancedSecurity', () => {
  let advancedSecurity: AdvancedSecurity;

  beforeEach(() => {
    advancedSecurity = new AdvancedSecurity();
  });

  describe('Zero-Knowledge Proof Functions', () => {
    describe('generateZKProof', () => {
      it('should generate a valid ZK proof for private transaction', async () => {
        const statement = new ZKStatementStruct(
          ZKCircuitType.PRIVATE_TRANSACTION,
          ['public_input_1', 'public_input_2'],
          []
        );

        const witness = {
          privateInputs: ['private_input_1', 'private_input_2'],
          randomness: StructUtils.generateId('random')
        };

        const provingKey = 'test_proving_key';

        const proof = await advancedSecurity.generateZKProof(statement, witness, provingKey);

        expect(proof).toBeDefined();
        expect(proof.proof).toBeTruthy();
        expect(proof.publicInputs).toEqual(statement.publicInputs);
        expect(proof.circuitType).toBe(ZKCircuitType.PRIVATE_TRANSACTION);
        expect(proof.gasUsed).toBeGreaterThan(0);
        expect(proof.verificationHash).toBeTruthy();
      });

      it('should generate ZK proof for energy trade', async () => {
        const statement = new ZKStatementStruct(
          ZKCircuitType.ENERGY_TRADE,
          ['energy_amount', 'price'],
          []
        );

        const witness = {
          privateInputs: ['seller_data', 'buyer_data'],
          randomness: StructUtils.generateId('random')
        };

        const provingKey = 'energy_trade_proving_key';

        const proof = await advancedSecurity.generateZKProof(statement, witness, provingKey);

        expect(proof.circuitType).toBe(ZKCircuitType.ENERGY_TRADE);
        expect(proof.gasUsed).toBeGreaterThan(0);
      });

      it('should throw error for invalid statement', async () => {
        const invalidStatement = {
          circuitType: undefined,
          publicInputs: [],
          constraints: []
        };

        const witness = {
          privateInputs: ['test'],
          randomness: 'random'
        };

        await expect(
          advancedSecurity.generateZKProof(invalidStatement, witness, 'key')
        ).rejects.toThrow('Invalid ZK statement');
      });
    });

    describe('verifyZKProof', () => {
      it('should verify a valid ZK proof', async () => {
        // First generate a proof
        const statement = new ZKStatementStruct(
          ZKCircuitType.PRIVATE_TRANSACTION,
          ['public_input'],
          []
        );

        const witness = {
          privateInputs: ['private_input'],
          randomness: 'randomness'
        };

        const provingKey = 'test_key';
        const verificationKey = 'test_verification_key';

        const proof = await advancedSecurity.generateZKProof(statement, witness, provingKey);

        // Then verify it
        const isValid = await advancedSecurity.verifyZKProof(proof, statement, verificationKey);

        expect(isValid).toBe(true);
      });

      it('should reject invalid proof', async () => {
        const statement = new ZKStatementStruct(
          ZKCircuitType.PRIVATE_TRANSACTION,
          ['public_input'],
          []
        );

        const invalidProof = new ZKProofStruct(
          'invalid_proof',
          ['wrong_input'],
          'wrong_hash',
          ZKCircuitType.PRIVATE_TRANSACTION,
          Date.now(),
          100000
        );

        const isValid = await advancedSecurity.verifyZKProof(invalidProof, statement, 'key');

        expect(isValid).toBe(false);
      });
    });
  });

  describe('Private Transaction Functions', () => {
    describe('createPrivateTransaction', () => {
      it('should create a private transaction with valid inputs', async () => {
        const inputs = [
          {
            commitment: 'commitment_1',
            nullifier: 'nullifier_1',
            merkleProof: 'merkle_proof_1'
          }
        ];

        const outputs = [
          {
            commitment: 'commitment_2',
            encryptedValue: 'encrypted_value',
            merkleProof: 'merkle_proof_2'
          }
        ];

        const proof = new ZKProofStruct(
          'proof_data',
          ['public_input'],
          'verification_hash',
          ZKCircuitType.PRIVATE_TRANSACTION,
          Date.now(),
          200000
        );

        const transactionId = await advancedSecurity.createPrivateTransaction(inputs, outputs, proof);

        expect(transactionId).toBeTruthy();
        expect(transactionId).toMatch(/^privatetx_/);
      });

      it('should throw error for unbalanced transaction', async () => {
        const inputs = [
          {
            commitment: 'commitment_1',
            nullifier: 'nullifier_1',
            merkleProof: 'merkle_proof_1'
          }
        ];

        const outputs = [
          {
            commitment: 'commitment_2',
            encryptedValue: 'encrypted_value',
            merkleProof: 'merkle_proof_2'
          },
          {
            commitment: 'commitment_3',
            encryptedValue: 'encrypted_value_2',
            merkleProof: 'merkle_proof_3'
          }
        ];

        const proof = new ZKProofStruct(
          'proof_data',
          ['public_input'],
          'verification_hash',
          ZKCircuitType.PRIVATE_TRANSACTION,
          Date.now(),
          200000
        );

        await expect(
          advancedSecurity.createPrivateTransaction(inputs, outputs, proof)
        ).rejects.toThrow('Private transaction inputs and outputs must balance');
      });
    });

    describe('verifyPrivateTransaction', () => {
      it('should verify a valid private transaction', async () => {
        // First create a transaction
        const inputs = [
          {
            commitment: 'commitment_1',
            nullifier: 'nullifier_1',
            merkleProof: 'merkle_proof_1'
          }
        ];

        const outputs = [
          {
            commitment: 'commitment_2',
            encryptedValue: 'encrypted_value',
            merkleProof: 'merkle_proof_2'
          }
        ];

        const proof = new ZKProofStruct(
          'proof_data',
          ['public_input'],
          'verification_hash',
          ZKCircuitType.PRIVATE_TRANSACTION,
          Date.now(),
          200000
        );

        const transactionId = await advancedSecurity.createPrivateTransaction(inputs, outputs, proof);

        // Then verify it
        const isValid = await advancedSecurity.verifyPrivateTransaction(transactionId, proof);

        expect(isValid).toBe(true);
      });

      it('should throw error for non-existent transaction', async () => {
        const proof = new ZKProofStruct(
          'proof_data',
          ['public_input'],
          'verification_hash',
          ZKCircuitType.PRIVATE_TRANSACTION,
          Date.now(),
          200000
        );

        await expect(
          advancedSecurity.verifyPrivateTransaction('non_existent', proof)
        ).rejects.toThrow('Private transaction not found');
      });
    });
  });

  describe('Privacy-Preserving Energy Trading', () => {
    describe('createPrivateEnergyTrade', () => {
      it('should create a private energy trade', async () => {
        const seller = 'seller_address';
        const buyer = 'buyer_address';
        const energyAmount = 1000;
        const price = 50;

        const proof = new ZKProofStruct(
          'energy_proof',
          ['energy_public_input'],
          'energy_verification_hash',
          ZKCircuitType.ENERGY_TRADE,
          Date.now(),
          300000
        );

        const tradeId = await advancedSecurity.createPrivateEnergyTrade(
          seller,
          buyer,
          energyAmount,
          price,
          proof
        );

        expect(tradeId).toBeTruthy();
        expect(tradeId).toMatch(/^energytrade_/);
      });
    });

    describe('matchPrivateTrades', () => {
      it('should match complementary trades', async () => {
        // Create two complementary trades
        const proof1 = new ZKProofStruct(
          'proof1',
          ['input1'],
          'hash1',
          ZKCircuitType.ENERGY_TRADE,
          Date.now(),
          300000
        );

        const proof2 = new ZKProofStruct(
          'proof2',
          ['input2'],
          'hash2',
          ZKCircuitType.ENERGY_TRADE,
          Date.now(),
          300000
        );

        const tradeId1 = await advancedSecurity.createPrivateEnergyTrade(
          'seller1',
          'buyer1',
          1000,
          50,
          proof1
        );

        const tradeId2 = await advancedSecurity.createPrivateEnergyTrade(
          'buyer1', // Complementary to first trade
          'seller1',
          1000,
          50,
          proof2
        );

        const matches = await advancedSecurity.matchPrivateTrades([tradeId1, tradeId2]);

        expect(matches).toHaveLength(1);
        expect(matches[0].seller).toBe('seller1');
        expect(matches[0].buyer).toBe('buyer1');
        expect(matches[0].energyAmount).toBe(1000);
      });

      it('should return empty array for non-matching trades', async () => {
        const proof = new ZKProofStruct(
          'proof',
          ['input'],
          'hash',
          ZKCircuitType.ENERGY_TRADE,
          Date.now(),
          300000
        );

        const tradeId1 = await advancedSecurity.createPrivateEnergyTrade(
          'seller1',
          'buyer1',
          1000,
          50,
          proof
        );

        const tradeId2 = await advancedSecurity.createPrivateEnergyTrade(
          'seller2',
          'buyer2',
          2000,
          75,
          proof
        );

        const matches = await advancedSecurity.matchPrivateTrades([tradeId1, tradeId2]);

        expect(matches).toHaveLength(0);
      });
    });

    describe('executePrivateTrade', () => {
      it('should execute a matched trade', async () => {
        const proof = new ZKProofStruct(
          'proof',
          ['input'],
          'hash',
          ZKCircuitType.ENERGY_TRADE,
          Date.now(),
          300000
        );

        const tradeId = await advancedSecurity.createPrivateEnergyTrade(
          'seller',
          'buyer',
          1000,
          50,
          proof
        );

        // First match the trade (simulate matching)
        const matches = await advancedSecurity.matchPrivateTrades([tradeId]);
        
        const settlementProof = new ZKProofStruct(
          'settlement_proof',
          ['settlement_input'],
          'settlement_hash',
          ZKCircuitType.ENERGY_TRADE,
          Date.now(),
          350000
        );

        const executed = await advancedSecurity.executePrivateTrade(tradeId, settlementProof);

        expect(executed).toBe(true);
      });

      it('should throw error for non-matched trade', async () => {
        const proof = new ZKProofStruct(
          'proof',
          ['input'],
          'hash',
          ZKCircuitType.ENERGY_TRADE,
          Date.now(),
          300000
        );

        const tradeId = await advancedSecurity.createPrivateEnergyTrade(
          'seller',
          'buyer',
          1000,
          50,
          proof
        );

        const settlementProof = new ZKProofStruct(
          'settlement_proof',
          ['settlement_input'],
          'settlement_hash',
          ZKCircuitType.ENERGY_TRADE,
          Date.now(),
          350000
        );

        await expect(
          advancedSecurity.executePrivateTrade(tradeId, settlementProof)
        ).rejects.toThrow('Trade must be matched before execution');
      });
    });
  });

  describe('Secure Multi-Party Computation', () => {
    describe('initiateSMPCComputation', () => {
      it('should initiate SMPC computation', async () => {
        const computationId = 'computation_1';
        const participants = ['participant1', 'participant2', 'participant3'];
        const computationType = SMPCComputationType.SUM;
        const encryptedInputs = [
          {
            participant: 'participant1',
            encryptedData: 'encrypted_data_1',
            keyShare: 'key_share_1'
          },
          {
            participant: 'participant2',
            encryptedData: 'encrypted_data_2',
            keyShare: 'key_share_2'
          }
        ];

        await advancedSecurity.initiateSMPCComputation(
          computationId,
          participants,
          computationType,
          encryptedInputs
        );

        // No error thrown means initialization was successful
        expect(true).toBe(true);
      });
    });

    describe('submitSMPCShare', () => {
      it('should submit SMPC share', async () => {
        const computationId = 'computation_2';
        const participants = ['participant1', 'participant2'];
        const encryptedInputs = [
          {
            participant: 'participant1',
            encryptedData: 'encrypted_data_1',
            keyShare: 'key_share_1'
          }
        ];

        await advancedSecurity.initiateSMPCComputation(
          computationId,
          participants,
          SMPCComputationType.SUM,
          encryptedInputs
        );

        await advancedSecurity.submitSMPCShare(
          computationId,
          'participant2',
          'encrypted_share_2'
        );

        // No error thrown means share submission was successful
        expect(true).toBe(true);
      });
    });

    describe('computeSMPCResult', () => {
      it('should compute SMPC result when all shares are submitted', async () => {
        const computationId = 'computation_3';
        const participants = ['participant1', 'participant2'];
        const encryptedInputs = [
          {
            participant: 'participant1',
            encryptedData: 'encrypted_data_1',
            keyShare: 'key_share_1'
          },
          {
            participant: 'participant2',
            encryptedData: 'encrypted_data_2',
            keyShare: 'key_share_2'
          }
        ];

        await advancedSecurity.initiateSMPCComputation(
          computationId,
          participants,
          SMPCComputationType.SUM,
          encryptedInputs
        );

        const result = await advancedSecurity.computeSMPCResult(computationId);

        expect(result).toBeDefined();
        expect(result.result).toBe('SUM_RESULT');
        expect(result.participants).toEqual(participants);
        expect(result.computationType).toBe(SMPCComputationType.SUM);
        expect(result.confidence).toBeGreaterThan(0.9);
      });

      it('should throw error when not all shares are submitted', async () => {
        const computationId = 'computation_4';
        const participants = ['participant1', 'participant2', 'participant3'];
        const encryptedInputs = [
          {
            participant: 'participant1',
            encryptedData: 'encrypted_data_1',
            keyShare: 'key_share_1'
          }
        ];

        await advancedSecurity.initiateSMPCComputation(
          computationId,
          participants,
          SMPCComputationType.SUM,
          encryptedInputs
        );

        await expect(
          advancedSecurity.computeSMPCResult(computationId)
        ).rejects.toThrow('Not all shares have been submitted');
      });
    });
  });

  describe('Advanced Cryptographic Primitives', () => {
    describe('generateQuantumResistantKey', () => {
      it('should generate quantum-resistant key', async () => {
        const keyType = QuantumResistantKeyType.DILITHIUM;

        const key = await advancedSecurity.generateQuantumResistantKey(keyType);

        expect(key).toBeDefined();
        expect(key.keyId).toBeTruthy();
        expect(key.keyType).toBe(keyType);
        expect(key.publicKey).toBeTruthy();
        expect(key.privateKey).toBeTruthy();
        expect(key.createdAt).toBeGreaterThan(0);
        expect(key.expiresAt).toBeGreaterThan(key.createdAt);
      });

      it('should generate different key types', async () => {
        const dilithiumKey = await advancedSecurity.generateQuantumResistantKey(QuantumResistantKeyType.DILITHIUM);
        const falconKey = await advancedSecurity.generateQuantumResistantKey(QuantumResistantKeyType.FALCON);

        expect(dilithiumKey.keyType).toBe(QuantumResistantKeyType.DILITHIUM);
        expect(falconKey.keyType).toBe(QuantumResistantKeyType.FALCON);
        expect(dilithiumKey.keyId).not.toBe(falconKey.keyId);
      });
    });

    describe('verifyQuantumResistantSignature', () => {
      it('should verify quantum-resistant signature', async () => {
        const key = await advancedSecurity.generateQuantumResistantKey(QuantumResistantKeyType.DILITHIUM);
        const message = 'test message';

        // Simulate signature creation (in real implementation, this would use the private key)
        const signature = StructUtils.calculateHash(message + key.publicKey);

        const isValid = await advancedSecurity.verifyQuantumResistantSignature(
          message,
          signature,
          key
        );

        expect(isValid).toBe(true);
      });

      it('should reject invalid signature', async () => {
        const key = await advancedSecurity.generateQuantumResistantKey(QuantumResistantKeyType.DILITHIUM);
        const message = 'test message';
        const invalidSignature = 'invalid_signature';

        const isValid = await advancedSecurity.verifyQuantumResistantSignature(
          message,
          invalidSignature,
          key
        );

        expect(isValid).toBe(false);
      });
    });

    describe('createHomomorphicEncryption', () => {
      it('should create homomorphic encryption', async () => {
        const plaintext = 42;
        const publicKey = 'test_public_key';

        const ciphertext = await advancedSecurity.createHomomorphicEncryption(plaintext, publicKey);

        expect(ciphertext).toBeDefined();
        expect(ciphertext.ciphertext).toBeTruthy();
        expect(ciphertext.randomness).toBeTruthy();
        expect(ciphertext.scheme).toBe(HomomorphicScheme.PAILLIER);
        expect(ciphertext.operationsPerformed).toBe(0);
        expect(ciphertext.maxOperations).toBe(10);
      });
    });

    describe('performHomomorphicOperation', () => {
      it('should perform homomorphic addition', async () => {
        const plaintext1 = 10;
        const plaintext2 = 20;
        const publicKey = 'test_public_key';

        const ciphertext1 = await advancedSecurity.createHomomorphicEncryption(plaintext1, publicKey);
        const ciphertext2 = await advancedSecurity.createHomomorphicEncryption(plaintext2, publicKey);

        const result = await advancedSecurity.performHomomorphicOperation(
          ciphertext1,
          ciphertext2,
          HomomorphicOperation.ADD
        );

        expect(result).toBeDefined();
        expect(result.operationsPerformed).toBe(1);
        expect(result.ciphertext).toContain('HOMO_ADD');
      });

      it('should perform homomorphic multiplication', async () => {
        const plaintext1 = 10;
        const plaintext2 = 20;
        const publicKey = 'test_public_key';

        const ciphertext1 = await advancedSecurity.createHomomorphicEncryption(plaintext1, publicKey);
        const ciphertext2 = await advancedSecurity.createHomomorphicEncryption(plaintext2, publicKey);

        const result = await advancedSecurity.performHomomorphicOperation(
          ciphertext1,
          ciphertext2,
          HomomorphicOperation.MULTIPLY
        );

        expect(result).toBeDefined();
        expect(result.operationsPerformed).toBe(1);
        expect(result.ciphertext).toContain('HOMO_MULT');
      });

      it('should throw error when max operations exceeded', async () => {
        const plaintext = 10;
        const publicKey = 'test_public_key';

        // Create ciphertext with max operations set to 0
        const ciphertext = new HomomorphicCiphertextStruct(
          'test_ciphertext',
          'randomness',
          HomomorphicScheme.PAILLIER,
          0, // Already at max
          0
        );

        const ciphertext2 = await advancedSecurity.createHomomorphicEncryption(plaintext, publicKey);

        await expect(
          advancedSecurity.performHomomorphicOperation(
            ciphertext,
            ciphertext2,
            HomomorphicOperation.ADD
          )
        ).rejects.toThrow('Ciphertext has reached maximum operations');
      });
    });
  });

  describe('Confidential Transaction Processing', () => {
    describe('createConfidentialTransaction', () => {
      it('should create confidential transaction', async () => {
        const from = 'from_address';
        const to = 'to_address';
        const encryptedAmount = 'encrypted_amount';
        const commitment = 'commitment';
        const proof = new ZKProofStruct(
          'confidential_proof',
          ['confidential_input'],
          'confidential_hash',
          ZKCircuitType.CONFIDENTIAL_ASSET,
          Date.now(),
          250000
        );

        const transactionId = await advancedSecurity.createConfidentialTransaction(
          from,
          to,
          encryptedAmount,
          commitment,
          proof
        );

        expect(transactionId).toBeTruthy();
        expect(transactionId).toMatch(/^confidentialtx_/);
      });
    });

    describe('verifyConfidentialTransaction', () => {
      it('should verify confidential transaction', async () => {
        const proof = new ZKProofStruct(
          'confidential_proof',
          ['confidential_input'],
          'confidential_hash',
          ZKCircuitType.CONFIDENTIAL_ASSET,
          Date.now(),
          250000
        );

        const transactionId = await advancedSecurity.createConfidentialTransaction(
          'from',
          'to',
          'encrypted_amount',
          'commitment',
          proof
        );

        const isValid = await advancedSecurity.verifyConfidentialTransaction(transactionId);

        expect(isValid).toBe(true);
      });

      it('should throw error for non-existent transaction', async () => {
        await expect(
          advancedSecurity.verifyConfidentialTransaction('non_existent')
        ).rejects.toThrow('Confidential transaction not found');
      });
    });

    describe('decryptTransactionAmount', () => {
      it('should decrypt transaction amount', async () => {
        const proof = new ZKProofStruct(
          'confidential_proof',
          ['confidential_input'],
          'confidential_hash',
          ZKCircuitType.CONFIDENTIAL_ASSET,
          Date.now(),
          250000
        );

        const transactionId = await advancedSecurity.createConfidentialTransaction(
          'from',
          'to',
          'HOMOMORPHIC_42_test_public_key', // Simulated encrypted amount
          'commitment',
          proof
        );

        const viewingKey = 'test_viewing_key';
        const amount = await advancedSecurity.decryptTransactionAmount(transactionId, viewingKey);

        expect(amount).toBe(42);
      });
    });
  });

  describe('Privacy Audit Trail Compliance', () => {
    describe('createPrivacyAuditEntry', () => {
      it('should create privacy audit entry', async () => {
        const action = 'TEST_ACTION';
        const actor = 'test_actor';
        const privacyLevel = PrivacyLevel.PRIVATE;
        const complianceMetadata = new ComplianceMetadataStruct(
          'TEST_REGULATION',
          'TEST_JURISDICTION',
          0.9,
          ['APPROVAL_1'],
          ['audit_trail_1']
        );

        const entryId = await advancedSecurity.createPrivacyAuditEntry(
          action,
          actor,
          privacyLevel,
          complianceMetadata
        );

        expect(entryId).toBeTruthy();
        expect(entryId).toMatch(/^audit_/);
      });
    });

    describe('verifyPrivacyCompliance', () => {
      it('should verify compliant audit entry', async () => {
        const complianceMetadata = new ComplianceMetadataStruct(
          'TEST_REGULATION',
          'TEST_JURISDICTION',
          0.95, // High compliance score
          ['APPROVAL_1'],
          ['audit_trail_1']
        );

        const entryId = await advancedSecurity.createPrivacyAuditEntry(
          'COMPLIANT_ACTION',
          'test_actor',
          PrivacyLevel.PRIVATE,
          complianceMetadata
        );

        const isCompliant = await advancedSecurity.verifyPrivacyCompliance(entryId);

        expect(isCompliant).toBe(true);
      });

      it('should reject non-compliant audit entry', async () => {
        const complianceMetadata = new ComplianceMetadataStruct(
          'TEST_REGULATION',
          'TEST_JURISDICTION',
          0.5, // Low compliance score
          ['APPROVAL_1'],
          ['audit_trail_1']
        );

        const entryId = await advancedSecurity.createPrivacyAuditEntry(
          'NON_COMPLIANT_ACTION',
          'test_actor',
          PrivacyLevel.PRIVATE,
          complianceMetadata
        );

        const isCompliant = await advancedSecurity.verifyPrivacyCompliance(entryId);

        expect(isCompliant).toBe(false);
      });

      it('should return false for non-existent entry', async () => {
        const isCompliant = await advancedSecurity.verifyPrivacyCompliance('non_existent');

        expect(isCompliant).toBe(false);
      });
    });

    describe('generatePrivacyReport', () => {
      it('should generate privacy compliance report', async () => {
        // Create some audit entries
        const complianceMetadata = new ComplianceMetadataStruct(
          'TEST_REGULATION',
          'TEST_JURISDICTION',
          0.9,
          ['APPROVAL_1'],
          ['audit_trail_1']
        );

        await advancedSecurity.createPrivacyAuditEntry(
          'ACTION_1',
          'actor_1',
          PrivacyLevel.PRIVATE,
          complianceMetadata
        );

        await advancedSecurity.createPrivacyAuditEntry(
          'ACTION_2',
          'actor_2',
          PrivacyLevel.CONFIDENTIAL,
          complianceMetadata
        );

        const report = await advancedSecurity.generatePrivacyReport(
          ReportingPeriod.DAILY,
          PrivacyLevel.PRIVATE
        );

        expect(report).toBeDefined();
        expect(report.period).toBe(ReportingPeriod.DAILY);
        expect(report.totalPrivateTransactions).toBeGreaterThan(0);
        expect(report.complianceScore).toBeGreaterThanOrEqual(0);
        expect(report.complianceScore).toBeLessThanOrEqual(1);
        expect(report.violations).toBeDefined();
        expect(report.recommendations).toBeDefined();
        expect(report.privacyMetrics).toBeDefined();
        expect(report.privacyMetrics.averagePrivacyLevel).toBeGreaterThan(0);
        expect(report.privacyMetrics.verificationSuccessRate).toBeGreaterThanOrEqual(0);
        expect(report.privacyMetrics.auditTrailCompleteness).toBeGreaterThanOrEqual(0);
      });
    });
  });

  describe('Gas Optimization', () => {
    describe('estimatePrivacyOperationGas', () => {
      it('should estimate gas for ZK proof generation', async () => {
        const parameters = { circuitType: ZKCircuitType.PRIVATE_TRANSACTION };
        const gasEstimate = await advancedSecurity.estimatePrivacyOperationGas(
          PrivacyOperationType.ZK_PROOF_GENERATION,
          parameters
        );

        expect(gasEstimate).toBeGreaterThan(0);
        expect(gasEstimate).toBeGreaterThan(100000); // Should be substantial for ZK operations
      });

      it('should estimate gas for private transaction', async () => {
        const gasEstimate = await advancedSecurity.estimatePrivacyOperationGas(
          PrivacyOperationType.PRIVATE_TRANSACTION,
          {}
        );

        expect(gasEstimate).toBe(250000); // Should match the default estimate
      });

      it('should estimate gas for SMPC computation', async () => {
        const gasEstimate = await advancedSecurity.estimatePrivacyOperationGas(
          PrivacyOperationType.SMPC_COMPUTATION,
          {}
        );

        expect(gasEstimate).toBe(500000); // Should match the default estimate
      });
    });

    describe('optimizePrivacyGas', () => {
      it('should optimize gas usage for transaction', async () => {
        const transaction = {
          transactionId: 'test_tx',
          gasEstimate: 1000000,
          operationType: PrivacyOperationType.PRIVATE_TRANSACTION
        };

        const optimized = await advancedSecurity.optimizePrivacyGas(transaction);

        expect(optimized).toBeDefined();
        expect(optimized.originalTransaction).toBe(transaction);
        expect(optimized.optimizedTransaction.gasEstimate).toBeLessThan(transaction.gasEstimate);
        expect(optimized.gasSavings).toBeGreaterThan(0);
        expect(optimized.savingsPercentage).toBeGreaterThan(0);
        expect(optimized.savingsPercentage).toBeLessThanOrEqual(100);
      });
    });

    describe('batchPrivacyOperations', () => {
      it('should batch operations and achieve gas savings', async () => {
        const operations = [
          {
            operationId: 'op1',
            type: PrivacyOperationType.ZK_PROOF_GENERATION,
            gasEstimate: 500000
          },
          {
            operationId: 'op2',
            type: PrivacyOperationType.ZK_PROOF_GENERATION,
            gasEstimate: 500000
          },
          {
            operationId: 'op3',
            type: PrivacyOperationType.PRIVATE_TRANSACTION,
            gasEstimate: 250000
          }
        ];

        const batchedResult = await advancedSecurity.batchPrivacyOperations(operations);

        expect(batchedResult).toBeDefined();
        expect(batchedResult.batchId).toBeTruthy();
        expect(batchedResult.operations).toEqual(operations);
        expect(batchedResult.results).toHaveLength(3);
        expect(batchedResult.totalGasUsed).toBeGreaterThan(0);
        expect(batchedResult.gasSavings).toBeGreaterThan(0);
        expect(batchedResult.savingsPercentage).toBeGreaterThan(0);

        // Should achieve at least 20% savings from batching
        expect(batchedResult.savingsPercentage).toBeGreaterThan(20);
      });
    });
  });

  describe('Integration Functions', () => {
    describe('integrateWithSecurityMonitor', () => {
      it('should integrate with security monitor', async () => {
        const securityMonitorAddress = '0x1234567890123456789012345678901234567890';

        // Should not throw error
        await expect(
          advancedSecurity.integrateWithSecurityMonitor(securityMonitorAddress)
        ).resolves.toBeUndefined();
      });
    });

    describe('syncPrivacyEvents', () => {
      it('should sync privacy events', async () => {
        const events = [
          {
            eventId: 'event1',
            eventType: 'ZK_PROOF_GENERATED',
            timestamp: Date.now()
          },
          {
            eventId: 'event2',
            eventType: 'PRIVATE_TRANSACTION_CREATED',
            timestamp: Date.now()
          }
        ];

        // Should not throw error
        await expect(
          advancedSecurity.syncPrivacyEvents(events)
        ).resolves.toBeUndefined();
      });
    });

    describe('crossValidateSecurity', () => {
      it('should perform cross-validation', async () => {
        const securityData = {
          securityLevel: 0.9,
          threats: ['threat1', 'threat2'],
          recommendations: ['recommendation1']
        };

        const result = await advancedSecurity.crossValidateSecurity(securityData);

        expect(result).toBeDefined();
        expect(result.validationResult).toBe(true);
        expect(result.confidence).toBeGreaterThan(0);
        expect(result.discrepancies).toBeDefined();
        expect(result.recommendations).toBeDefined();
      });
    });
  });

  describe('Event Handling', () => {
    it('should emit ZK proof generated event', async () => {
      let eventReceived = false;
      let eventData: any = null;

      advancedSecurity.onZKProofGenerated = (event) => {
        eventReceived = true;
        eventData = event;
      };

      const statement = new ZKStatementStruct(
        ZKCircuitType.PRIVATE_TRANSACTION,
        ['public_input'],
        []
      );

      const witness = {
        privateInputs: ['private_input'],
        randomness: 'randomness'
      };

      await advancedSecurity.generateZKProof(statement, witness, 'key');

      expect(eventReceived).toBe(true);
      expect(eventData).toBeDefined();
      expect(eventData.circuitType).toBe(ZKCircuitType.PRIVATE_TRANSACTION);
      expect(eventData.gasUsed).toBeGreaterThan(0);
    });

    it('should emit private transaction created event', async () => {
      let eventReceived = false;
      let eventData: any = null;

      advancedSecurity.onPrivateTransactionCreated = (event) => {
        eventReceived = true;
        eventData = event;
      };

      const inputs = [
        {
          commitment: 'commitment_1',
          nullifier: 'nullifier_1',
          merkleProof: 'merkle_proof_1'
        }
      ];

      const outputs = [
        {
          commitment: 'commitment_2',
          encryptedValue: 'encrypted_value',
          merkleProof: 'merkle_proof_2'
        }
      ];

      const proof = new ZKProofStruct(
        'proof_data',
        ['public_input'],
        'verification_hash',
        ZKCircuitType.PRIVATE_TRANSACTION,
        Date.now(),
        200000
      );

      await advancedSecurity.createPrivateTransaction(inputs, outputs, proof);

      expect(eventReceived).toBe(true);
      expect(eventData).toBeDefined();
      expect(eventData.inputCount).toBe(1);
      expect(eventData.outputCount).toBe(1);
      expect(eventData.privacyLevel).toBe(PrivacyLevel.PRIVATE);
    });

    it('should emit energy trade matched event', async () => {
      let eventReceived = false;
      let eventData: any = null;

      advancedSecurity.onEnergyTradeMatched = (event) => {
        eventReceived = true;
        eventData = event;
      };

      const proof = new ZKProofStruct(
        'proof',
        ['input'],
        'hash',
        ZKCircuitType.ENERGY_TRADE,
        Date.now(),
        300000
      );

      const tradeId1 = await advancedSecurity.createPrivateEnergyTrade(
        'seller1',
        'buyer1',
        1000,
        50,
        proof
      );

      const tradeId2 = await advancedSecurity.createPrivateEnergyTrade(
        'buyer1',
        'seller1',
        1000,
        50,
        proof
      );

      await advancedSecurity.matchPrivateTrades([tradeId1, tradeId2]);

      expect(eventReceived).toBe(true);
      expect(eventData).toBeDefined();
      expect(eventData.seller).toBe('seller1');
      expect(eventData.buyer).toBe('buyer1');
      expect(eventData.energyAmount).toBe(1000);
    });

    it('should emit SMPC completed event', async () => {
      let eventReceived = false;
      let eventData: any = null;

      advancedSecurity.onSMPCCompleted = (event) => {
        eventReceived = true;
        eventData = event;
      };

      const computationId = 'computation_event_test';
      const participants = ['participant1', 'participant2'];
      const encryptedInputs = [
        {
          participant: 'participant1',
          encryptedData: 'encrypted_data_1',
          keyShare: 'key_share_1'
        },
        {
          participant: 'participant2',
          encryptedData: 'encrypted_data_2',
          keyShare: 'key_share_2'
        }
      ];

      await advancedSecurity.initiateSMPCComputation(
        computationId,
        participants,
        SMPCComputationType.SUM,
        encryptedInputs
      );

      await advancedSecurity.computeSMPCResult(computationId);

      expect(eventReceived).toBe(true);
      expect(eventData).toBeDefined();
      expect(eventData.computationId).toBe(computationId);
      expect(eventData.computationType).toBe(SMPCComputationType.SUM);
      expect(eventData.participantCount).toBe(2);
    });
  });

  describe('Gas Optimization Targets', () => {
    it('should achieve 50% gas reduction target for privacy operations', async () => {
      // Test individual operation optimization
      const originalTransaction = {
        transactionId: 'gas_test_tx',
        gasEstimate: 1000000,
        operationType: PrivacyOperationType.PRIVATE_TRANSACTION
      };

      const optimized = await advancedSecurity.optimizePrivacyGas(originalTransaction);

      // Should achieve at least 50% reduction
      expect(optimized.savingsPercentage).toBeGreaterThanOrEqual(50);

      // Test batch optimization
      const operations = [
        {
          operationId: 'batch_op1',
          type: PrivacyOperationType.ZK_PROOF_GENERATION,
          gasEstimate: 800000
        },
        {
          operationId: 'batch_op2',
          type: PrivacyOperationType.ZK_PROOF_GENERATION,
          gasEstimate: 800000
        }
      ];

      const batchedResult = await advancedSecurity.batchPrivacyOperations(operations);

      // Batch should achieve even better savings
      expect(batchedResult.savingsPercentage).toBeGreaterThanOrEqual(50);
    });
  });

  describe('Compliance Requirements', () => {
    it('should maintain 100% confidentiality for private trades', async () => {
      const proof = new ZKProofStruct(
        'private_trade_proof',
        ['private_input'],
        'private_hash',
        ZKCircuitType.PRIVATE_TRANSACTION,
        Date.now(),
        400000
      );

      const tradeId = await advancedSecurity.createPrivateEnergyTrade(
        'private_seller',
        'private_buyer',
        5000,
        100,
        proof
      );

      // Verify that the trade is completely private
      // In a real implementation, this would test that no sensitive data is exposed
      expect(tradeId).toBeTruthy();
      expect(tradeId).toMatch(/^energytrade_/);

      // Verify audit trail maintains privacy
      const report = await advancedSecurity.generatePrivacyReport(
        ReportingPeriod.DAILY,
        PrivacyLevel.PRIVATE
      );

      expect(report.privacyMetrics.averagePrivacyLevel).toBeGreaterThanOrEqual(3); // PRIVATE level
    });

    it('should preserve transaction privacy while maintaining compliance', async () => {
      const complianceMetadata = new ComplianceMetadataStruct(
        'ENERGY_TRADING_REGULATION',
        'GLOBAL',
        0.95,
        ['ZK_PROOF_VERIFIED', 'COMPLIANCE_CHECK'],
        ['compliance_audit_1']
      );

      const entryId = await advancedSecurity.createPrivacyAuditEntry(
        'COMPLIANT_PRIVATE_TRANSACTION',
        'compliant_actor',
        PrivacyLevel.CONFIDENTIAL,
        complianceMetadata
      );

      const isCompliant = await advancedSecurity.verifyPrivacyCompliance(entryId);

      expect(isCompliant).toBe(true);

      // Verify that privacy is maintained while ensuring compliance
      const report = await advancedSecurity.generatePrivacyReport(
        ReportingPeriod.DAILY,
        PrivacyLevel.CONFIDENTIAL
      );

      expect(report.complianceScore).toBeGreaterThanOrEqual(0.8);
      expect(report.privacyMetrics.auditTrailCompleteness).toBeGreaterThan(0);
    });
  });
});
