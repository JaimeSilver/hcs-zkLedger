# zkLedger-hcs
 zkLedger implementation on HCS
 
Abstract – Privacy-Preserving ledgers are Distributed Ledgers designed to preserve confidentiality about the nature of the transactions conducted, including the value, the actors involved, the asset balance on the ledger, as well as the sourcing graph of the assets recorded. zkLedger provided the first system that enables auditing directly from the ledger without the need to reveal keys, use any third-party validator, or generate any trusted setup. FabZK builds on this model as an extension to Hyperledger Fabric, keeping the privacy-preserving capabilities of zkLedger, but increasing the throughput capacity. This paper implements the baseline model of zkLedger in an open network of Hedera Hashgraph but incorporates BulletProofs to calculate Range Proofs on the ledger, and the Disjunctive Zero-Knowledge Proof
used for consistency in FabZK.
zkLedger provides complete and confidential auditing, where the participants cannot hide transactions. Still, the auditor only needs the value of individual operations to ascertain the integrity of the ledger. By implementing zkLedger on top of Hedera Consensus Service, our implementation assures a globally ordered ledger for valid transactions, including asynchronous Byzantine Fault Tolerance for the system.

[Read the Paper](zkLedger-HCS_1.0.pdf)

[License](LICENSE)
