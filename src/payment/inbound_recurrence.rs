// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use bitcoin::hashes::{sha256, Hash as BitcoinHash, HashEngine};
use bitcoin::secp256k1::PublicKey;
use lightning::ln::channelmanager::PaymentId;
use lightning::offers::offer::{OfferId, Recurrence};
use lightning::{impl_ser_tlv_based, impl_ser_tlv_based_enum};

use crate::data_store::{StorableObject, StorableObjectId, StorableObjectUpdate};
use crate::hex_utils;

/// A stable identifier derived from an inbound relationship's offer and payer signing public key.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct InboundRecurrenceId(pub [u8; 32]);

impl InboundRecurrenceId {
	/// Derives the relationship id by hashing both fixed-width identifiers in order.
	pub(crate) fn new(offer_id: OfferId, payer_signing_pubkey: PublicKey) -> Self {
		// The 32-byte hash encodes to 64 hex characters, within the KVStore key length limit.
		let mut engine = sha256::Hash::engine();
		engine.input(&offer_id.0);
		engine.input(&payer_signing_pubkey.serialize());
		Self(sha256::Hash::from_engine(engine).to_byte_array())
	}
}

impl StorableObjectId for InboundRecurrenceId {
	/// Encodes the relationship id as a KVStore key.
	fn encode_to_hex_str(&self) -> String {
		hex_utils::to_string(&self.0)
	}

	/// Recovers the relationship id from a hex key containing exactly 32 bytes.
	fn decode_from_hex_str(s: &str) -> Option<Self> {
		hex_utils::to_vec(s)?.try_into().ok().map(Self)
	}
}

/// The lifecycle status of a recurring offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecurrenceStatus {
	/// Recurrence can accept its next payment attempt.
	Active,
	/// Current payment window closed before a payment succeeded.
	Missed,
	/// Recurrence will not accept further payments.
	Cancelled,
	/// Recurrence reached its configured payment limit.
	Completed,
}

impl_ser_tlv_based_enum!(RecurrenceStatus,
	(0, Active) => {},
	(2, Missed) => {},
	(4, Cancelled) => {},
	(6, Completed) => {},
);

/// The payment attempt status of an inbound recurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundRecurrenceClaimStatus {
	/// No claim is in progress. Successful payments are recorded separately.
	Idle,
	/// This payment owns the current expected counter while its claim is pending.
	Pending(PaymentId),
	/// A confirmed failed attempt for the current expected counter.
	///
	/// Retains the payment ID until another attempt replaces it.
	Failed(PaymentId),
}

impl_ser_tlv_based_enum!(InboundRecurrenceClaimStatus,
	(0, Idle) => {},
	{2, Pending} => (),
	{4, Failed} => (),
);

/// Details of recurring payments received for an offer and payer signing public key.
///
/// Individual payment records are available through [`crate::Node::payment`].
///
/// Returned by [`crate::Node::inbound_recurrence`] and [`crate::Node::list_inbound_recurrences`]
/// as a copy of the saved state. Changing this copy does not change the node's stored recurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundRecurrenceDetails {
	/// ID of the offer defining this recurrence.
	pub offer_id: OfferId,

	/// Payer signing public key identifying the payer's relationship with this offer.
	pub payer_signing_pubkey: PublicKey,

	/// Recurrence terms defining the schedule, payment window, and any period limit.
	pub recurrence: Recurrence,

	/// Current lifecycle status of the recurrence.
	pub status: RecurrenceStatus,

	/// UNIX timestamp anchoring period zero of the recurrence, once established.
	///
	/// Together with the recurrence terms, determines when payment windows open and close.
	pub basetime: Option<u64>,

	/// First recurrence period selected by the payer, if specified.
	pub initial_start: Option<u32>,

	/// Status of the attempt for the next expected counter.
	///
	/// Retains the payment ID while a claim is pending or after a confirmed failure.
	/// Successful payments are recorded in [`Self::completed_payments`].
	pub claim_status: InboundRecurrenceClaimStatus,

	/// Successful payment IDs in counter order, starting at counter zero.
	///
	/// The index identifies the counter, and the length is the next counter to reserve. Append
	/// only after PaymentClaimed confirms success. Keep earlier entries to recognize replays
	/// without changing newer progress or reservations.
	pub completed_payments: Vec<PaymentId>,
}

impl_ser_tlv_based!(InboundRecurrenceDetails, {
	(0, offer_id, required),
	(2, payer_signing_pubkey, required),
	(4, recurrence, required),
	(6, status, required),
	(8, basetime, option),
	(10, initial_start, option),
	(14, claim_status, (default_value, InboundRecurrenceClaimStatus::Idle)),
	(16, completed_payments, required_vec),
});

impl StorableObject for InboundRecurrenceDetails {
	type Id = InboundRecurrenceId;
	// Updates are complete relationship snapshots. Event handling will own state transitions.
	type Update = Self;

	/// Derives the store key from this relationship's offer and payer signing public key.
	fn id(&self) -> Self::Id {
		InboundRecurrenceId::new(self.offer_id, self.payer_signing_pubkey)
	}

	/// Replaces a relationship snapshot only when its state changed.
	fn update(&mut self, update: Self::Update) -> bool {
		debug_assert_eq!(StorableObject::id(self), StorableObject::id(&update));
		if *self == update {
			return false;
		}
		*self = update;
		true
	}

	/// Copies the complete relationship state for the generic store's update path.
	fn to_update(&self) -> Self::Update {
		self.clone()
	}
}

impl StorableObjectUpdate<InboundRecurrenceDetails> for InboundRecurrenceDetails {
	/// Routes a snapshot update to its existing relationship.
	fn id(&self) -> InboundRecurrenceId {
		StorableObject::id(self)
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use bitcoin::Network;
	use lightning::offers::offer::{
		RecurrenceBase, RecurrenceLimit, RecurrencePaywindow, RecurrencePeriod, RecurrenceType,
	};
	use lightning::util::persist::KVStore;
	use lightning::util::ser::{Readable, Writeable};

	use super::*;
	use crate::builder::{BuildError, NodeBuilder};
	use crate::entropy::NodeEntropy;
	use crate::io::test_utils::InMemoryStore;
	use crate::io::{INBOUND_RECURRENCE_PRIMARY_NAMESPACE, INBOUND_RECURRENCE_SECONDARY_NAMESPACE};
	use crate::types::{DynStore, DynStoreRef, DynStoreWrapper};
	use crate::Node;

	/// Creates a recurrence with known timing and two completed payments.
	/// Changing either seed gives a different offer or payer.
	fn details(offer: u8, payer: u8) -> InboundRecurrenceDetails {
		let secret = SecretKey::from_slice(&[payer; 32]).unwrap();
		InboundRecurrenceDetails {
			offer_id: OfferId([offer; 32]),
			payer_signing_pubkey: PublicKey::from_secret_key(&Secp256k1::new(), &secret),
			recurrence: Recurrence {
				recurrence_type: RecurrenceType::Compulsory(Some(RecurrenceBase {
					proportional: true,
					basetime: 1_700_000_000,
				})),
				recurrence_period: RecurrencePeriod::Months(1),
				recurrence_paywindow: Some(RecurrencePaywindow {
					seconds_before: 60,
					seconds_after: 120,
				}),
				recurrence_limit: Some(RecurrenceLimit(12)),
			},
			status: RecurrenceStatus::Active,
			basetime: Some(1_700_000_000),
			initial_start: Some(2),
			claim_status: InboundRecurrenceClaimStatus::Idle,
			completed_payments: vec![PaymentId([7; 32]), PaymentId([3; 32])],
		}
	}

	/// Builds a node without starting it or writing logs.
	/// Reuses the seed and storage to check that saved records survive rebuilding.
	fn build_node(store: Arc<DynStore>) -> Result<Node, BuildError> {
		let mut builder = NodeBuilder::new();
		builder.set_network(Network::Regtest).set_log_facade_logger();
		#[cfg(not(feature = "uniffi"))]
		let entropy = NodeEntropy::from_seed_bytes([42; 64]);
		#[cfg(feature = "uniffi")]
		let entropy = NodeEntropy::from_seed_bytes(vec![42; 64]).unwrap();
		builder.build_with_store(entropy, DynStoreRef(store))
	}

	/// Checks that saving and reading preserves every status, filled or missing timing, and history.
	/// Missing bytes must cause an error rather than lose payment history.
	#[test]
	fn inbound_recurrence_serialization_preserves_state_and_history() {
		for status in [
			RecurrenceStatus::Active,
			RecurrenceStatus::Missed,
			RecurrenceStatus::Cancelled,
			RecurrenceStatus::Completed,
		] {
			for claim_status in [
				InboundRecurrenceClaimStatus::Idle,
				InboundRecurrenceClaimStatus::Pending(PaymentId([11; 32])),
				InboundRecurrenceClaimStatus::Failed(PaymentId([13; 32])),
			] {
				let mut expected = details(1, 1);
				expected.status = status;
				expected.claim_status = claim_status;
				let encoded = expected.encode();
				assert_eq!(InboundRecurrenceDetails::read(&mut &encoded[..]).unwrap(), expected);
				// Reject incomplete data instead of returning a partial record.
				assert!(InboundRecurrenceDetails::read(&mut &encoded[..encoded.len() - 1]).is_err());
			}
		}

		// Missing timing and empty history must stay empty rather than gain invented values.
		let mut expected = details(1, 1);
		expected.recurrence.recurrence_type = RecurrenceType::Optional;
		expected.recurrence.recurrence_paywindow = None;
		expected.recurrence.recurrence_limit = None;
		expected.basetime = None;
		expected.initial_start = None;
		expected.completed_payments.clear();
		assert_eq!(InboundRecurrenceDetails::read(&mut &expected.encode()[..]).unwrap(), expected);
	}

	/// Checks that lookup and listing return all saved recurrences after rebuilding the node.
	/// Editing a returned copy must not change the stored records.
	#[test]
	fn inbound_recurrence_apis_reload_relationships_and_return_copies() {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let node = build_node(Arc::clone(&store)).unwrap();
		let mut expected = vec![details(1, 1), details(1, 2), details(2, 1), details(3, 1)];
		expected[1].status = RecurrenceStatus::Cancelled;
		expected[1].claim_status = InboundRecurrenceClaimStatus::Pending(PaymentId([11; 32]));
		expected[2].status = RecurrenceStatus::Missed;
		expected[2].claim_status = InboundRecurrenceClaimStatus::Failed(PaymentId([13; 32]));
		expected[3].status = RecurrenceStatus::Completed;
		assert!(node.list_inbound_recurrences().is_empty());
		assert_eq!(
			node.inbound_recurrence(&expected[0].offer_id, &expected[0].payer_signing_pubkey)
				.unwrap(),
			None
		);

		// Include shared IDs and inactive records so none can be mixed up or left out.
		for recurrence in &expected {
			node.runtime
				.block_on(node.inbound_recurrence_store.insert(recurrence.clone()))
				.unwrap();
		}
		assert!(node.list_payments(None).unwrap().payments.is_empty());
		// Rebuild with the same storage to check that the records were saved.
		drop(node);
		let node = build_node(Arc::clone(&store)).unwrap();
		for recurrence in &expected {
			let mut copy = node
				.inbound_recurrence(&recurrence.offer_id, &recurrence.payer_signing_pubkey)
				.unwrap()
				.unwrap();
			assert_eq!(&copy, recurrence);
			copy.completed_payments.clear();
			copy.status = RecurrenceStatus::Active;
			assert_eq!(
				node.inbound_recurrence(&recurrence.offer_id, &recurrence.payer_signing_pubkey)
					.unwrap()
					.as_ref(),
				Some(recurrence)
			);
		}
		let mut listed = node.list_inbound_recurrences();
		assert_eq!(listed.len(), expected.len());
		for recurrence in &expected {
			assert!(listed.contains(recurrence));
		}
		listed[0].completed_payments.clear();
		assert!(node.list_inbound_recurrences().iter().all(|r| expected.contains(r)));
		// Known IDs must not make an unstored offer-and-payer pair match.
		assert_eq!(
			node.inbound_recurrence(&expected[3].offer_id, &expected[1].payer_signing_pubkey)
				.unwrap(),
			None
		);
	}

	/// Checks that an update survives rebuilding without changing another recurrence.
	/// Fields not changed by the update must keep their saved values.
	#[test]
	fn inbound_recurrence_snapshot_update_survives_rebuild() {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let node = build_node(Arc::clone(&store)).unwrap();
		let mut updated = details(1, 1);
		let other = details(1, 2);
		for recurrence in [&updated, &other] {
			node.runtime
				.block_on(node.inbound_recurrence_store.insert(recurrence.clone()))
				.unwrap();
		}
		updated.status = RecurrenceStatus::Cancelled;
		updated.claim_status = InboundRecurrenceClaimStatus::Pending(PaymentId([11; 32]));
		updated.completed_payments.push(PaymentId([17; 32]));
		node.runtime.block_on(node.inbound_recurrence_store.update(updated.clone())).unwrap();
		drop(node);
		let node = build_node(store).unwrap();
		let listed = node.list_inbound_recurrences();
		assert_eq!(listed.len(), 2);
		assert!(listed.contains(&updated));
		assert!(listed.contains(&other));
	}

	/// Checks that a corrupt recurrence prevents building the node.
	/// The node must report the problem instead of silently ignoring saved state.
	#[test]
	fn inbound_recurrence_corrupt_record_fails_build() {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let node = build_node(Arc::clone(&store)).unwrap();
		let key = StorableObject::id(&details(1, 1)).encode_to_hex_str();
		node.runtime
			.block_on(KVStore::write(
				&*store,
				INBOUND_RECURRENCE_PRIMARY_NAMESPACE,
				INBOUND_RECURRENCE_SECONDARY_NAMESPACE,
				&key,
				vec![0xff],
			))
			.unwrap();
		drop(node);
		assert!(matches!(build_node(store), Err(BuildError::ReadFailed)));
	}
}
