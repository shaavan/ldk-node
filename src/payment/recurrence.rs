// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use lightning::ln::channelmanager::PaymentId;
use lightning::ln::msgs::DecodeError;
use lightning::ln::outbound_payment::Retry;
use lightning::offers::offer::OfferId;
use lightning::routing::router::RouteParametersConfig;
use lightning::util::ser::{Readable, Writeable, Writer};
use lightning::{_init_and_read_len_prefixed_tlv_fields, write_tlv_fields};
use lightning::{impl_ser_tlv_based, impl_ser_tlv_based_enum};
use lightning_types::string::UntrustedString;

use crate::data_store::{StorableObject, StorableObjectId, StorableObjectUpdate};
use crate::hex_utils;
use crate::types::RecurrenceStore;

/// A stable identifier for a recurring offer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecurrenceId(
	/// The stable 32-byte identifier.
	pub [u8; 32],
);

impl From<RecurrenceId> for lightning::offers::invoice_request::RecurrenceId {
	fn from(id: RecurrenceId) -> Self {
		Self(id.0)
	}
}

impl Writeable for RecurrenceId {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
		self.0.write(writer)
	}
}

impl Readable for RecurrenceId {
	fn read<R: lightning::io::Read>(
		reader: &mut R,
	) -> Result<Self, lightning::ln::msgs::DecodeError> {
		Ok(Self(<[u8; 32]>::read(reader)?))
	}
}

impl StorableObjectId for RecurrenceId {
	fn encode_to_hex_str(&self) -> String {
		hex_utils::to_string(&self.0)
	}

	fn decode_from_hex_str(s: &str) -> Option<Self> {
		hex_utils::to_vec(s)?.try_into().ok().map(Self)
	}
}

/// The lifecycle status of a recurring offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecurrenceStatus {
	/// Recurrence can accept its next payment attempt.
	Active,
	/// Cancellation was requested and is being propagated.
	CancellationPending,
	/// Recurrence will not accept further payments.
	Cancelled,
	/// Recurrence reached its configured payment limit.
	Completed,
	/// Current payment window closed before a payment succeeded.
	Missed,
	/// Durable state needs operator or application attention before continuing.
	RequiresAttention,
}

impl_ser_tlv_based_enum!(RecurrenceStatus,
	(0, Active) => {},
	(2, CancellationPending) => {},
	(4, Cancelled) => {},
	(6, Completed) => {},
	(8, Missed) => {},
	(10, RequiresAttention) => {},
);

/// The state of a recurring payment's retry schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecurrenceRetryState {
	/// Number of failed attempts in the current payment window.
	pub attempts: u32,
	/// Unix timestamp at which another attempt may be made, if any.
	pub next_retry_at: Option<u64>,
}

impl_ser_tlv_based!(RecurrenceRetryState, {
	(0, attempts, required),
	(2, next_retry_at, option),
});

/// The lifecycle state of a payment attempt for a recurring offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecurrenceAttempt {
	/// Payment identifier was persisted before submission was attempted.
	Prepared { payment_id: PaymentId, amount_msat: u64 },
	/// Payment submission was handed to LDK and awaits its terminal event.
	Submitted { payment_id: PaymentId, amount_msat: u64 },
}

impl_ser_tlv_based_enum!(RecurrenceAttempt,
	(0, Prepared) => {
		(0, payment_id, required),
		(2, amount_msat, required),
	},
	(2, Submitted) => {
		(0, payment_id, required),
		(2, amount_msat, required),
	},
);

/// The cancellation state of a recurring offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecurrenceCancellationState {
	/// No cancellation request has been made.
	NotRequested,
	/// Local cancellation is recorded while the payee notification is in flight.
	Pending,
	/// Cancellation completed and no further payments are allowed.
	Cancelled,
}

impl_ser_tlv_based_enum!(RecurrenceCancellationState,
	(0, NotRequested) => {},
	(2, Pending) => {},
	(4, Cancelled) => {},
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecurrenceFailure {
	/// Payment or invoice request expired before completion.
	Expired,
	/// Payee rejected the payment or invoice request.
	Rejected,
	/// Routing or retry exhaustion prevented payment completion.
	RouteFailed,
	/// Application or user abandoned the payment.
	Abandoned,
	/// Failure reason did not match a known category.
	Unknown,
}

impl_ser_tlv_based_enum!(RecurrenceFailure,
	(0, Expired) => {},
	(2, Rejected) => {},
	(4, RouteFailed) => {},
	(6, Abandoned) => {},
	(8, Unknown) => {},
);

/// Persisted state for one recurring offer.
#[derive(Clone, Debug)]
pub(crate) struct RecurrenceState {
	/// Stable identifier for the recurring offer.
	pub id: RecurrenceId,
	/// Serialized offer retained so later payments use the original recurrence terms.
	pub original_offer: Vec<u8>,
	/// Amount requested for each payment, when fixed by the offer or caller.
	pub amount_msat: Option<u64>,
	/// Maximum amount accepted for a payment attempt.
	pub maximum_amount_msat: Option<u64>,
	/// Quantity to include in each invoice request, if configured.
	pub quantity: Option<u64>,
	/// Note sent to the payee with invoice requests.
	pub payer_note: Option<UntrustedString>,
	/// Per-recurrence routing policy overriding the node default.
	pub routing_override: Option<RouteParametersConfig>,
	/// LDK retry strategy for one payment attempt.
	pub retry_policy: Retry,
	/// Recurrence-level retry state across payment attempts.
	pub retry_state: RecurrenceRetryState,
	/// Whether the node should submit future periods automatically.
	pub pay_next_automatically: bool,
	/// Optional period from which this recurrence starts.
	pub initial_start: Option<u32>,
	/// Number of successfully completed periods.
	pub paid_count: u64,
	/// Offer-defined recurrence baseline timestamp.
	pub basetime: Option<u64>,
	/// Opaque state returned by the payee for the next invoice request.
	pub opaque_state: Option<Vec<u8>>,
	/// Payment identifier of the most recently successful period.
	pub last_successful_payment_id: Option<PaymentId>,
	/// Payment currently reserved or submitted for this recurrence.
	pub attempt: Option<RecurrenceAttempt>,
	/// Durable cancellation phase associated with [`Self::status`].
	pub cancellation: RecurrenceCancellationState,
	/// Monotonic identifier for externally observable state transitions.
	/// Most recent failure classification for the current payment window.
	pub failure: Option<RecurrenceFailure>,
	pub transition_id: u64,
	/// Current lifecycle status.
	pub status: RecurrenceStatus,
}

pub(crate) type RecurrenceDetails = RecurrenceState;

#[derive(Clone, Debug)]
pub(crate) struct RecurrenceDetailsUpdate {
	pub details: RecurrenceDetails,
}

impl StorableObject for RecurrenceDetails {
	type Id = RecurrenceId;
	type Update = RecurrenceDetailsUpdate;

	fn id(&self) -> Self::Id {
		self.id
	}

	fn update(&mut self, update: Self::Update) -> bool {
		if self.id != update.details.id {
			return false;
		}
		*self = update.details;
		true
	}

	fn to_update(&self) -> Self::Update {
		RecurrenceDetailsUpdate { details: self.clone() }
	}
}

impl StorableObjectUpdate<RecurrenceDetails> for RecurrenceDetailsUpdate {
	fn id(&self) -> RecurrenceId {
		self.details.id
	}
}

/// Applies one successful payment transition exactly once.
pub(crate) fn record_success(
	details: &mut RecurrenceDetails, payment_id: PaymentId, basetime: u64,
	next_state: Option<&[u8]>, period_index: u32, recurrence_limit: Option<u32>,
) {
	if matches!(
		details.status,
		RecurrenceStatus::Cancelled | RecurrenceStatus::Completed | RecurrenceStatus::Missed
	) {
		return;
	}
	if details.last_successful_payment_id == Some(payment_id) && details.attempt.is_none() {
		return;
	}
	details.paid_count = details.paid_count.saturating_add(1);
	details.basetime.get_or_insert(basetime);
	details.opaque_state = next_state.map(|state| state.to_vec());
	details.last_successful_payment_id = Some(payment_id);
	details.attempt = None;
	details.retry_state = RecurrenceRetryState { attempts: 0, next_retry_at: None };
	details.transition_id = details.transition_id.saturating_add(1);
	if details.status == RecurrenceStatus::Active
		&& recurrence_limit.map(|limit| period_index >= limit).unwrap_or(false)
	{
		details.status = RecurrenceStatus::Completed;
	}
}

/// Records a failed attempt without changing an already successful or terminal recurrence.
pub(crate) fn record_failure(
	details: &mut RecurrenceDetails, payment_id: PaymentId, failure: RecurrenceFailure, now: u64,
	closing_time: Option<u64>,
) {
	if details.last_successful_payment_id == Some(payment_id)
		|| matches!(
			details.status,
			RecurrenceStatus::Cancelled | RecurrenceStatus::Completed | RecurrenceStatus::Missed
		) {
		return;
	}
	details.attempt = None;
	details.failure = Some(failure);
	details.transition_id = details.transition_id.saturating_add(1);
	if closing_time.map(|closing| now >= closing).unwrap_or(false) {
		details.status = RecurrenceStatus::Missed;
		details.retry_state.next_retry_at = None;
	}
}

/// Coordinates durable recurrence records and the in-memory payment index.
pub(crate) struct RecurrenceManager {
	store: Arc<RecurrenceStore>,
	payment_index: Mutex<HashMap<PaymentId, RecurrenceId>>,
}

impl RecurrenceManager {
	/// Creates a manager backed by the durable recurrence store.
	pub(crate) fn new(store: Arc<RecurrenceStore>) -> Self {
		Self { store, payment_index: Mutex::new(HashMap::new()) }
	}

	/// Returns the store used for durable recurrence records.
	pub(crate) fn store(&self) -> &Arc<RecurrenceStore> {
		&self.store
	}

	/// Rebuilds payment-to-recurrence lookups after loading records from storage.
	pub(crate) async fn rebuild_index(&self) {
		let details = self.list().await;
		let mut index = self.payment_index.lock().expect("lock");
		index.clear();
		for details in details {
			if let Some(payment_id) = details.last_successful_payment_id {
				index.insert(payment_id, details.id);
			}
			if let Some(
				RecurrenceAttempt::Prepared { payment_id, .. }
				| RecurrenceAttempt::Submitted { payment_id, .. },
			) = details.attempt
			{
				index.insert(payment_id, details.id);
			}
		}
	}

	/// Persists a new recurrence and indexes its known payment identifiers.
	pub(crate) async fn insert(&self, details: RecurrenceDetails) -> Result<(), crate::Error> {
		details.validate().map_err(|_| crate::Error::PersistenceFailed)?;
		let inserted = self
			.store
			.mutate(&details.id, |current| current.is_none().then(|| details.clone()))
			.await?;
		if inserted.is_none() {
			return Err(crate::Error::PersistenceFailed);
		}
		self.index(&details);
		Ok(())
	}

	/// Loads one recurrence by its stable identifier.
	pub(crate) async fn get(
		&self, id: &RecurrenceId,
	) -> Result<Option<RecurrenceDetails>, crate::Error> {
		self.store.get(id).await
	}

	/// Persists an updated recurrence and refreshes its payment lookup entries.
	pub(crate) async fn update(
		&self, details: RecurrenceDetails,
	) -> Result<crate::data_store::DataStoreUpdateResult, crate::Error> {
		details.validate().map_err(|_| crate::Error::PersistenceFailed)?;
		let result = self.store.update(details.to_update()).await?;
		self.index(&details);
		Ok(result)
	}

	/// Atomically reserves the single durable attempt slot for a recurrence.
	///
	/// The store mutation lock covers the read, eligibility check, transition increment, and
	/// persistence. This prevents manual payment, retry, recovery, and scheduling paths from
	/// observing the same empty slot and creating competing attempts.
	pub(crate) async fn claim_attempt(
		&self, id: &RecurrenceId, attempt: RecurrenceAttempt,
	) -> Result<Option<RecurrenceDetails>, crate::Error> {
		let claimed = self
			.store
			.mutate(id, |current| {
				let current = current?;
				if current.status != RecurrenceStatus::Active || current.attempt.is_some() {
					return None;
				}

				let mut updated = current.clone();
				updated.transition_id = updated.transition_id.checked_add(1)?;
				updated.attempt = Some(attempt.clone());
				updated.failure = None;
				updated.validate().ok()?;
				Some(updated)
			})
			.await?;

		if let Some(details) = &claimed {
			self.index(details);
		}
		Ok(claimed)
	}

	/// Removes a recurrence and all cached payment-to-recurrence mappings for it.
	pub(crate) async fn remove(&self, id: &RecurrenceId) -> Result<(), crate::Error> {
		self.store.remove(id).await?;
		self.payment_index.lock().expect("lock").retain(|_, recurrence_id| recurrence_id != id);
		Ok(())
	}

	/// Returns every persisted recurrence record.
	pub(crate) async fn list(&self) -> Vec<RecurrenceDetails> {
		self.store.list_filter(|_| true).await
	}

	/// Finds a recurrence by its latest successful or in-flight payment identifier.
	///
	/// Falls back to scanning durable records when the in-memory index is cold or stale, then
	/// repopulates the index with the record it finds.
	pub(crate) async fn by_payment_id(
		&self, payment_id: &PaymentId,
	) -> Result<Option<RecurrenceDetails>, crate::Error> {
		let cached_id = self.payment_index.lock().expect("lock").get(payment_id).copied();
		if let Some(id) = cached_id {
			if let Some(details) = self.store.get(&id).await? {
				return Ok(Some(details));
			}
		}

		let details = self
			.store
			.list_filter(|details| {
				details.last_successful_payment_id.as_ref() == Some(payment_id)
					|| matches!(&details.attempt, Some(RecurrenceAttempt::Prepared { payment_id: id, .. } | RecurrenceAttempt::Submitted { payment_id: id, .. }) if id == payment_id)
			})
			.await
			.into_iter()
			.next();
		if let Some(details) = &details {
			self.index(details);
		}
		Ok(details)
	}

	/// Adds the successful and in-flight payment identifiers for one recurrence to the cache.
	fn index(&self, details: &RecurrenceDetails) {
		let mut index = self.payment_index.lock().expect("lock");
		if let Some(payment_id) = details.last_successful_payment_id {
			index.insert(payment_id, details.id);
		}
		if let Some(
			RecurrenceAttempt::Prepared { payment_id, .. }
			| RecurrenceAttempt::Submitted { payment_id, .. },
		) = details.attempt
		{
			index.insert(payment_id, details.id);
		}
	}
}

impl Default for RecurrenceState {
	fn default() -> Self {
		Self {
			id: RecurrenceId([0; 32]),
			original_offer: Vec::new(),
			amount_msat: None,
			maximum_amount_msat: None,
			quantity: None,
			payer_note: None,
			routing_override: None,
			retry_policy: Retry::Attempts(0),
			retry_state: RecurrenceRetryState { attempts: 0, next_retry_at: None },
			pay_next_automatically: false,
			initial_start: None,
			paid_count: 0,
			basetime: None,
			opaque_state: None,
			last_successful_payment_id: None,
			attempt: None,
			cancellation: RecurrenceCancellationState::NotRequested,
			failure: None,
			transition_id: 0,
			status: RecurrenceStatus::Active,
		}
	}
}

impl RecurrenceState {
	/// Validates persisted recurrence invariants before state enters memory or storage.
	pub(crate) fn validate(&self) -> Result<(), DecodeError> {
		if self.original_offer.is_empty()
			|| self.amount_msat == Some(0)
			|| self.maximum_amount_msat == Some(0)
			|| self.quantity == Some(0)
			|| self
				.maximum_amount_msat
				.zip(self.amount_msat)
				.is_some_and(|(maximum, amount)| amount > maximum)
			|| self.paid_count > self.transition_id
		{
			return Err(DecodeError::InvalidValue);
		}

		if self.retry_state.attempts == 0 && self.retry_state.next_retry_at.is_some() {
			return Err(DecodeError::InvalidValue);
		}

		if let Some(attempt) = &self.attempt {
			let amount_msat = match attempt {
				RecurrenceAttempt::Prepared { amount_msat, .. }
				| RecurrenceAttempt::Submitted { amount_msat, .. } => *amount_msat,
			};
			if amount_msat == 0
				|| self.maximum_amount_msat.is_some_and(|maximum| amount_msat > maximum)
				|| !matches!(
					self.status,
					RecurrenceStatus::Active | RecurrenceStatus::RequiresAttention
				) {
				return Err(DecodeError::InvalidValue);
			}
		}

		match (self.status, self.cancellation) {
			(RecurrenceStatus::Active, RecurrenceCancellationState::NotRequested)
			| (RecurrenceStatus::CancellationPending, RecurrenceCancellationState::Pending)
			| (RecurrenceStatus::Cancelled, RecurrenceCancellationState::Cancelled) => {},
			(
				RecurrenceStatus::Completed | RecurrenceStatus::Missed,
				RecurrenceCancellationState::NotRequested,
			) => {
				if self.attempt.is_some() || self.retry_state.next_retry_at.is_some() {
					return Err(DecodeError::InvalidValue);
				}
			},
			(RecurrenceStatus::RequiresAttention, _) => {},
			_ => return Err(DecodeError::InvalidValue),
		}

		if matches!(
			self.status,
			RecurrenceStatus::Cancelled | RecurrenceStatus::Completed | RecurrenceStatus::Missed
		) && (self.attempt.is_some() || self.retry_state.next_retry_at.is_some())
		{
			return Err(DecodeError::InvalidValue);
		}

		Ok(())
	}
}

impl Writeable for RecurrenceState {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
		write_tlv_fields!(writer, {
			(0, self.id, required),
			(2, self.original_offer, required),
			(4, self.amount_msat, option),
			(6, self.maximum_amount_msat, option),
			(8, self.quantity, option),
			(10, self.payer_note, option),
			(12, self.routing_override, option),
			(14, self.retry_policy, required),
			(16, self.retry_state, required),
			(18, self.pay_next_automatically, required),
			(20, self.initial_start, required),
			(22, self.paid_count, required),
			(24, self.basetime, required),
			(26, self.opaque_state, option),
			(28, self.last_successful_payment_id, option),
			(30, self.attempt, option),
			(32, self.cancellation, required),
			(33, self.failure, option),
			(34, self.transition_id, required),
			(36, self.status, required)
		});
		Ok(())
	}
}

impl Readable for RecurrenceState {
	fn read<R: lightning::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, id, required),
			(2, original_offer, required),
			(4, amount_msat, option),
			(6, maximum_amount_msat, option),
			(8, quantity, option),
			(10, payer_note, option),
			(12, routing_override, option),
			(14, retry_policy, required),
			(16, retry_state, required),
			(18, pay_next_automatically, required),
			(20, initial_start, required),
			(22, paid_count, required),
			(24, basetime, required),
			(26, opaque_state, option),
			(28, last_successful_payment_id, option),
			(30, attempt, option),
			(32, cancellation, required),
			(33, failure, option),
			(34, transition_id, required),
			(36, status, required)
		});

		let state = Self {
			id: id.0.ok_or(DecodeError::InvalidValue)?,
			original_offer: original_offer.0.ok_or(DecodeError::InvalidValue)?,
			amount_msat: amount_msat.0,
			maximum_amount_msat: maximum_amount_msat.0,
			quantity: quantity.0,
			payer_note: payer_note.0,
			routing_override: routing_override.0,
			retry_policy: retry_policy.0.ok_or(DecodeError::InvalidValue)?,
			retry_state: retry_state.0.ok_or(DecodeError::InvalidValue)?,
			pay_next_automatically: pay_next_automatically.0.ok_or(DecodeError::InvalidValue)?,
			initial_start: initial_start.0.ok_or(DecodeError::InvalidValue)?,
			paid_count: paid_count.0.ok_or(DecodeError::InvalidValue)?,
			basetime: basetime.0.ok_or(DecodeError::InvalidValue)?,
			opaque_state: opaque_state.0,
			last_successful_payment_id: last_successful_payment_id.0,
			attempt: attempt.0,
			cancellation: cancellation.0.ok_or(DecodeError::InvalidValue)?,
			failure: failure.0,
			transition_id: transition_id.0.ok_or(DecodeError::InvalidValue)?,
			status: status.0.ok_or(DecodeError::InvalidValue)?,
		};
		state.validate()?;
		Ok(state)
	}
}

impl From<OfferId> for RecurrenceId {
	fn from(offer_id: OfferId) -> Self {
		Self(offer_id.0)
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use lightning::offers::offer::{
		Recurrence, RecurrenceLimit, RecurrencePaywindow, RecurrencePeriod, RecurrenceType,
	};
	use lightning::routing::router::RouteParametersConfig;
	use lightning::util::ser::{Readable, Writeable};

	use super::*;
	use crate::data_store::DataStore;
	use crate::io::test_utils::InMemoryStore;
	use crate::logger::Logger;
	use crate::types::{DynStore, DynStoreWrapper};

	fn state(opaque_state: Option<Vec<u8>>) -> RecurrenceState {
		RecurrenceState {
			id: RecurrenceId([1; 32]),
			original_offer: vec![2, 3, 4],
			amount_msat: Some(5_000),
			maximum_amount_msat: Some(7_000),
			quantity: Some(2),
			payer_note: Some(UntrustedString("payer note".to_string())),
			routing_override: Some(RouteParametersConfig {
				max_total_routing_fee_msat: Some(11),
				max_total_cltv_expiry_delta: 12,
				max_path_count: 13,
				max_channel_saturation_power_of_half: 14,
			}),
			retry_policy: Retry::Attempts(15),
			retry_state: RecurrenceRetryState { attempts: 16, next_retry_at: Some(17) },
			pay_next_automatically: true,
			initial_start: Some(18),
			paid_count: 19,
			basetime: Some(20),
			opaque_state,
			last_successful_payment_id: Some(PaymentId([21; 32])),
			attempt: Some(RecurrenceAttempt::Submitted {
				payment_id: PaymentId([22; 32]),
				amount_msat: 23,
			}),
			cancellation: RecurrenceCancellationState::Pending,
			failure: Some(RecurrenceFailure::RouteFailed),
			transition_id: 24,
			status: RecurrenceStatus::RequiresAttention,
		}
	}

	fn manager(details: Vec<RecurrenceDetails>) -> (RecurrenceManager, Arc<RecurrenceStore>) {
		let store: Arc<DynStore> = Arc::new(DynStoreWrapper(InMemoryStore::new()));
		let logger = Arc::new(Logger::new_log_facade());
		let recurrence_store = Arc::new(DataStore::new(
			details,
			crate::data_store::KeepAllEntries,
			crate::io::RECURRENCE_INFO_PERSISTENCE_PRIMARY_NAMESPACE.to_string(),
			crate::io::RECURRENCE_INFO_PERSISTENCE_SECONDARY_NAMESPACE.to_string(),
			Arc::clone(&store),
			Arc::clone(&logger),
		));
		(RecurrenceManager::new(Arc::clone(&recurrence_store)), recurrence_store)
	}

	fn assert_state_fields(actual: &RecurrenceState, expected: &RecurrenceState) {
		assert_eq!(actual.id, expected.id);
		assert_eq!(actual.original_offer, expected.original_offer);
		assert_eq!(actual.amount_msat, expected.amount_msat);
		assert_eq!(actual.maximum_amount_msat, expected.maximum_amount_msat);
		assert_eq!(actual.quantity, expected.quantity);
		assert_eq!(actual.payer_note, expected.payer_note);
		assert_eq!(
			actual.routing_override.as_ref().map(|v| v.max_total_routing_fee_msat),
			expected.routing_override.as_ref().map(|v| v.max_total_routing_fee_msat)
		);
		assert_eq!(
			actual.routing_override.as_ref().map(|v| v.max_total_cltv_expiry_delta),
			expected.routing_override.as_ref().map(|v| v.max_total_cltv_expiry_delta)
		);
		assert_eq!(
			actual.routing_override.as_ref().map(|v| v.max_path_count),
			expected.routing_override.as_ref().map(|v| v.max_path_count)
		);
		assert_eq!(
			actual.routing_override.as_ref().map(|v| v.max_channel_saturation_power_of_half),
			expected.routing_override.as_ref().map(|v| v.max_channel_saturation_power_of_half)
		);
		assert_eq!(actual.retry_policy, expected.retry_policy);
		assert_eq!(actual.retry_state, expected.retry_state);
		assert_eq!(actual.pay_next_automatically, expected.pay_next_automatically);
		assert_eq!(actual.initial_start, expected.initial_start);
		assert_eq!(actual.paid_count, expected.paid_count);
		assert_eq!(actual.basetime, expected.basetime);
		assert_eq!(actual.opaque_state, expected.opaque_state);
		assert_eq!(actual.last_successful_payment_id, expected.last_successful_payment_id);
		assert_eq!(actual.attempt, expected.attempt);
		assert_eq!(actual.cancellation, expected.cancellation);
		assert_eq!(actual.failure, expected.failure);
		assert_eq!(actual.transition_id, expected.transition_id);
		assert_eq!(actual.status, expected.status);
	}

	#[test]
	fn recurrence_state_round_trips_all_fields() {
		let expected = state(Some(vec![25, 26, 27]));
		let actual = RecurrenceState::read(&mut &expected.encode()[..]).unwrap();
		assert_state_fields(&actual, &expected);
	}

	#[test]
	fn recurrence_state_round_trips_without_opaque_state() {
		let expected = state(None);
		let actual = RecurrenceState::read(&mut &expected.encode()[..]).unwrap();
		assert_state_fields(&actual, &expected);
	}

	#[test]
	fn defaults_disable_automatic_recurrence() {
		let defaults = RecurrenceState::default();
		assert!(!defaults.pay_next_automatically);
		assert_eq!(defaults.status, RecurrenceStatus::Active);
		assert_eq!(defaults.cancellation, RecurrenceCancellationState::NotRequested);
		assert_eq!(defaults.failure, None);
	}

	#[test]
	fn recurrence_ids_are_stable_storage_keys() {
		let id = RecurrenceId([42; 32]);
		let encoded = id.encode_to_hex_str();
		assert_eq!(RecurrenceId::decode_from_hex_str(&encoded), Some(id));
		assert_eq!(RecurrenceId::decode_from_hex_str("00"), None);
		assert_ne!(id, RecurrenceId([43; 32]));
	}

	#[test]
	fn recurrence_status_discriminants_are_stable() {
		let statuses = [
			RecurrenceStatus::Active,
			RecurrenceStatus::CancellationPending,
			RecurrenceStatus::Cancelled,
			RecurrenceStatus::Completed,
			RecurrenceStatus::Missed,
			RecurrenceStatus::RequiresAttention,
		];
		let encoded: Vec<Vec<u8>> = statuses.iter().map(|status| status.encode()).collect();
		assert_eq!(
			encoded,
			vec![vec![0, 0], vec![2, 0], vec![4, 0], vec![6, 0], vec![8, 0], vec![10, 0]]
		);
	}

	#[test]
	fn unknown_odd_tlvs_are_ignored() {
		let mut encoded = RecurrenceStatus::Active.encode();
		encoded.extend_from_slice(&[1, 0]);
		assert_eq!(RecurrenceStatus::read(&mut &encoded[..]).unwrap(), RecurrenceStatus::Active);
	}

	#[test]
	fn recurrence_substates_round_trip_all_variants() {
		assert_eq!(Retry::Attempts(3), Retry::read(&mut &Retry::Attempts(3).encode()[..]).unwrap());
		assert_eq!(
			Retry::Timeout(std::time::Duration::from_secs(4)),
			Retry::read(&mut &Retry::Timeout(std::time::Duration::from_secs(4)).encode()[..])
				.unwrap()
		);

		for attempt in [
			RecurrenceAttempt::Prepared { payment_id: PaymentId([1; 32]), amount_msat: 2 },
			RecurrenceAttempt::Submitted { payment_id: PaymentId([3; 32]), amount_msat: 4 },
		] {
			assert_eq!(attempt, RecurrenceAttempt::read(&mut &attempt.encode()[..]).unwrap());
		}
		for cancellation in [
			RecurrenceCancellationState::NotRequested,
			RecurrenceCancellationState::Pending,
			RecurrenceCancellationState::Cancelled,
		] {
			assert_eq!(
				cancellation,
				RecurrenceCancellationState::read(&mut &cancellation.encode()[..]).unwrap()
			);
		}
	}

	#[test]
	fn corrupted_recurrence_records_are_rejected() {
		let encoded = state(None).encode();
		for length in 0..encoded.len() {
			assert!(RecurrenceState::read(&mut &encoded[..length]).is_err());
		}
	}

	#[tokio::test]
	async fn recurrence_manager_supports_crud_and_cache_miss_fallback() {
		let mut expected = state(None);
		expected.attempt =
			Some(RecurrenceAttempt::Prepared { payment_id: PaymentId([30; 32]), amount_msat: 31 });
		let (manager, store) = manager(Vec::new());

		manager.insert(expected.clone()).await.unwrap();
		assert_eq!(manager.get(&expected.id).await.unwrap().unwrap().id, expected.id);
		assert_eq!(manager.list().await.len(), 1);
		assert_eq!(
			manager.by_payment_id(&PaymentId([30; 32])).await.unwrap().map(|v| v.id),
			Some(expected.id)
		);

		expected.paid_count += 1;
		manager.update(expected.clone()).await.unwrap();
		assert_eq!(manager.get(&expected.id).await.unwrap().unwrap().paid_count, 20);

		manager.payment_index.lock().expect("lock").clear();
		assert_eq!(
			manager.by_payment_id(&PaymentId([30; 32])).await.unwrap().map(|v| v.id),
			Some(expected.id)
		);

		store.remove(&expected.id).await.unwrap();
		assert!(manager.get(&expected.id).await.unwrap().is_none());
	}

	#[tokio::test]
	async fn recurrence_manager_reconstructs_index_after_restart() {
		let expected = state(None);
		let (first, store) = manager(Vec::new());
		first.insert(expected.clone()).await.unwrap();

		let restarted = RecurrenceManager::new(store);
		restarted.rebuild_index().await;
		assert_eq!(restarted.get(&expected.id).await.unwrap().map(|v| v.id), Some(expected.id));
	}

	#[tokio::test]
	async fn recurrence_manager_claims_only_one_concurrent_attempt() {
		let mut expected = state(None);
		expected.status = RecurrenceStatus::Active;
		expected.cancellation = RecurrenceCancellationState::NotRequested;
		expected.attempt = None;
		expected.retry_state = RecurrenceRetryState { attempts: 0, next_retry_at: None };
		let (manager, _) = manager(vec![expected.clone()]);
		let first_attempt =
			RecurrenceAttempt::Prepared { payment_id: PaymentId([30; 32]), amount_msat: 31 };
		let second_attempt =
			RecurrenceAttempt::Prepared { payment_id: PaymentId([32; 32]), amount_msat: 33 };

		let (first, second) = tokio::join!(
			manager.claim_attempt(&expected.id, first_attempt),
			manager.claim_attempt(&expected.id, second_attempt)
		);
		assert_eq!(
			first.as_ref().unwrap().is_some() as u8 + second.as_ref().unwrap().is_some() as u8,
			1
		);
		let claimed = manager.get(&expected.id).await.unwrap().unwrap();
		assert!(matches!(
			claimed.attempt,
			Some(RecurrenceAttempt::Prepared { payment_id, .. })
				if payment_id == PaymentId([30; 32]) || payment_id == PaymentId([32; 32])
		));
		assert_eq!(claimed.transition_id, expected.transition_id + 1);
	}

	#[tokio::test]
	async fn recurrence_manager_does_not_claim_cancelled_recurrence() {
		let mut expected = state(None);
		expected.status = RecurrenceStatus::Cancelled;
		expected.cancellation = RecurrenceCancellationState::Cancelled;
		let (manager, _) = manager(vec![expected.clone()]);
		let attempt =
			RecurrenceAttempt::Prepared { payment_id: PaymentId([34; 32]), amount_msat: 35 };
		assert!(manager.claim_attempt(&expected.id, attempt).await.unwrap().is_none());
	}

	#[tokio::test]
	async fn recurrence_manager_rejects_concurrent_duplicate_registration() {
		let expected = state(None);
		let (manager, _) = manager(Vec::new());
		let (first, second) =
			tokio::join!(manager.insert(expected.clone()), manager.insert(expected.clone()));
		assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);
		assert_eq!(manager.list().await.len(), 1);
	}

	#[test]
	fn successful_payment_advances_and_replay_is_idempotent() {
		let mut details = state(Some(vec![1, 2]));
		details.basetime = None;
		details.paid_count = 0;
		details.last_successful_payment_id = None;
		details.status = RecurrenceStatus::Active;
		record_success(&mut details, PaymentId([50; 32]), 100, Some(&[3, 4]), 0, Some(2));
		assert_eq!(details.paid_count, 1);
		assert_eq!(details.basetime, Some(100));
		assert_eq!(details.opaque_state, Some(vec![3, 4]));
		assert!(details.attempt.is_none());
		let transition_id = details.transition_id;

		record_success(&mut details, PaymentId([50; 32]), 200, None, 0, Some(2));
		assert_eq!(details.paid_count, 1);
		assert_eq!(details.basetime, Some(100));
		assert_eq!(details.transition_id, transition_id);
	}

	#[test]
	fn successful_payment_marks_completion_at_schedule_limit() {
		let mut details = state(None);
		details.paid_count = 1;
		details.status = RecurrenceStatus::Active;
		record_success(&mut details, PaymentId([51; 32]), 100, None, 1, Some(1));
		assert_eq!(details.paid_count, 2);
		assert_eq!(details.status, RecurrenceStatus::Completed);
	}

	#[test]
	fn terminal_success_replay_does_not_change_recurrence() {
		let mut details = state(None);
		details.status = RecurrenceStatus::Completed;
		details.paid_count = 2;
		details.transition_id = 3;
		let before = details.clone();
		record_success(&mut details, PaymentId([52; 32]), 100, Some(&[5]), 2, Some(2));
		assert_eq!(details.paid_count, before.paid_count);
		assert_eq!(details.transition_id, before.transition_id);
		assert_eq!(details.basetime, before.basetime);
	}

	#[test]
	fn failed_payment_preserves_schedule_and_tracks_open_window() {
		let mut details = state(None);
		details.status = RecurrenceStatus::Active;
		details.paid_count = 3;
		details.basetime = Some(100);
		let paid_count = details.paid_count;
		let basetime = details.basetime;
		record_failure(
			&mut details,
			PaymentId([60; 32]),
			RecurrenceFailure::RouteFailed,
			199,
			Some(200),
		);
		assert_eq!(details.paid_count, paid_count);
		assert_eq!(details.basetime, basetime);
		assert_eq!(details.failure, Some(RecurrenceFailure::RouteFailed));
		assert_eq!(details.status, RecurrenceStatus::Active);
		assert!(details.attempt.is_none());

		record_failure(
			&mut details,
			PaymentId([61; 32]),
			RecurrenceFailure::Expired,
			200,
			Some(200),
		);
		assert_eq!(details.status, RecurrenceStatus::Missed);
		assert_eq!(details.retry_state.next_retry_at, None);
	}

	#[test]
	fn failure_after_success_does_not_change_recurrence() {
		let mut details = state(None);
		details.status = RecurrenceStatus::Active;
		record_success(&mut details, PaymentId([62; 32]), 100, None, 0, None);
		let snapshot = details.clone();
		record_failure(
			&mut details,
			PaymentId([62; 32]),
			RecurrenceFailure::Rejected,
			200,
			Some(200),
		);
		assert_eq!(details.paid_count, snapshot.paid_count);
		assert_eq!(details.failure, snapshot.failure);
		assert_eq!(details.status, snapshot.status);
	}

	#[test]
	fn failure_classifications_round_trip_and_closing_is_exclusive() {
		for failure in [
			RecurrenceFailure::Expired,
			RecurrenceFailure::Rejected,
			RecurrenceFailure::RouteFailed,
			RecurrenceFailure::Abandoned,
			RecurrenceFailure::Unknown,
		] {
			assert_eq!(failure, RecurrenceFailure::read(&mut &failure.encode()[..]).unwrap());
		}
		let mut details = state(None);
		details.status = RecurrenceStatus::Active;
		record_failure(
			&mut details,
			PaymentId([63; 32]),
			RecurrenceFailure::Expired,
			199,
			Some(200),
		);
		assert_eq!(details.status, RecurrenceStatus::Active);
		record_failure(
			&mut details,
			PaymentId([64; 32]),
			RecurrenceFailure::Expired,
			200,
			Some(200),
		);
		assert_eq!(details.status, RecurrenceStatus::Missed);
	}

	#[test]
	fn later_periods_are_sequential_and_window_boundaries_are_exact() {
		let recurrence = Recurrence {
			recurrence_type: RecurrenceType::Compulsory(None),
			recurrence_period: RecurrencePeriod::Seconds(100),
			recurrence_paywindow: Some(RecurrencePaywindow {
				seconds_before: 0,
				seconds_after: 100,
			}),
			recurrence_limit: Some(RecurrenceLimit(2)),
		};
		assert_eq!(recurrence.period_index(1, None).unwrap(), 1);
		assert_eq!(recurrence.payment_window(1_000, 1).unwrap(), (1_100, 1_200));
		assert!(recurrence.period_index(u32::MAX, Some(1)).is_err());
		assert!(1_100 < 1_200);
		assert!(1_200 >= 1_200);
		assert!(recurrence.period_index(3, None).unwrap() > recurrence.recurrence_limit.unwrap().0);
	}
}
