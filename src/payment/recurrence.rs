// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. You may not use this file except in
// accordance with one or both of these licenses.

use lightning::ln::channelmanager::PaymentId;
use lightning::ln::msgs::DecodeError;
use lightning::ln::outbound_payment::Retry;
use lightning::offers::offer::OfferId;
use lightning::routing::router::RouteParametersConfig;
use lightning::util::ser::{Readable, Writeable, Writer};
use lightning::{_init_and_read_len_prefixed_tlv_fields, write_tlv_fields};
use lightning::{impl_ser_tlv_based, impl_ser_tlv_based_enum};
use lightning_types::string::UntrustedString;

use crate::data_store::StorableObjectId;
use crate::hex_utils;

/// A stable identifier for a recurring offer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RecurrenceId(pub [u8; 32]);

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
	pub initial_start: u64,
	/// Number of successfully completed periods.
	pub paid_count: u64,
	/// Offer-defined recurrence baseline timestamp.
	pub basetime: u64,
	/// Opaque state returned by the payee for the next invoice request.
	pub opaque_state: Option<Vec<u8>>,
	/// Payment identifier of the most recently successful period.
	pub last_successful_payment_id: Option<PaymentId>,
	/// Payment currently reserved or submitted for this recurrence.
	pub attempt: Option<RecurrenceAttempt>,
	/// Durable cancellation phase associated with [`Self::status`].
	pub cancellation: RecurrenceCancellationState,
	/// Monotonic identifier for externally observable state transitions.
	pub transition_id: u64,
	/// Current lifecycle status.
	pub status: RecurrenceStatus,
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
			initial_start: 0,
			paid_count: 0,
			basetime: 0,
			opaque_state: None,
			last_successful_payment_id: None,
			attempt: None,
			cancellation: RecurrenceCancellationState::NotRequested,
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
			|| self.basetime < self.initial_start
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
	use lightning::routing::router::RouteParametersConfig;
	use lightning::util::ser::{Readable, Writeable};

	use super::*;

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
			initial_start: 18,
			paid_count: 19,
			basetime: 20,
			opaque_state,
			last_successful_payment_id: Some(PaymentId([21; 32])),
			attempt: Some(RecurrenceAttempt::Submitted {
				payment_id: PaymentId([22; 32]),
				amount_msat: 23,
			}),
			cancellation: RecurrenceCancellationState::Pending,
			transition_id: 24,
			status: RecurrenceStatus::RequiresAttention,
		}
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
}
