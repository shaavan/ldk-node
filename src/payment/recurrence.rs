// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. You may not use this file except in
// accordance with one or both of these licenses.

use lightning::ln::channelmanager::PaymentId;
use lightning::ln::msgs::DecodeError;
use lightning::ln::outbound_payment::Retry;
pub(crate) use lightning::offers::invoice_request::RecurrenceId;
use lightning::offers::offer::OfferId;
use lightning::routing::router::RouteParametersConfig;
use lightning::util::ser::{Readable, Writeable, Writer};
use lightning::{_init_and_read_len_prefixed_tlv_fields, write_tlv_fields};
use lightning::{impl_ser_tlv_based, impl_ser_tlv_based_enum};
use lightning_types::string::UntrustedString;

use crate::data_store::StorableObjectId;
use crate::hex_utils;

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
			amount_msat,
			maximum_amount_msat,
			quantity,
			payer_note,
			routing_override,
			retry_policy: retry_policy.0.ok_or(DecodeError::InvalidValue)?,
			retry_state: retry_state.0.ok_or(DecodeError::InvalidValue)?,
			pay_next_automatically: pay_next_automatically.0.ok_or(DecodeError::InvalidValue)?,
			initial_start: initial_start.0.ok_or(DecodeError::InvalidValue)?,
			paid_count: paid_count.0.ok_or(DecodeError::InvalidValue)?,
			basetime: basetime.0.ok_or(DecodeError::InvalidValue)?,
			opaque_state,
			last_successful_payment_id,
			attempt,
			cancellation: cancellation.0.ok_or(DecodeError::InvalidValue)?,
			transition_id: transition_id.0.ok_or(DecodeError::InvalidValue)?,
			status: status.0.ok_or(DecodeError::InvalidValue)?,
		};
		state.validate()?;
		Ok(state)
	}
}
