// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use lightning::ln::channelmanager::PaymentId;
use lightning::ln::outbound_payment::Retry;
pub(crate) use lightning::offers::invoice_request::RecurrenceId;
use lightning::routing::router::RouteParametersConfig;
use lightning::{impl_ser_tlv_based, impl_ser_tlv_based_enum};
use lightning_types::string::UntrustedString;

use crate::data_store::{StorableObject, StorableObjectId, StorableObjectUpdate};
use crate::hex_utils;
use crate::types::RecurrenceStore;

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

/// Persisted state for an outbound recurrence, where this node is the payer.
///
/// Stored using [`RecurrenceId`] as the key.
#[derive(Clone, Debug)]
pub(crate) struct RecurrenceDetails {
	/// Recurrence ID
	pub id: RecurrenceId,

	/// Current lifecycle status of the recurrence.
	pub status: RecurrenceStatus,

	/// Serialized original offer defining the recurrence terms.
	///
	/// Retained to ensure that subsequent payments use the same offer.
	pub original_offer: Vec<u8>,

	/// Amount in millisatoshis to use for each payment by default.
	///
	/// May be increased by the user before the next period begins. If the original
	/// offer specifies an amount, this must be at least that amount multiplied by
	/// [`Self::quantity`], when a quantity is set.
	pub amount_msat: Option<u64>,

	/// Quantity to include in each invoice request, if any.
	///
	/// May be changed by the user before the next period begins.
	pub quantity: Option<u64>,

	/// Note to include in each invoice request.
	pub payer_note: Option<UntrustedString>,

	/// UNIX timestamp anchoring period zero of the recurrence.
	pub basetime: u64,

	/// First recurrence period to pay, if specified.
	pub initial_start: Option<u32>,

	/// Number of recurrence periods successfully paid.
	pub paid_count: u64,

	/// Opaque state provided by the payee for the next invoice request.
	pub opaque_state: Option<Vec<u8>>,

	/// Retry strategy to use when attempting each payment.
	pub retry_policy: Retry,

	/// Per-recurrence routing configuration overriding the node-wide default.
	pub routing_override: Option<RouteParametersConfig>,

	/// Payment ID of the most recently completed payment.
	pub last_successful_payment_id: Option<PaymentId>,

	/// Whether future recurrence periods should be paid automatically.
	pub pay_next_automatically: bool,
}

impl Default for RecurrenceDetails {
	fn default() -> Self {
		Self {
			id: RecurrenceId([0; 32]),
			status: RecurrenceStatus::Active,
			original_offer: Vec::new(),
			amount_msat: None,
			quantity: None,
			payer_note: None,
			basetime: 0,
			initial_start: None,
			paid_count: 0,
			opaque_state: None,
			retry_policy: Retry::Attempts(0),
			routing_override: None,
			last_successful_payment_id: None,
			pay_next_automatically: false,
		}
	}
}

impl_ser_tlv_based!(RecurrenceDetails, {
	(0, id, required),
	(2, status, required),
	(4, original_offer, required),
	(6, amount_msat, option),
	(8, quantity, option),
	(10, payer_note, option),
	(12, basetime, required),
	(14, initial_start, option),
	(16, paid_count, required),
	(18, opaque_state, option),
	(20, retry_policy, required),
	(22, routing_override, option),
	(24, last_successful_payment_id, option),
	(26, pay_next_automatically, required),
});

impl StorableObject for RecurrenceDetails {
	type Id = RecurrenceId;
	type Update = RecurrenceDetailsUpdate;

	fn id(&self) -> Self::Id {
		self.id
	}

	fn update(&mut self, update: Self::Update) -> bool {
		if self.id() != update.details.id() {
			return false;
		}
		*self = update.details;
		true
	}

	fn to_update(&self) -> Self::Update {
		RecurrenceDetailsUpdate { details: self.clone() }
	}
}

/// Update instructions for a RecurrenceDetails
#[derive(Clone, Debug)]
pub(crate) struct RecurrenceDetailsUpdate {
	pub details: RecurrenceDetails,
}

impl StorableObjectUpdate<RecurrenceDetails> for RecurrenceDetailsUpdate {
	fn id(&self) -> RecurrenceId {
		self.details.id
	}
}

#[cfg(test)]
mod tests {
	use lightning::util::ser::{Readable, Writeable};

	use super::*;

	#[test]
	fn outbound_recurrence_state_roundtrip() {
		let state = RecurrenceDetails {
			id: RecurrenceId([2; 32]),
			status: RecurrenceStatus::Completed,
			original_offer: vec![1, 2, 3],
			amount_msat: Some(21_000),
			quantity: Some(2),
			payer_note: Some(UntrustedString("recurring payment".to_owned())),
			basetime: 1_700_000_000,
			initial_start: Some(3),
			paid_count: 4,
			opaque_state: Some(vec![4, 5, 6]),
			retry_policy: Retry::Attempts(7),
			routing_override: Some(
				RouteParametersConfig::default()
					.with_max_total_routing_fee_msat(8_000)
					.with_max_total_cltv_expiry_delta(9)
					.with_max_path_count(10)
					.with_max_channel_saturation_power_of_half(11),
			),
			last_successful_payment_id: Some(PaymentId([12; 32])),
			pay_next_automatically: true,
		};

		let encoded = state.encode();
		let decoded = RecurrenceDetails::read(&mut &*encoded).unwrap();

		assert_eq!(decoded.status, state.status);
		assert_eq!(decoded.original_offer, state.original_offer);
		assert_eq!(decoded.amount_msat, state.amount_msat);
		assert_eq!(decoded.quantity, state.quantity);
		assert_eq!(decoded.payer_note, state.payer_note);
		assert_eq!(decoded.basetime, state.basetime);
		assert_eq!(decoded.initial_start, state.initial_start);
		assert_eq!(decoded.paid_count, state.paid_count);
		assert_eq!(decoded.opaque_state, state.opaque_state);
		assert_eq!(decoded.retry_policy, state.retry_policy);
		assert_eq!(
			decoded.routing_override.map(|config| (
				config.max_total_routing_fee_msat,
				config.max_total_cltv_expiry_delta,
				config.max_path_count,
				config.max_channel_saturation_power_of_half,
			)),
			state.routing_override.map(|config| (
				config.max_total_routing_fee_msat,
				config.max_total_cltv_expiry_delta,
				config.max_path_count,
				config.max_channel_saturation_power_of_half,
			)),
		);
		assert_eq!(decoded.last_successful_payment_id, state.last_successful_payment_id);
		assert_eq!(decoded.pay_next_automatically, state.pay_next_automatically);
	}
}
