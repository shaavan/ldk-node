// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Holds a payment handler allowing to create and pay [BOLT 12] offers and refunds.
//!
//! [BOLT 12]: https://github.com/lightning/bolts/blob/master/12-offer-encoding.md

use std::num::NonZeroU64;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lightning::blinded_path::message::BlindedMessagePath;
use lightning::ln::channelmanager::{OptionalOfferPaymentParams, PaymentId};
use lightning::ln::outbound_payment::Retry;
use lightning::offers::offer::{Amount, Offer as LdkOffer, OfferFromHrn, Quantity, RecurrenceType};
use lightning::offers::parse::Bolt12SemanticError;
use lightning::offers::payer_proof::PaidBolt12Invoice as LdkPaidBolt12Invoice;
#[cfg(not(feature = "uniffi"))]
use lightning::offers::payer_proof::PayerProof as LdkPayerProof;
use lightning::routing::router::RouteParametersConfig;
use lightning::sign::{EntropySource, NodeSigner};
#[cfg(feature = "uniffi")]
use lightning::util::ser::Readable;
use lightning::util::ser::Writeable;
use lightning_types::payment::PaymentPreimage;
use lightning_types::string::UntrustedString;

use crate::config::{AsyncPaymentsRole, Config, LDK_PAYMENT_RETRY_TIMEOUT};
use crate::error::Error;
use crate::ffi::{maybe_deref, maybe_wrap};
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::payment::recurrence::RecurrenceManager;
use crate::payment::recurrence::{
	RecurrenceAttempt, RecurrenceCancellationState, RecurrenceConfig, RecurrenceDetails,
	RecurrenceId, RecurrencePaymentWindow, RecurrenceRetryState, RecurrenceStatus,
};
use crate::payment::store::{PaymentDetails, PaymentDirection, PaymentKind, PaymentStatus};
use crate::runtime::Runtime;
use crate::types::{ChannelManager, KeysManager, PaymentStore};

fn validate_recurrence_amount(
	offer_amount_msat: Option<u64>, requested_amount_msat: Option<u64>,
	maximum_amount_msat: Option<u64>,
) -> Result<u64, Error> {
	let amount_msat = requested_amount_msat.or(offer_amount_msat).ok_or(Error::InvalidAmount)?;
	if maximum_amount_msat.is_some_and(|maximum| amount_msat > maximum) {
		return Err(Error::InvalidAmount);
	}
	Ok(amount_msat)
}

#[cfg(all(test, not(feature = "uniffi")))]
mod recurrence_tests {
	use super::validate_recurrence_amount;
	use lightning::offers::offer::{
		Recurrence, RecurrenceBase, RecurrenceLimit, RecurrencePeriod, RecurrenceType,
	};

	fn recurrence(recurrence_type: RecurrenceType) -> Recurrence {
		Recurrence {
			recurrence_type,
			recurrence_period: RecurrencePeriod::Days(30),
			recurrence_paywindow: None,
			recurrence_limit: Some(RecurrenceLimit(3)),
		}
	}

	#[test]
	fn validates_explicit_and_implicit_basetimes() {
		let explicit = recurrence(RecurrenceType::Compulsory(Some(RecurrenceBase {
			proportional: false,
			basetime: 100,
		})));
		assert_eq!(explicit.period_index(0, Some(2)).unwrap(), 2);
		assert!(explicit.period_index(0, None).is_err());

		let implicit = recurrence(RecurrenceType::Compulsory(None));
		assert_eq!(implicit.period_index(0, None).unwrap(), 0);
		assert!(implicit.period_index(0, Some(2)).is_err());
	}

	#[test]
	fn validates_fixed_amounts_and_maximum_ceiling() {
		assert_eq!(validate_recurrence_amount(Some(100), None, None).unwrap(), 100);
		assert_eq!(validate_recurrence_amount(Some(100), Some(150), Some(200)).unwrap(), 150);
		assert!(validate_recurrence_amount(Some(100), Some(250), Some(200)).is_err());
		assert!(validate_recurrence_amount(None, None, None).is_err());
	}

	#[test]
	fn preserves_quantity_and_proportional_schedule_inputs() {
		let recurrence = recurrence(RecurrenceType::Compulsory(Some(RecurrenceBase {
			proportional: true,
			basetime: 100,
		})));
		assert!(
			matches!(recurrence.recurrence_type, RecurrenceType::Compulsory(Some(base)) if base.proportional)
		);
		assert_eq!(recurrence.period_index(2, Some(1)).unwrap(), 3);
	}
}

#[cfg(not(feature = "uniffi"))]
type Bolt12Invoice = lightning::offers::invoice::Bolt12Invoice;
#[cfg(feature = "uniffi")]
type Bolt12Invoice = Arc<crate::ffi::Bolt12Invoice>;

#[cfg(not(feature = "uniffi"))]
type Offer = LdkOffer;
#[cfg(feature = "uniffi")]
type Offer = Arc<crate::ffi::Offer>;

#[cfg(not(feature = "uniffi"))]
type Refund = lightning::offers::refund::Refund;
#[cfg(feature = "uniffi")]
type Refund = Arc<crate::ffi::Refund>;

#[cfg(not(feature = "uniffi"))]
type HumanReadableName = lightning::onion_message::dns_resolution::HumanReadableName;
#[cfg(feature = "uniffi")]
type HumanReadableName = Arc<crate::ffi::HumanReadableName>;

#[cfg(not(feature = "uniffi"))]
type PayerProof = LdkPayerProof;
#[cfg(feature = "uniffi")]
type PayerProof = Arc<crate::ffi::PayerProof>;

/// Options controlling which optional fields are disclosed in a [BOLT 12] payer proof.
///
/// A payer proof always commits to the payer id, the payment hash, and the issuer signing
/// pubkey, and additionally discloses the invoice features whenever the invoice carries any.
/// Everything else is disclosed only if requested here, allowing to reveal just as much of the
/// invoice as the verifier needs to see.
///
/// [BOLT 12]: https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PayerProofOptions {
	/// An optional note to attach to the payer proof itself.
	pub note: Option<String>,
	/// Whether to disclose the offer description.
	pub include_offer_description: bool,
	/// Whether to disclose the offer issuer.
	pub include_offer_issuer: bool,
	/// Whether to disclose the invoice amount.
	pub include_invoice_amount: bool,
	/// Whether to disclose the invoice creation timestamp.
	pub include_invoice_created_at: bool,
	/// Additional TLV types to disclose, for fields not covered by the flags above.
	pub extra_tlv_types: Vec<u64>,
}

/// A payment handler allowing to create and pay [BOLT 12] offers and refunds.
///
/// Should be retrieved by calling [`Node::bolt12_payment`].
///
/// [BOLT 12]: https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
/// [`Node::bolt12_payment`]: crate::Node::bolt12_payment
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Bolt12Payment {
	runtime: Arc<Runtime>,
	channel_manager: Arc<ChannelManager>,
	keys_manager: Arc<KeysManager>,
	payment_store: Arc<PaymentStore>,
	recurrence_manager: Arc<RecurrenceManager>,
	config: Arc<Config>,
	is_running: Arc<RwLock<bool>>,
	logger: Arc<Logger>,
	async_payments_role: Option<AsyncPaymentsRole>,
}

impl Bolt12Payment {
	/// Starts a recurrence using the supplied durable configuration. The primary invoice request
	/// is submitted immediately; the returned identifiers distinguish the relationship from its
	/// first payment attempt.
	#[cfg(not(feature = "uniffi"))]
	pub fn start_recurrence(
		&self, offer: &Offer, config: RecurrenceConfig,
	) -> Result<(RecurrenceId, PaymentId), Error> {
		let result = self.initiate_recurrence(
			offer,
			config.amount_msat,
			config.maximum_amount_msat,
			config.quantity,
			config.payer_note,
			config.routing_override,
			config.initial_start,
		)?;
		let mut details = self
			.runtime
			.block_on(self.recurrence_manager.get(&result.0))
			.map_err(|_| Error::PersistenceFailed)?
			.ok_or(Error::PersistenceFailed)?;
		details.pay_next_automatically = config.pay_next_automatically;
		details.recurrence_retry_policy = Some(config.retry_policy);
		details.transition_id += 1;
		self.runtime
			.block_on(self.recurrence_manager.update(details))
			.map_err(|_| Error::PersistenceFailed)?;
		Ok(result)
	}

	#[cfg(not(feature = "uniffi"))]
	/// Returns the durable details for a recurrence.
	pub fn recurrence(&self, recurrence_id: RecurrenceId) -> Result<RecurrenceDetails, Error> {
		self.runtime
			.block_on(self.recurrence_manager.get(&recurrence_id))
			.map_err(|_| Error::PersistenceFailed)?
			.ok_or(Error::InvalidOfferId)
	}

	#[cfg(not(feature = "uniffi"))]
	/// Lists all durable recurrence records.
	pub fn list_recurrences(&self) -> Vec<RecurrenceDetails> {
		self.runtime.block_on(self.recurrence_manager.list())
	}

	#[cfg(not(feature = "uniffi"))]
	/// Returns the payment window for a period of an explicit-basetime offer.
	pub fn recurrence_payment_window(
		&self, offer: &Offer, period_index: u32,
	) -> Result<RecurrencePaymentWindow, Error> {
		let offer = maybe_deref(offer);
		let recurrence = offer.offer_recurrence().ok_or(Error::InvalidOffer)?;
		let basetime = match recurrence.recurrence_type {
			RecurrenceType::Compulsory(Some(base)) => base.basetime,
			_ => return Err(Error::InvalidOffer),
		};
		let (opens_at, closes_at) =
			recurrence.payment_window(basetime, period_index).map_err(|_| Error::InvalidOffer)?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
		Ok(RecurrencePaymentWindow {
			period_index,
			opens_at,
			closes_at,
			currently_payable: now >= opens_at && now < closes_at,
		})
	}

	/// Returns the next payment window for an existing recurrence.
	#[cfg(not(feature = "uniffi"))]
	pub fn next_recurrence_payment_window(
		&self, recurrence_id: RecurrenceId,
	) -> Result<RecurrencePaymentWindow, Error> {
		let details = self.recurrence(recurrence_id)?;
		let basetime = details.basetime.ok_or(Error::InvalidOffer)?;
		let offer =
			LdkOffer::try_from(details.original_offer.clone()).map_err(|_| Error::InvalidOffer)?;
		let recurrence = offer.offer_recurrence().ok_or(Error::InvalidOffer)?;
		let period_index = u32::try_from(details.paid_count).map_err(|_| Error::InvalidAmount)?;
		let (opens_at, closes_at) =
			recurrence.payment_window(basetime, period_index).map_err(|_| Error::InvalidOffer)?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
		Ok(RecurrencePaymentWindow {
			period_index,
			opens_at,
			closes_at,
			currently_payable: now >= opens_at && now < closes_at,
		})
	}

	/// Removes a completed recurrence without removing its ordinary payment history.
	#[cfg(not(feature = "uniffi"))]
	pub fn remove_recurrence(&self, recurrence_id: RecurrenceId) -> Result<(), Error> {
		let details = self.recurrence(recurrence_id)?;
		if !matches!(
			details.status,
			RecurrenceStatus::Cancelled
				| RecurrenceStatus::Completed
				| RecurrenceStatus::Missed
				| RecurrenceStatus::RequiresAttention
		) {
			return Err(Error::InvalidOffer);
		}
		self.runtime
			.block_on(self.recurrence_manager.remove(&recurrence_id))
			.map_err(|_| Error::PersistenceFailed)
	}
	pub(crate) fn new(
		runtime: Arc<Runtime>, channel_manager: Arc<ChannelManager>,
		keys_manager: Arc<KeysManager>, payment_store: Arc<PaymentStore>,
		recurrence_manager: Arc<RecurrenceManager>, config: Arc<Config>,
		is_running: Arc<RwLock<bool>>, logger: Arc<Logger>,
		async_payments_role: Option<AsyncPaymentsRole>,
	) -> Self {
		Self {
			runtime,
			channel_manager,
			keys_manager,
			payment_store,
			recurrence_manager,
			config,
			is_running,
			logger,
			async_payments_role,
		}
	}

	/// Registers and submits the primary invoice request for a recurring offer.
	///
	/// The returned [`RecurrenceId`] identifies the complete recurring relationship and must be
	/// retained for its lifetime. The returned [`PaymentId`] identifies only the initial payment
	/// attempt. Both identifiers are generated after validation and persisted before submission.
	#[cfg(not(feature = "uniffi"))]
	pub fn initiate_recurrence(
		&self, offer: &Offer, amount_msat: Option<u64>, maximum_amount_msat: Option<u64>,
		quantity: Option<u64>, payer_note: Option<String>,
		route_parameters: Option<RouteParametersConfig>, initial_start: Option<u32>,
	) -> Result<(RecurrenceId, PaymentId), Error> {
		if !*self.is_running.read().expect("lock") {
			return Err(Error::NotRunning);
		}

		let offer = maybe_deref(offer);
		let recurrence = offer.offer_recurrence().ok_or(Error::InvoiceRequestCreationFailed)?;
		if recurrence.period_index(0, initial_start).is_err() {
			return Err(Error::InvoiceRequestCreationFailed);
		}

		let offer_amount_msat = match offer.amount() {
			Some(Amount::Bitcoin { amount_msats }) => Some(amount_msats),
			Some(_) => return Err(Error::UnsupportedCurrency),
			None => None,
		};
		let amount_msat =
			validate_recurrence_amount(offer_amount_msat, amount_msat, maximum_amount_msat)?;
		if amount_msat == 0 || maximum_amount_msat == Some(0) {
			return Err(Error::InvalidAmount);
		}
		if quantity == Some(0) {
			return Err(Error::InvalidQuantity);
		}

		let recurrence_id = RecurrenceId(self.keys_manager.get_secure_random_bytes());
		let payment_id = PaymentId(self.keys_manager.get_secure_random_bytes());
		let retry_policy = Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT);
		let mut details = RecurrenceDetails {
			id: recurrence_id,
			original_offer: offer.encode(),
			amount_msat: Some(amount_msat),
			maximum_amount_msat,
			quantity,
			payer_note: payer_note.clone().map(UntrustedString),
			routing_override: route_parameters,
			retry_policy,
			recurrence_retry_policy: Some(
				crate::payment::recurrence::RecurrenceRetryPolicy::default(),
			),
			retry_state: RecurrenceRetryState { attempts: 0, next_retry_at: None },
			pay_next_automatically: false,
			initial_start,
			paid_count: 0,
			basetime: match recurrence.recurrence_type {
				RecurrenceType::Compulsory(Some(base)) => Some(base.basetime),
				_ => None,
			},
			opaque_state: None,
			last_successful_payment_id: None,
			attempt: Some(RecurrenceAttempt::Prepared { payment_id, amount_msat }),
			cancellation: RecurrenceCancellationState::NotRequested,
			failure: None,
			transition_id: 0,
			status: RecurrenceStatus::Active,
		};

		// Persist the attempt before submitting it so a restart can reconcile an interrupted call.
		if self.runtime.block_on(self.recurrence_manager.insert(details.clone())).is_err() {
			return Err(Error::PersistenceFailed);
		}
		let kind = PaymentKind::Bolt12Offer {
			hash: None,
			preimage: None,
			secret: None,
			offer_id: offer.id(),
			payer_note: details.payer_note.clone(),
			quantity,
		};
		let payment = PaymentDetails::new(
			payment_id,
			kind,
			Some(amount_msat),
			None,
			PaymentDirection::Outbound,
			PaymentStatus::Pending,
		);
		if self.runtime.block_on(self.payment_store.insert(payment)).is_err() {
			// The recurrence remains durable, but cannot proceed until its payment record is repaired.
			details.status = RecurrenceStatus::RequiresAttention;
			details.transition_id += 1;
			let _ = self.runtime.block_on(self.recurrence_manager.update(details));
			return Ok((recurrence_id, payment_id));
		}

		let params = lightning::ln::channelmanager::RecurrencePaymentParams {
			counter: 0,
			start: initial_start,
			prev_state: None,
			quantity,
			expected_invoice_recurrence_basetime: details.basetime,
		};
		let optional_params = lightning::ln::channelmanager::OptionalOfferPaymentParams {
			payer_note,
			route_params_config: route_parameters.unwrap_or_default(),
			retry_strategy: retry_policy,
		};
		if self
			.channel_manager
			.pay_for_recurrence(
				&offer,
				Some(amount_msat),
				payment_id,
				recurrence_id,
				params,
				optional_params,
			)
			.is_ok()
		{
			// Mark submission only after LDK accepts the request; prepared state remains recoverable
			// when synchronous submission fails.
			details.attempt = Some(RecurrenceAttempt::Submitted { payment_id, amount_msat });
			details.transition_id += 1;
		} else {
			details.status = RecurrenceStatus::RequiresAttention;
			details.transition_id += 1;
		}
		let _ = self.runtime.block_on(self.recurrence_manager.update(details));
		Ok((recurrence_id, payment_id))
	}

	/// Submits the next sequential payment for an active recurring offer.
	///
	/// Once the attempt is durably recorded, the returned [`PaymentId`] remains valid even when
	/// synchronous submission fails; inspect the recurrence and payment records for that result.
	#[cfg(not(feature = "uniffi"))]
	pub fn pay_next_recurrence(&self, recurrence_id: RecurrenceId) -> Result<PaymentId, Error> {
		if !*self.is_running.read().expect("lock") {
			return Err(Error::NotRunning);
		}
		let Some(mut details) = self
			.runtime
			.block_on(self.recurrence_manager.get(&recurrence_id))
			.map_err(|_| Error::PersistenceFailed)?
		else {
			return Err(Error::InvalidOfferId);
		};
		if details.status != RecurrenceStatus::Active || details.paid_count == 0 {
			return Err(Error::InvalidOffer);
		}
		if details.attempt.is_some() {
			return Err(Error::PaymentSendingFailed);
		}
		let counter = u32::try_from(details.paid_count).map_err(|_| Error::InvalidAmount)?;
		let offer =
			LdkOffer::try_from(details.original_offer.clone()).map_err(|_| Error::InvalidOffer)?;
		let recurrence = offer.offer_recurrence().ok_or(Error::InvalidOffer)?;
		let period_index = recurrence
			.period_index(counter, details.initial_start)
			.map_err(|_| Error::InvalidOffer)?;
		if recurrence.recurrence_limit.map(|limit| period_index > limit.0).unwrap_or(false) {
			return Err(Error::InvalidOffer);
		}
		let basetime = details.basetime.ok_or(Error::InvalidOffer)?;
		let (opening, closing) =
			recurrence.payment_window(basetime, period_index).map_err(|_| Error::InvalidOffer)?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
		if now < opening {
			return Err(Error::InvalidOffer);
		}
		if now >= closing {
			details.status = RecurrenceStatus::Missed;
			details.transition_id += 1;
			let _ = self.runtime.block_on(self.recurrence_manager.update(details));
			return Err(Error::InvalidOffer);
		}
		let amount_msat = details.amount_msat.ok_or(Error::InvalidAmount)?;
		let payment_id = PaymentId(self.keys_manager.get_secure_random_bytes());
		let retry_policy = details.retry_policy;
		details = self
			.runtime
			.block_on(self.recurrence_manager.claim_attempt(
				&recurrence_id,
				RecurrenceAttempt::Prepared { payment_id, amount_msat },
			))
			.map_err(|_| Error::PersistenceFailed)?
			.ok_or(Error::PaymentSendingFailed)?;
		let payment = PaymentDetails::new(
			payment_id,
			PaymentKind::Bolt12Offer {
				hash: None,
				preimage: None,
				secret: None,
				offer_id: offer.id(),
				payer_note: details.payer_note.clone(),
				quantity: details.quantity,
			},
			Some(amount_msat),
			None,
			PaymentDirection::Outbound,
			PaymentStatus::Pending,
		);
		if self.runtime.block_on(self.payment_store.insert(payment)).is_err() {
			details.status = RecurrenceStatus::RequiresAttention;
			details.transition_id += 1;
			let _ = self.runtime.block_on(self.recurrence_manager.update(details));
			return Ok(payment_id);
		}
		let optional_params = OptionalOfferPaymentParams {
			payer_note: details.payer_note.as_ref().map(ToString::to_string),
			route_params_config: details
				.routing_override
				.or(self.config.route_parameters)
				.unwrap_or_default(),
			retry_strategy: retry_policy,
		};
		let params = lightning::ln::channelmanager::RecurrencePaymentParams {
			counter,
			start: details.initial_start,
			prev_state: details.opaque_state.clone(),
			quantity: details.quantity,
			expected_invoice_recurrence_basetime: details.basetime,
		};
		if self
			.channel_manager
			.pay_for_recurrence(
				&offer,
				details.amount_msat,
				payment_id,
				recurrence_id,
				params,
				optional_params,
			)
			.is_ok()
		{
			details.attempt = Some(RecurrenceAttempt::Submitted { payment_id, amount_msat });
		} else {
			details.status = RecurrenceStatus::RequiresAttention;
		}
		details.transition_id += 1;
		let _ = self.runtime.block_on(self.recurrence_manager.update(details));
		Ok(payment_id)
	}

	/// Persists whether future recurrence periods should be submitted automatically.
	pub(crate) fn set_pay_next_automatically(
		&self, recurrence_id: RecurrenceId, enabled: bool,
	) -> Result<(), Error> {
		let mut details = self
			.runtime
			.block_on(self.recurrence_manager.get(&recurrence_id))
			.map_err(|_| Error::PersistenceFailed)?
			.ok_or(Error::InvalidOfferId)?;
		details.pay_next_automatically = enabled;
		details.transition_id += 1;
		self.runtime
			.block_on(self.recurrence_manager.update(details))
			.map_err(|_| Error::PersistenceFailed)?;
		Ok(())
	}

	/// Persists a per-recurrence routing override; `None` restores node defaults.
	pub(crate) fn set_recurrence_route_parameters(
		&self, recurrence_id: RecurrenceId, route_parameters: Option<RouteParametersConfig>,
	) -> Result<(), Error> {
		let mut details = self
			.runtime
			.block_on(self.recurrence_manager.get(&recurrence_id))
			.map_err(|_| Error::PersistenceFailed)?
			.ok_or(Error::InvalidOfferId)?;
		details.routing_override = route_parameters;
		details.transition_id += 1;
		self.runtime
			.block_on(self.recurrence_manager.update(details))
			.map_err(|_| Error::PersistenceFailed)?;
		Ok(())
	}

	/// Cancels a recurring offer locally and, after the first successful payment, queues a
	/// continuity-preserving cancellation request for the payee.
	#[cfg(not(feature = "uniffi"))]
	pub fn cancel_recurrence(&self, recurrence_id: RecurrenceId) -> Result<(), Error> {
		let Some(mut details) = self
			.runtime
			.block_on(self.recurrence_manager.get(&recurrence_id))
			.map_err(|_| Error::PersistenceFailed)?
		else {
			return Err(Error::InvalidOfferId);
		};
		if matches!(
			details.status,
			RecurrenceStatus::Cancelled
				| RecurrenceStatus::Completed
				| RecurrenceStatus::Missed
				| RecurrenceStatus::RequiresAttention
		) {
			return Err(Error::InvalidOffer);
		}
		if details.status == RecurrenceStatus::CancellationPending {
			return Ok(());
		}

		details.status = RecurrenceStatus::CancellationPending;
		details.cancellation = RecurrenceCancellationState::Pending;
		details.transition_id += 1;
		// Persist the pending state before abandoning or notifying the payee so a restart cannot
		// resume payment while cancellation is being processed.
		self.runtime
			.block_on(self.recurrence_manager.update(details.clone()))
			.map_err(|_| Error::PersistenceFailed)?;

		if let Some(
			RecurrenceAttempt::Prepared { payment_id, .. }
			| RecurrenceAttempt::Submitted { payment_id, .. },
		) = details.attempt
		{
			self.channel_manager.abandon_payment(payment_id);
		}
		if details.paid_count > 0 {
			// The payee needs the previous recurrence state to authenticate cancellation continuity.
			let offer = LdkOffer::try_from(details.original_offer.clone())
				.map_err(|_| Error::InvalidOffer)?;
			let counter = u32::try_from(details.paid_count).map_err(|_| Error::InvalidAmount)?;
			let params = lightning::ln::channelmanager::RecurrenceCancellationParams {
				counter,
				start: details.initial_start,
				prev_state: details.opaque_state.clone(),
			};
			let _ = self.channel_manager.cancel_recurrence(&offer, recurrence_id, params);
		}
		details.status = RecurrenceStatus::Cancelled;
		details.cancellation = RecurrenceCancellationState::Cancelled;
		details.transition_id += 1;
		// Mark the record terminal only after the local cancellation work is complete.
		self.runtime
			.block_on(self.recurrence_manager.update(details))
			.map_err(|_| Error::PersistenceFailed)?;
		Ok(())
	}

	pub(crate) fn send_using_amount_inner(
		&self, offer: &Offer, amount_msat: u64, quantity: Option<u64>, payer_note: Option<String>,
		route_parameters: Option<RouteParametersConfig>, hrn: Option<HumanReadableName>,
	) -> Result<PaymentId, Error> {
		if !*self.is_running.read().expect("lock") {
			return Err(Error::NotRunning);
		}

		let offer = maybe_deref(offer);

		let payment_id = PaymentId(self.keys_manager.get_secure_random_bytes());
		let retry_strategy = Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT);
		let route_parameters =
			route_parameters.or(self.config.route_parameters).unwrap_or_default();

		let offer_amount_msat = match offer.amount() {
			Some(Amount::Bitcoin { amount_msats }) => amount_msats,
			Some(_) => {
				log_error!(self.logger, "Failed to send payment as the provided offer was denominated in an unsupported currency.");
				return Err(Error::UnsupportedCurrency);
			},
			None => amount_msat,
		};

		if amount_msat < offer_amount_msat {
			log_error!(
				self.logger,
				"Failed to pay as the given amount needs to be at least the offer amount: required {}msat, gave {}msat.", offer_amount_msat, amount_msat);
			return Err(Error::InvalidAmount);
		}

		let params = OptionalOfferPaymentParams {
			payer_note: payer_note.clone(),
			retry_strategy,
			route_params_config: route_parameters,
		};
		let res = if let Some(hrn) = hrn {
			let hrn = maybe_deref(&hrn);
			let offer = OfferFromHrn { offer: offer.clone(), hrn: *hrn };
			self.channel_manager.pay_for_offer_from_hrn(&offer, amount_msat, payment_id, params)
		} else if let Some(quantity) = quantity {
			self.channel_manager.pay_for_offer_with_quantity(
				&offer,
				Some(amount_msat),
				payment_id,
				params,
				quantity,
			)
		} else {
			self.channel_manager.pay_for_offer(&offer, Some(amount_msat), payment_id, params)
		};

		match res {
			Ok(()) => {
				let payee_pubkey = offer.issuer_signing_pubkey();
				log_info!(
					self.logger,
					"Initiated sending {}msat to {:?}",
					amount_msat,
					payee_pubkey
				);

				let kind = PaymentKind::Bolt12Offer {
					hash: None,
					preimage: None,
					secret: None,
					offer_id: offer.id(),
					payer_note: payer_note.map(UntrustedString),
					quantity,
				};
				let payment = PaymentDetails::new(
					payment_id,
					kind,
					Some(amount_msat),
					None,
					PaymentDirection::Outbound,
					PaymentStatus::Pending,
				);
				self.runtime.block_on(self.payment_store.insert(payment))?;

				Ok(payment_id)
			},
			Err(e) => {
				log_error!(self.logger, "Failed to send payment: {:?}", e);
				match e {
					Bolt12SemanticError::DuplicatePaymentId => Err(Error::DuplicatePayment),
					_ => {
						let kind = PaymentKind::Bolt12Offer {
							hash: None,
							preimage: None,
							secret: None,
							offer_id: offer.id(),
							payer_note: payer_note.map(UntrustedString),
							quantity,
						};
						let payment = PaymentDetails::new(
							payment_id,
							kind,
							Some(amount_msat),
							None,
							PaymentDirection::Outbound,
							PaymentStatus::Failed,
						);
						self.runtime.block_on(self.payment_store.insert(payment))?;
						Err(Error::PaymentSendingFailed)
					},
				}
			},
		}
	}

	pub(crate) fn receive_inner(
		&self, amount_msat: u64, description: &str, expiry_secs: Option<u32>, quantity: Option<u64>,
	) -> Result<LdkOffer, Error> {
		let mut offer_builder = self.channel_manager.create_offer_builder().map_err(|e| {
			log_error!(self.logger, "Failed to create offer builder: {:?}", e);
			Error::OfferCreationFailed
		})?;

		if let Some(expiry_secs) = expiry_secs {
			let absolute_expiry = (SystemTime::now() + Duration::from_secs(expiry_secs as u64))
				.duration_since(UNIX_EPOCH)
				.expect("system time must be after Unix epoch");
			offer_builder = offer_builder.absolute_expiry(absolute_expiry);
		}

		let mut offer =
			offer_builder.amount_msats(amount_msat).description(description.to_string());

		if let Some(qty) = quantity {
			if qty == 0 {
				log_error!(self.logger, "Failed to create offer: quantity can't be zero.");
				return Err(Error::InvalidQuantity);
			} else {
				offer = offer.supported_quantity(Quantity::Bounded(
					NonZeroU64::new(qty).expect("quantity is non-zero"),
				))
			};
		};

		let finalized_offer = offer.build().map_err(|e| {
			log_error!(self.logger, "Failed to create offer: {:?}", e);
			Error::OfferCreationFailed
		})?;

		Ok(finalized_offer)
	}

	fn blinded_paths_for_async_recipient_internal(
		&self, recipient_id: Vec<u8>,
	) -> Result<Vec<BlindedMessagePath>, Error> {
		match self.async_payments_role {
			Some(AsyncPaymentsRole::Server) => {},
			_ => {
				return Err(Error::AsyncPaymentServicesDisabled);
			},
		}

		self.channel_manager
			.blinded_paths_for_async_recipient(recipient_id, None)
			.or(Err(Error::InvalidBlindedPaths))
	}
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Bolt12Payment {
	/// Send a payment given an offer.
	///
	/// If `payer_note` is `Some` it will be seen by the recipient and reflected back in the invoice
	/// response.
	///
	/// If `quantity` is `Some` it represents the number of items requested.
	///
	/// If `route_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::route_parameters`] on a per-field basis.
	pub fn send(
		&self, offer: &Offer, quantity: Option<u64>, payer_note: Option<String>,
		route_parameters: Option<RouteParametersConfig>,
	) -> Result<PaymentId, Error> {
		if !*self.is_running.read().expect("lock") {
			return Err(Error::NotRunning);
		}

		let offer = maybe_deref(offer);

		let payment_id = PaymentId(self.keys_manager.get_secure_random_bytes());
		let retry_strategy = Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT);
		let route_parameters =
			route_parameters.or(self.config.route_parameters).unwrap_or_default();

		let offer_amount_msat = match offer.amount() {
			Some(Amount::Bitcoin { amount_msats }) => amount_msats,
			Some(_) => {
				log_error!(self.logger, "Failed to send payment as the provided offer was denominated in an unsupported currency.");
				return Err(Error::UnsupportedCurrency);
			},
			None => {
				log_error!(self.logger, "Failed to send payment due to the given offer being \"zero-amount\". Please use send_using_amount instead.");
				return Err(Error::InvalidOffer);
			},
		};

		let params = OptionalOfferPaymentParams {
			payer_note: payer_note.clone(),
			retry_strategy,
			route_params_config: route_parameters,
		};
		let res = if let Some(quantity) = quantity {
			self.channel_manager
				.pay_for_offer_with_quantity(&offer, None, payment_id, params, quantity)
		} else {
			self.channel_manager.pay_for_offer(&offer, None, payment_id, params)
		};

		match res {
			Ok(()) => {
				let payee_pubkey = offer.issuer_signing_pubkey();
				log_info!(
					self.logger,
					"Initiated sending {}msat to {:?}",
					offer_amount_msat,
					payee_pubkey
				);

				let kind = PaymentKind::Bolt12Offer {
					hash: None,
					preimage: None,
					secret: None,
					offer_id: offer.id(),
					payer_note: payer_note.map(UntrustedString),
					quantity,
				};
				let payment = PaymentDetails::new(
					payment_id,
					kind,
					Some(offer_amount_msat),
					None,
					PaymentDirection::Outbound,
					PaymentStatus::Pending,
				);
				self.runtime.block_on(self.payment_store.insert(payment))?;

				Ok(payment_id)
			},
			Err(e) => {
				log_error!(self.logger, "Failed to send invoice request: {:?}", e);
				match e {
					Bolt12SemanticError::DuplicatePaymentId => Err(Error::DuplicatePayment),
					_ => {
						let kind = PaymentKind::Bolt12Offer {
							hash: None,
							preimage: None,
							secret: None,
							offer_id: offer.id(),
							payer_note: payer_note.map(UntrustedString),
							quantity,
						};
						let payment = PaymentDetails::new(
							payment_id,
							kind,
							Some(offer_amount_msat),
							None,
							PaymentDirection::Outbound,
							PaymentStatus::Failed,
						);
						self.runtime.block_on(self.payment_store.insert(payment))?;
						Err(Error::InvoiceRequestCreationFailed)
					},
				}
			},
		}
	}

	/// Send a payment given an offer and an amount in millisatoshi.
	///
	/// This will fail if the amount given is less than the value required by the given offer.
	///
	/// This can be used to pay a so-called "zero-amount" offers, i.e., an offer that leaves the
	/// amount paid to be determined by the user.
	///
	/// If `payer_note` is `Some` it will be seen by the recipient and reflected back in the invoice
	/// response.
	///
	/// If `route_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::route_parameters`] on a per-field basis.
	pub fn send_using_amount(
		&self, offer: &Offer, amount_msat: u64, quantity: Option<u64>, payer_note: Option<String>,
		route_parameters: Option<RouteParametersConfig>,
	) -> Result<PaymentId, Error> {
		let payment_id = self.send_using_amount_inner(
			offer,
			amount_msat,
			quantity,
			payer_note,
			route_parameters,
			None,
		)?;
		Ok(payment_id)
	}

	/// Creates a [BOLT 12] payer proof for a payment this node made.
	///
	/// A payer proof lets the payer demonstrate to a third party that they paid a particular
	/// [BOLT 12] invoice, disclosing only the invoice fields they choose to reveal via
	/// [`PayerProofOptions`].
	///
	/// All inputs are taken straight from [`Event::PaymentSuccessful`]: pass its `payment_id` and
	/// `payment_preimage`, plus the [`Bolt12Invoice`] out of its `bolt12_invoice` field. Nothing
	/// is read from or written to the payment store, so it's up to you to hold on to the invoice
	/// if you want to build a proof later on.
	///
	/// Note that payments settled via a static invoice, i.e., async payments, can't be proven this
	/// way, which is why this takes a [`Bolt12Invoice`] rather than the event's
	/// [`PaidBolt12Invoice`]: those payments simply won't yield one.
	///
	/// [BOLT 12]: https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
	/// [`Event::PaymentSuccessful`]: crate::Event::PaymentSuccessful
	/// [`Bolt12Invoice`]: lightning::offers::invoice::Bolt12Invoice
	/// [`PaidBolt12Invoice`]: lightning::offers::payer_proof::PaidBolt12Invoice
	pub fn create_payer_proof(
		&self, payment_id: PaymentId, payment_preimage: PaymentPreimage, invoice: &Bolt12Invoice,
		options: Option<PayerProofOptions>,
	) -> Result<PayerProof, Error> {
		let invoice = maybe_deref(invoice);
		let paid_invoice = LdkPaidBolt12Invoice::Bolt12Invoice(invoice.clone());

		let options = options.unwrap_or_default();
		let expanded_key = self.keys_manager.get_expanded_key();
		let secp_ctx = bitcoin::secp256k1::Secp256k1::new();

		let mut builder = paid_invoice
			.prove_payer_derived(payment_preimage, &expanded_key, payment_id, &secp_ctx)
			.map_err(|e| {
				log_error!(
					self.logger,
					"Failed to initialize payer proof builder for {}: {:?}",
					payment_id,
					e
				);
				Error::PayerProofCreationFailed
			})?;

		for tlv_type in options.extra_tlv_types {
			builder = builder.include_type(tlv_type).map_err(|e| {
				log_error!(
					self.logger,
					"Failed to include TLV {} in payer proof for {}: {:?}",
					tlv_type,
					payment_id,
					e
				);
				Error::PayerProofCreationFailed
			})?;
		}

		if options.include_offer_description {
			builder = builder.include_offer_description();
		}
		if options.include_offer_issuer {
			builder = builder.include_offer_issuer();
		}
		if options.include_invoice_amount {
			builder = builder.include_invoice_amount();
		}
		if options.include_invoice_created_at {
			builder = builder.include_invoice_created_at();
		}
		if let Some(note) = options.note {
			builder = builder.with_proof_note(note);
		}

		let proof = builder.build_and_sign().map_err(|e| {
			log_error!(self.logger, "Failed to build payer proof for {}: {:?}", payment_id, e);
			Error::PayerProofCreationFailed
		})?;

		log_info!(self.logger, "Created payer proof for payment {}", payment_id);

		Ok(maybe_wrap(proof))
	}

	/// Returns a payable offer that can be used to request and receive a payment of the amount
	/// given.
	pub fn receive(
		&self, amount_msat: u64, description: &str, expiry_secs: Option<u32>, quantity: Option<u64>,
	) -> Result<Offer, Error> {
		let offer = self.receive_inner(amount_msat, description, expiry_secs, quantity)?;
		Ok(maybe_wrap(offer))
	}

	/// Returns a payable offer that can be used to request and receive a payment for which the
	/// amount is to be determined by the user, also known as a "zero-amount" offer.
	pub fn receive_variable_amount(
		&self, description: &str, expiry_secs: Option<u32>,
	) -> Result<Offer, Error> {
		let mut offer_builder = self.channel_manager.create_offer_builder().map_err(|e| {
			log_error!(self.logger, "Failed to create offer builder: {:?}", e);
			Error::OfferCreationFailed
		})?;

		if let Some(expiry_secs) = expiry_secs {
			let absolute_expiry = (SystemTime::now() + Duration::from_secs(expiry_secs as u64))
				.duration_since(UNIX_EPOCH)
				.expect("system time must be after Unix epoch");
			offer_builder = offer_builder.absolute_expiry(absolute_expiry);
		}

		let offer = offer_builder.description(description.to_string()).build().map_err(|e| {
			log_error!(self.logger, "Failed to create offer: {:?}", e);
			Error::OfferCreationFailed
		})?;

		Ok(maybe_wrap(offer))
	}

	/// Requests a refund payment for the given [`Refund`].
	///
	/// The returned [`Bolt12Invoice`] is for informational purposes only (i.e., isn't needed to
	/// retrieve the refund).
	///
	/// [`Refund`]: lightning::offers::refund::Refund
	/// [`Bolt12Invoice`]: lightning::offers::invoice::Bolt12Invoice
	pub fn request_refund_payment(&self, refund: &Refund) -> Result<Bolt12Invoice, Error> {
		if !*self.is_running.read().expect("lock") {
			return Err(Error::NotRunning);
		}

		let refund = maybe_deref(refund);
		let invoice = self.channel_manager.request_refund_payment(&refund).map_err(|e| {
			log_error!(self.logger, "Failed to request refund payment: {:?}", e);
			Error::InvoiceRequestCreationFailed
		})?;

		Ok(maybe_wrap(invoice))
	}

	/// Returns a [`Refund`] object that can be used to offer a refund payment of the amount given.
	///
	/// If `route_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::route_parameters`] on a per-field basis.
	///
	/// [`Refund`]: lightning::offers::refund::Refund
	pub fn initiate_refund(
		&self, amount_msat: u64, expiry_secs: u32, quantity: Option<u64>,
		payer_note: Option<String>, route_parameters: Option<RouteParametersConfig>,
	) -> Result<Refund, Error> {
		let payment_id = PaymentId(self.keys_manager.get_secure_random_bytes());

		let absolute_expiry = (SystemTime::now() + Duration::from_secs(expiry_secs as u64))
			.duration_since(UNIX_EPOCH)
			.expect("system time must be after Unix epoch");
		let retry_strategy = Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT);
		let route_parameters =
			route_parameters.or(self.config.route_parameters).unwrap_or_default();

		let mut refund_builder = self
			.channel_manager
			.create_refund_builder(
				amount_msat,
				absolute_expiry,
				payment_id,
				retry_strategy,
				route_parameters,
			)
			.map_err(|e| {
				log_error!(self.logger, "Failed to create refund builder: {:?}", e);
				Error::RefundCreationFailed
			})?;

		if let Some(qty) = quantity {
			refund_builder = refund_builder.quantity(qty);
		}

		if let Some(note) = payer_note.clone() {
			refund_builder = refund_builder.payer_note(note);
		}

		let refund = refund_builder.build().map_err(|e| {
			log_error!(self.logger, "Failed to create refund: {:?}", e);
			Error::RefundCreationFailed
		})?;

		log_info!(self.logger, "Offering refund of {}msat", amount_msat);

		let kind = PaymentKind::Bolt12Refund {
			hash: None,
			preimage: None,
			secret: None,
			payer_note: payer_note.map(|note| UntrustedString(note)),
			quantity,
		};
		let payment = PaymentDetails::new(
			payment_id,
			kind,
			Some(amount_msat),
			None,
			PaymentDirection::Outbound,
			PaymentStatus::Pending,
		);

		self.runtime.block_on(self.payment_store.insert(payment))?;

		Ok(maybe_wrap(refund))
	}

	/// Retrieve an [`Offer`] for receiving async payments as an often-offline recipient.
	///
	/// Will only return an offer if [`Bolt12Payment::set_paths_to_static_invoice_server`] was called and we succeeded
	/// in interactively building a [`StaticInvoice`] with the static invoice server.
	///
	/// Useful for posting offers to receive payments later, such as posting an offer on a website.
	///
	/// **Caution**: Async payments support is considered experimental.
	///
	/// [`StaticInvoice`]: lightning::offers::static_invoice::StaticInvoice
	/// [`Offer`]: lightning::offers::offer::Offer
	pub fn receive_async(&self) -> Result<Offer, Error> {
		self.channel_manager
			.get_async_receive_offer()
			.map(maybe_wrap)
			.or(Err(Error::OfferCreationFailed))
	}
}

#[cfg(not(feature = "uniffi"))]
impl Bolt12Payment {
	/// Sets the [`BlindedMessagePath`]s that we will use as an async recipient to interactively build [`Offer`]s with a
	/// static invoice server, so the server can serve [`StaticInvoice`]s to payers on our behalf when we're offline.
	///
	/// **Caution**: Async payments support is considered experimental.
	///
	/// [`Offer`]: lightning::offers::offer::Offer
	/// [`StaticInvoice`]: lightning::offers::static_invoice::StaticInvoice
	pub fn set_paths_to_static_invoice_server(
		&self, paths: Vec<BlindedMessagePath>,
	) -> Result<(), Error> {
		self.channel_manager
			.set_paths_to_static_invoice_server(paths)
			.or(Err(Error::InvalidBlindedPaths))
	}

	/// [`BlindedMessagePath`]s for an async recipient to communicate with this node and interactively
	/// build [`Offer`]s and [`StaticInvoice`]s for receiving async payments.
	///
	/// **Caution**: Async payments support is considered experimental.
	///
	/// [`Offer`]: lightning::offers::offer::Offer
	/// [`StaticInvoice`]: lightning::offers::static_invoice::StaticInvoice
	pub fn blinded_paths_for_async_recipient(
		&self, recipient_id: Vec<u8>,
	) -> Result<Vec<BlindedMessagePath>, Error> {
		self.blinded_paths_for_async_recipient_internal(recipient_id)
	}
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl Bolt12Payment {
	/// Sets the [`BlindedMessagePath`]s that we will use as an async recipient to interactively build [`Offer`]s with a
	/// static invoice server, so the server can serve [`StaticInvoice`]s to payers on our behalf when we're offline.
	///
	/// **Caution**: Async payments support is considered experimental.
	///
	/// [`Offer`]: lightning::offers::offer::Offer
	/// [`StaticInvoice`]: lightning::offers::static_invoice::StaticInvoice
	pub fn set_paths_to_static_invoice_server(&self, paths: Vec<u8>) -> Result<(), Error> {
		let decoded_paths = <Vec<BlindedMessagePath> as Readable>::read(&mut &paths[..])
			.or(Err(Error::InvalidBlindedPaths))?;

		self.channel_manager
			.set_paths_to_static_invoice_server(decoded_paths)
			.or(Err(Error::InvalidBlindedPaths))
	}

	/// [`BlindedMessagePath`]s for an async recipient to communicate with this node and interactively
	/// build [`Offer`]s and [`StaticInvoice`]s for receiving async payments.
	///
	/// **Caution**: Async payments support is considered experimental.
	///
	/// [`Offer`]: lightning::offers::offer::Offer
	/// [`StaticInvoice`]: lightning::offers::static_invoice::StaticInvoice
	pub fn blinded_paths_for_async_recipient(
		&self, recipient_id: Vec<u8>,
	) -> Result<Vec<u8>, Error> {
		let paths = self.blinded_paths_for_async_recipient_internal(recipient_id)?;

		let mut bytes = Vec::new();
		paths.write(&mut bytes).or(Err(Error::InvalidBlindedPaths))?;
		Ok(bytes)
	}
}
