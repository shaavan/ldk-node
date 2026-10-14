## Inbound Recurrence

1. **LDK prerequisite: Inbound recurrence timing context.** Add
   `offer_recurrence: Option<Recurrence>` and
   `invoice_recurrence_basetime: Option<u64>` to `Bolt12OfferContext`. Populate
   them during invoice creation using the offer's recurrence terms and the
   basetime actually set in the invoice. Carry them through authenticated blinded
   payment paths so `PaymentClaimable` and `PaymentClaimed` expose them in
   `payment_context`. Keep them absent for non-recurring payments and preserve
   serialization compatibility. LDK Node can then persist these values and
   calculate the next expected counter's window using LDK's recurrence helpers.

2. **Inbound store.** Introduce a separate inbound recurrence store, keyed by
   `(offer_id, payer_signing_pubkey)`. Persist/load it in its own namespace and
   thread it through the event handler.

   **Fields:**

   | Field | Value |
   | --- | --- |
   | `recurrence` | `Recurrence` |
   | `status` | `Active` / `Cancelled` / `Missed` |
   | `basetime` | `Option<u64>` |
   | `initial_start` | `Option<u32>` |
   | `last_paid_counter` | `Option<u32>` |
   | `last_successful_payment_id` | `Option<PaymentId>` |
   | Pending claim | Persisted counter and payment ID |

   Retain timing fields for missed-window tracking; defer completion and offer-term
   validation. Define a cancellation-only
   record for relationships whose terms are not known yet. Keep individual
   payment details in `PaymentStore`.

3. **Add lookup/list APIs.** Look up a relationship by
   `(offer_id, payer_signing_pubkey)` and list stored inbound recurrences. Expose
   status, paid progress, and pending claims, including cancellation-only records.
   Return public views without allowing direct mutation of stored state. Keep
   UniFFI exposure in Shared.

4. **Claim reservation safety.** Use the inbound store's `mutate_async` to check
   status and paid/pending counters and persist a reservation before calling
   `claim_funds`. Reject a different payment for a paid or reserved counter;
   allow replay of the same accepted payment. Acquire recurrence-store locks
   before payment-store locks, and specify the write order for recurrence records,
   `PaymentStore`, and LDK claim state. Persist event updates before acknowledging
   them; a failed write must leave the event replayable.

5. **Payment acceptance.** Add `PaymentClaimable` checks before claiming funds.
   Check cancellation and duplicate
   counters through the reservation path above. Reject invalid payments through
   the existing failure path. Do not recheck invoice-request windows here.

   These checks control payment acceptance. Preventing future invoice issuance
   requires an earlier LDK request-handling integration.

6. **Successful payments.** Handle `PaymentClaimed`: clear only the matching
   reservation and update paid progress once. Replayed or older events must not
   overwrite newer progress, and late success must preserve cancelled status.

7. **Cancellation.** Handle `RecurringOfferCancelled` through the same mutation
   path, including when no record exists yet. If cancellation wins first, reject
   new claims; if acceptance wins first, retain the accepted claim through
   cancellation.

8. **Testing.** Cover timing-context round-trip and serialization compatibility,
   store persistence, lookup/list APIs, claim acceptance, paid progress, replay,
   concurrent claims, and cancellation before or during acceptance.

---

## Outbound Recurrence

✅ marks existing implementation; the remaining points cover corrections and
missing APIs. Shared follow-up work is listed below.

1. ✅ **Outbound store.** Introduce `RecurrenceDetails`, lifecycle and attempt
   states, and TLV persistence keyed by `RecurrenceId`. Load records during node
   construction and pass the store to payment and event handlers.

2. **Add lookup/list APIs.** Expose recurrence IDs, status, paid progress, and
   current attempts. Let callers recover records after restart or an initiation
   error, without directly mutating stored state.

3. **Initiation.** Add `initiate_recurrence` to submit the first invoice request
   and record the relationship and payment attempt. Retain the original offer,
   payment parameters, initial start, and any explicit basetime.
   
   FIX: Validate amount and quantity against the offer. Calculate
   the default total with checked multiplication. Record submission failures
   without advancing the recurrence counter. Use the reservation helpers to
   persist the initial attempt before submitting its request.

4. ✅ **Manual next payment.** Add `pay_next_recurrence` using the stored offer
   and continuity state. Require a successful initial payment, an active
   relationship, no active attempt, and an open payment window. Use the shared
   reservation/submission helpers.

5. ✅ **Manual retry.** Add `retry_recurrence` for failed initial or subsequent
   attempts. Submit a fresh payment ID for the same counter without advancing
   paid progress, using the shared reservation/submission helpers.

6. **Cancellation.** Add `cancel_recurrence` to abandon the active attempt and
   record local cancellation. After a successful payment, queue a cancellation
   request carrying the relationship's continuity state.
   
   FIX: Abandon the active attempt but retain its payment ID.
   Record late success while preserving `Cancelled` status. Replayed events must
   not count a payment twice or overwrite a newer attempt. Use the same mutation
   path as submission so cancellation can prevent an unqueued reservation from
   being submitted.

7. ✅ **Successful payments.** Handle `PaymentSent` for the matching active
   attempt. Advance paid progress, retain basetime and next-state proof, clear
   the attempt, and mark completion at the inclusive recurrence limit. Persist
   the update before acknowledging the event; request replay on write failure.

8. ✅ **Failed payments.** Handle `PaymentFailed` for the matching active attempt.
   Retain its ID as failed without advancing paid progress, and request event
   replay if the recurrence update cannot be persisted.

9. **Testing.** Cover store persistence, lookup/list APIs, initiation and quantity
   scaling, manual payments and retries, payment-event replay, concurrent
   submissions, and cancellation with late success.

---

## Shared

1. **Restart reconciliation.** Add reconciliation for unfinished outbound attempts
   and inbound claims using restored LDK state and replayed events. Preserve
   cancellation and apply progress only once. Missing records or events alone
   must not justify retrying a payment or clearing a reservation. Until an outcome
   is established, retain the reservation.

2. **Time-based scheduler.** Introduce periodic reconciliation for both directions
   in the third PR. Mark unpaid expected counters missed after their windows
   close, accounting for pending claims and active attempts. For outbound
   recurrences, reconcile completion, retry failed attempts within their windows,
   and submit eligible future payments when automatic payment is enabled. Persist
   that setting, reuse each direction's reservation and mutation helpers, and
   respect node startup and shutdown. Earlier PRs provide manual operations and
   event handling; periodic behavior is introduced here.

3. **Expose APIs through UniFFI.** Export outbound recurrence operations and
   automatic-payment configuration, plus lookup/list APIs for both directions
   once their Rust APIs exist. Expose their public records, statuses, identifiers,
   and errors, including the inbound composite key.

4. **Testing.** Cover restart reconciliation, scheduler timing and races,
   missed/completed transitions, and UniFFI bindings. Exercise persistence
   failures and crashes at reservation, submission, claim, and event-update
   boundaries, then verify end-to-end recurring payments.
