/**
 * Effect Schema codecs for evidence events. These are the machine-readable
 * half of `docs/EVIDENCE_FORMAT.md`: consumers decode untrusted journal lines
 * into typed events, and producers get the field contract in one place. The
 * verifier (`Verify.ts`) performs its own per-code checks on top, because a
 * chain break and a missing field are different findings, not one parse error.
 */
import { Schema } from "effect";

const SharedFields = {
  schema_version: Schema.String,
  event_type: Schema.String,
  event_id: Schema.String,
  timestamp_utc: Schema.String,
  key_id: Schema.String,
  event_hash: Schema.String,
  signature: Schema.String,
};

const ActionFields = {
  action_id: Schema.String,
  action_name: Schema.String,
  contract_hash: Schema.String,
};

export const DecisionEvent = Schema.Struct({
  ...SharedFields,
  ...ActionFields,
  decision: Schema.Literal("allowed", "denied"),
  risk: Schema.String,
  approval_mode: Schema.String,
  redacted_input_summary: Schema.String,
  input_hash: Schema.String,
});

export const OutcomeEvent = Schema.Struct({
  ...SharedFields,
  ...ActionFields,
  status: Schema.Literal("succeeded", "failed"),
  decision_event_id: Schema.String,
});

export const CheckpointEvent = Schema.Struct({
  ...SharedFields,
  checkpoint_count: Schema.Number,
  head_sha256: Schema.Union(Schema.String, Schema.Null),
});

export const ResolutionEvent = Schema.Struct({
  ...SharedFields,
  ...ActionFields,
  decision_event_id: Schema.String,
  resolution: Schema.Literal("confirmed_completed", "confirmed_not_completed"),
  note: Schema.String,
});

export const CountersignatureEvent = Schema.Struct({
  ...SharedFields,
  checkpoint_event_id: Schema.String,
  checkpoint_count: Schema.Number,
  head_sha256: Schema.Union(Schema.String, Schema.Null),
});

export const ArchiveEvent = Schema.Struct({
  ...SharedFields,
  prior_count: Schema.Number,
  prior_head: Schema.Union(Schema.String, Schema.Null),
  archived_path: Schema.String,
});

export const RotationEvent = Schema.Struct({
  ...SharedFields,
  prior_key_id: Schema.String,
  successor_key_id: Schema.String,
  successor_fingerprint: Schema.String,
});

export type DecisionEvent = typeof DecisionEvent.Type;
export type OutcomeEvent = typeof OutcomeEvent.Type;
export type CheckpointEvent = typeof CheckpointEvent.Type;
export type ResolutionEvent = typeof ResolutionEvent.Type;
export type CountersignatureEvent = typeof CountersignatureEvent.Type;
export type ArchiveEvent = typeof ArchiveEvent.Type;
export type RotationEvent = typeof RotationEvent.Type;
