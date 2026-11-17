import type { AuditAction, AuditActorKind, AuditTargetKind } from "@antireverse/protocol";
import type { MessageKey } from "@/lib/t.ts";

/** Each audit action in readable words. A record over the protocol's closed list: a new action fails to compile. */
export const ACTION_LABEL: Readonly<Record<AuditAction, MessageKey>> = {
  "organization.create": "audit.action.organization.create",
  "app.create": "audit.action.app.create",
  "build.register": "audit.action.build.register",
  "assessment.create": "audit.action.assessment.create",
  "finding.ignore": "audit.action.finding.ignore",
  "finding.reopen": "audit.action.finding.reopen",
  "policy.publish": "audit.action.policy.publish",
  "policy.rule.promote": "audit.action.policy.rule.promote",
  "policy.rollback": "audit.action.policy.rollback",
  "patch.promote": "audit.action.patch.promote",
  "patch.demote": "audit.action.patch.demote",
  "incident.acknowledge": "audit.action.incident.acknowledge",
  "incident.resolve": "audit.action.incident.resolve",
  "containment.create": "audit.action.containment.create",
  "containment.lift": "audit.action.containment.lift",
  "allowlist_entry.create": "audit.action.allowlist_entry.create",
  "allowlist_entry.delete": "audit.action.allowlist_entry.delete",
  "alert_channel.create": "audit.action.alert_channel.create",
  "alert_channel.delete": "audit.action.alert_channel.delete",
  "alert_channel.test": "audit.action.alert_channel.test",
  "alert_recipient.resend": "audit.action.alert_recipient.resend",
  "target.create": "audit.action.target.create",
  "target.delete": "audit.action.target.delete",
  "target.verify": "audit.action.target.verify",
  "rules_of_engagement.sign": "audit.action.rules_of_engagement.sign",
  "organization.export": "audit.action.organization.export",
  "organization.deletion.request": "audit.action.organization.deletion.request",
  "organization.deletion.cancel": "audit.action.organization.deletion.cancel",
  "subject.export": "audit.action.subject.export",
  "subject.erase": "audit.action.subject.erase",
  "organization.retention.update": "audit.action.organization.retention.update",
  "campaign.create": "audit.action.campaign.create",
  "campaign.stop": "audit.action.campaign.stop",
  "campaign.start": "audit.action.campaign.start",
  "campaign.end": "audit.action.campaign.end",
  "campaign.refuse": "audit.action.campaign.refuse",
  "campaign.operator_kill": "audit.action.campaign.operator_kill",
  "campaign.operator_suspend": "audit.action.campaign.operator_suspend",
  "campaign.operator_resume": "audit.action.campaign.operator_resume",
};

/** What an entry's target is, in readable words. */
export const TARGET_LABEL: Readonly<Record<AuditTargetKind, MessageKey>> = {
  organization: "audit.target.organization",
  app: "audit.target.app",
  build: "audit.target.build",
  assessment: "audit.target.assessment",
  finding: "audit.target.finding",
  policy: "audit.target.policy",
  patch: "audit.target.patch",
  incident: "audit.target.incident",
  containment: "audit.target.containment",
  allowlist_entry: "audit.target.allowlist_entry",
  alert_channel: "audit.target.alert_channel",
  alert_recipient: "audit.target.alert_recipient",
  target: "audit.target.target",
  rules_of_engagement: "audit.target.rules_of_engagement",
  organization_deletion: "audit.target.organization_deletion",
  subject: "audit.target.subject",
  campaign: "audit.target.campaign",
};

/**
 * Who acted, in words (slice 15a). An admin key is named by its id beside the word; the system (a Campaign the API
 * started, ended or refused) and the operator have no key.
 */
export const ACTOR_LABEL: Readonly<Record<AuditActorKind, MessageKey>> = {
  admin_key: "audit.actor.key",
  system: "audit.actor.system",
  operator: "audit.actor.operator",
};
