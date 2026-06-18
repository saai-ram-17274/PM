# Blast Radius in Response Actions

## Purpose

This note explains what blast radius means when choosing a containment action in V6.

## What it is

Blast radius is the potential negative impact or unintended consequence if an action is executed incorrectly or has side effects.

It is not the impact of the attack. It is the impact of the analyst's chosen response.

## Three levels

### High Risk

**High risk actions change system state broadly and affect many users or systems.**

Examples:
- Disable a user account (affects everyone who depends on that user)
- Network-isolate a host (affects all users on that host)
- Block an IP or ASN at the firewall (affects all traffic from that range)
- Block an app tenant-wide (affects all users relying on that app)

High risk actions:
- Are reversible in some cases, but reversal takes time
- May disrupt legitimate business operations
- Require confirmation before execution
- Should be used when the threat is clear and containment is urgent

### Medium Risk

**Medium risk actions disrupt active sessions or processes but are more targeted.**

Examples:
- Force password reset (users must log back in)
- Kill suspicious processes (may terminate legitimate child processes)
- Revoke OAuth consent (blocks app access temporarily)
- Kill process tree (affects related processes)

Medium risk actions:
- Are usually reversible or have minimal side effects
- May cause temporary service disruption
- Do not require confirmation in most cases
- Are useful for disrupting active attacker activity

### Low Risk

**Low risk actions are read-only, informational, or metadata-only.**

Examples:
- Investigate entity (no state change)
- Collect forensics (no system change)
- Run AV scan (may find issues but doesn't block)
- Add to threat-intel feed (administrative tagging)
- Notify manager (informational only)

Low risk actions:
- Do not change system state or user access
- Have no negative side effects if executed
- Are always safe to take
- Are useful for investigation, evidence collection, and escalation

## How to use it

When choosing a response action:

1. Read the action's blast radius first.
2. Use **high risk** actions only when:
   - The threat is clear and confirmed
   - Containment is urgent
   - The analyst is certain about the target
   - Business impact can be managed

3. Use **medium risk** actions when:
   - Active attacker activity is occurring
   - Containment is needed but confirmation is not required
   - Side effects are acceptable

4. Use **low risk** actions when:
   - Investigation is ongoing
   - Evidence collection is needed
   - Escalation or notification is required

## Practical rule

- **High risk** = act only when you are sure
- **Medium risk** = act when active threat is present
- **Low risk** = act anytime for investigation or evidence

