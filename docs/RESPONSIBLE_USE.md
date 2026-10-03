# Responsible use

> *Investigate public evidence, verify sources, protect privacy, and never turn an AI inference into an identity
> claim.*

This guide explains how Angel Engine is meant to be used and why it behaves the way it does. The binding texts
shown to users are the **Acceptable Use Policy** and **Responsible Use & Methodology** in
`backend/src/angel_engine/legal/` (templates for counsel to review); this page adds practical guidance for
investigators, supervisors and the organizations that deploy the platform.

## Before you start

- **Purpose.** Write down what you need to find out and why (at least 50 characters), specifically enough that a
  colleague or supervisor could judge whether a given search serves it. The purpose is screened like every request.
- **Lawful basis and authorization.** Record the legal basis and, where one exists, the reference of the
  assignment, contract, court order or editorial approval.
- **Necessity and proportionality.** Prefer the least intrusive source that answers the question. Organizations,
  websites, documents and events rarely require information about private individuals.
- **Individuals.** If the subject is a person, the investigation needs a supervisor's approval and then runs in
  **restricted mode**: stricter redaction, no contact or location details, fewer sources, profile lookups only with
  a written note and approval, no reverse-image search, and promotions to *confirmed* or *corroborated* by a
  supervisor other than the finding's author. Public figures are researched in their **public role** (office,
  company, publications), not their private life.

## What Angel Engine will not do

Requests in these categories are refused, with lawful alternatives where one exists:

| Category | Examples of what is refused | What you can do instead |
|---|---|---|
| Home address / location tracking | Where someone lives, their routine, real-time whereabouts, the exact place a selfie was taken | Registered office of an organization; the broad region an image shows; where an event was reported |
| Facial identification | Who the person in a photo is; matching faces across images | Text, logos, landmarks, signage and metadata; where else the image was published (with approval when people are visible) |
| Private contact information | Personal phone numbers or e-mail addresses | Published press or organizational contacts |
| Harassment, doxxing, surveillance | Unmasking an account holder, monitoring a person's posts | Research the content and its spread, not the person |
| Sensitive attributes | Sexual orientation, religion, ethnicity, health, political opinions, immigration status of individuals | None — these inferences are not offered |
| Privacy circumvention / restricted data | Private profiles, paywalls, logins, breach dumps, leaked credentials | Public archives and official records; references the investigator reviews manually |
| Impersonation | Fake personas or deceptive accounts | — |

Repeated refused requests are flagged for administrator review and can lead to suspension. If a refusal is
wrong, explain the legitimate need to your supervisor; do not rephrase the request to get around the screening.

## Collecting

- Use the connectors: they only query official APIs and pages that allow automated access, identify themselves
  honestly and respect rate limits. Pages behind logins, paywalls or robots exclusions become references for you
  to review manually — within your organization's rules and the site's terms.
- Search-engine results are **leads**, not evidence. Capture the pages that matter; let the rest expire.
- Do not paste personal data you do not need into notes, purposes or report sections. Redaction is a safety net,
  not permission.
- Treat everything you collect as untrusted: pages can be manipulated, including to mislead AI tools.

## Images

- Upload only images you are legally authorized to investigate.
- Faces are detected only so they can be blurred: *"A face was detected in the image. Angel Engine does not
  perform facial identification."* Do not try to identify people by other means inside the platform, and do not
  describe people's appearance as a way to identify them.
- Metadata can be edited or stripped; its presence or absence proves nothing on its own. GPS coordinates are
  reduced to country and region on purpose.
- Duplicates and visually similar images show **where an image appears**, not who is in it. Note the earliest
  credible appearance and its source, and consider re-uploads, crops and edits.

## Verifying

Every finding reads **Source → Finding → Evidence → Timestamp → Confidence → Verification Status**.

- **Provenance never changes.** A claim that came from a source stays *source-reported*; one that came from the AI
  stays an *AI hypothesis* in its history, even after verification.
- **Confirmed by source** means an authoritative source *directly states* it — not that it is likely.
- **Corroborated** needs two **independent** origins. Syndicated copies, wire stories, mirrors and pages citing each
  other count once; Angel Engine suggests such dependencies, but you are responsible for the independence attestation.
- **Contradicted** wins until every contradiction is resolved or dismissed with a reason. Different definitions
  (for example founding date vs. registration date) are not contradictions — say which definition you use.
- **Timestamps** have a basis (captured, published, event) and a precision (day, month, year). Do not report more
  precision than the evidence has; convert time zones explicitly.
- **Confidence** describes analytical certainty and must state its basis (for example an OCR score). It is never
  used for identity-related or sensitive findings.
- Absence of evidence is not evidence of absence, especially in incomplete public sources.

## Using the AI assistant

- The assistant only sees evidence from the current investigation (excluding items flagged sensitive) and must cite
  it. Check every citation: open the evidence and read the quoted text in context.
- Text without a citation is labelled *uncited AI commentary*. Do not copy it into findings or reports as fact.
- *"Insufficient public evidence to establish this conclusion."* is a valid, useful answer. Do not re-prompt until
  you get a different one; collect better evidence instead.
- Accepted AI proposals become **AI hypotheses**. They need independent evidence and a human status change before
  they can be presented as established.
- The assistant never identifies people in images; requests to do so are refused.

## Reporting

- Reports are built from verified data; claims without citations move to *Unverified claims*, AI hypotheses are
  labelled, and limitations (missing keys, blocked sources, metadata gaps, faces present but not identified) are
  listed automatically. Keep them — they are part of an honest report.
- Write about evidence, not about people's character or private lives. State what the evidence shows, how strongly,
  and what it does not show.
- A finalized report is locked and hashed; corrections go into a new report that explains what changed.
- Exports leave the platform's protections. Share them only with people entitled to see them and delete local
  copies when no longer needed.

## Retention and deletion

- Close investigations when the work ends; closed investigations are archived and later deleted automatically
  unless a legal hold applies.
- Delete what you no longer need: individual images (files only, or everything derived from them), evidence, or
  the whole investigation. Deletion destroys the investigation's encryption key, so it cannot be undone.

## For organizations deploying Angel Engine

- Appoint supervisors who are independent of the investigators they approve, and give them time to review.
- Train users on this guide and the Acceptable Use Policy before granting access; record that training.
- Have auditors review the audit log and refusal flags regularly, and verify the audit chain.
- Publish the Responsible Use page (the connectors' User-Agent links to it) and a real contact address, and
  respond to abuse reports and data-subject requests promptly.
- Review the legal templates with counsel for every jurisdiction you operate in, and keep the terms of the
  third-party APIs you enable under review.
- Decide in advance what you will do if the platform is misused: who investigates, who can suspend access, and how
  affected people are informed.

## Reporting misuse

Anyone — including people who believe they are being investigated — can use the public **Report abuse** page.
Reports are encrypted, triaged by administrators and supervisors, and can lead to legal holds, suspension or
deletion of investigations, and suspension of accounts.
