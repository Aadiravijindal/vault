# Employee Privacy Mode

**A button.** Click it, pick your country, and Vault reconfigures itself to be lawful
there — and generates the compliance pack.

```bash
vault privacy preview de     # exactly what changes, before anything changes
vault privacy apply de
vault privacy pack           # the documents, ready for the DPO or the works council
```

## The presets

| | Preset | Ships |
|---|---|---|
| | `off` | full visibility (US at-will default) |
| 🇬🇧 | `uk` | UK GDPR + DPA 2018, ICO-format DPIA, LIA, transparency notice, IDTA — 5 documents |
| 🇩🇪 | `de` | everything in EU plus §87(1) no. 6 BetrVG readiness — 5 documents |
| 🇦🇹 | `at` | Austria, works council |
| 🇳🇱 | `nl` | Netherlands, works council |
| 🇸🇪 | `se` | Sweden, co-determination |
| 🇫🇷 | `fr` | France, CSE |
| 🇪🇺 | `eu` | EU baseline |
| 🇮🇳 | `in` | DPDP — Consent Manager, 1-year security log retention, SDF obligations |
| 🇺🇸 | `us_strict` | CA/CO/CT incl. CPRA ADMT |
| 🇨🇦 | `ca` | PIPEDA, provincial variants, Quebec Law 25 |
| 🌍 | `global_strictest` | the union of all of them |

**Preview before apply** shows which screens disappear, which fields get
pseudonymised, which retention shortens, and who gets notified.

## What ON actually does

| Control | Behaviour |
|---|---|
| **No individual dashboards** | no screen anywhere shows one named employee's AI activity. **Architecturally absent, not permission-gated** — the query does not exist. |
| **Aggregate-only analytics** | department minimum, with a **k-anonymity floor** (default k=5). Below the floor no number renders at all. |
| **Pseudonymised by default** | identity replaced with a rotating token. Re-identification needs two named approvers, a stated legal reason and a time box, and is itself receipted. |
| **Purpose lock** | memory governance only. Cannot be queried for performance, productivity, discipline or promotion — enforced in the query layer. |
| **No affect analysis, ever** | no sentiment, mood, stress, engagement, motivation or honesty scoring. **Not a config option — the code does not exist**, and asking for it raises `wall_violation`. Emotion recognition at work has been prohibited in the EU since February 2025. |
| **No productivity scoring** | no output counts per person, no speed rankings |
| **Excluded contexts** | personal accounts and email · union and works-council communications · health and banking portals · legal advice · breaks · outside working hours · personal devices |
| **Sample, don't stream** | event-triggered capture. Minimisation is the default posture. |
| **No covert monitoring** | every capture is disclosed. Covert mode does not exist. |
| **Shortened retention** | employee-linked data expires faster than customer data |
| **Employee transparency portal** | the **My Data** screen — see everything held about you, export it |
| **Objection channel** | a formal route to challenge a fact about yourself, with a tracked response |
| **Works-council role** | a named non-management role with visibility into policy changes and retention, and a formal objection channel |
| **Change notification** | any change to a monitoring-relevant setting notifies employee reps automatically |

## 🇬🇧 UK, specifically

UK GDPR + DPA 2018 basis with a pre-generated **LIA**. ICO Employment Practices
alignment — proportionality, necessity, transparency, least-intrusive-means, all
documented. **ICO-format DPIA**, pre-filled, ready for the DPO to sign. Employee-facing
transparency notice in UK wording. DSAR workflow on the UK 1-month clock with extension
tracking. UK-only storage and UK keys. IDTA / Addendum generated per flow. 72-hour ICO
breach clock. **Covert monitoring disabled entirely** — UK guidance permits it only in
narrow criminal-suspicion cases, which Vault does not support. Art 22 safeguards, and
Vault never makes an employment decision, in writing.

The UK has no statutory co-determination, but the consultation pack still ships,
because unions and staff forums exist and the ICO expects consultation evidence.

## 🇩🇪 Germany, specifically

The strictest preset, and the one that unblocks Europe. Everything in EU baseline plus:

- **A pre-drafted Betriebsvereinbarung** — purpose, scope, retention, access matrix,
  prohibited uses, deletion, dispute process, term
- **§26 BDSG** written necessity and proportionality assessment
- **Works council portal** — the Betriebsrat gets a read-only role and a veto-tracked
  change process
- **Einigungsstelle-ready documentation**, assembled in advance
- **Prohibited-by-design list, in German**, for the works council to read
- **No individual performance visibility at all.** Not to HR. Not under break-glass.

Bringing a first draft of the works agreement to the table is what turns an 18-month
blocker into a 6-week approval.

---

# Delete vs keep

The sharpest legal hook in the product, because it is a live conflict that nobody else
resolves on screen.

```
[ Erase person ] Rodriguez, M.          request REQ-2026-0881

  FOUND   8 facts · 3 conversations · 2 support transcripts · 1 recording
          4 masked PII tokens · 12 read-log entries · 2 derived facts
          1 summary · 3 backup generations · 1 archive-tier object
          → reaches the TRANSCRIPTS, not just the tidy summaries

  CONFLICT ⚠️
    4 items are under legal hold on a DIFFERENT matter (Case 2026-114).
    Privacy law says delete. Retention law says keep.

    VAULT'S ANSWER
    → the 4 held items are LOCKED but MINIMISED to the least the hold
      actually requires (other fields crypto-shredded)
    → a written record: which law, which matter, whose decision, when
    → they auto-delete the instant the hold lifts
    → the data subject gets a written explanation of the deferral
```

Method per location: facts and transcripts hard-deleted · indexes purged and rebuilt ·
caches invalidated · **backups crypto-shredded** (key destroyed, which is the only
honest way to prove deletion from immutable backups) · archive tier tombstoned ·
read logs keep the event but pseudonymise the subject · derived facts regenerated
without them · connected third parties sent a propagation request and confirmed.

Every erasure produces a signed, independently verifiable receipt: what was found by
count and category (**never content**), what was deleted and from where, the method per
location, what was retained and the specific legal basis, when, by whom, under what
request ID. Machine-readable and human-readable.
