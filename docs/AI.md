# The model layer

**The model may arrange the memory. It may never decide who can read it.**

Everything in this document is optional. With no model configured, filing uses
deterministic rules, answers are composed from retrieved facts, and every screen says
which path produced its result. An air-gapped install loses wording, never correctness.

---

## Where the model runs

Three providers. The local one is the recommendation, not the fallback.

| | Runs on | API key | Timeout | Every classified claim |
|---|---|---|---|---|
| `ollama` | your hardware | none | 120s | stays in the building |
| `anthropic` | Anthropic | required | 8s | sent to a third party |
| `openai` | OpenAI | required | 8s | sent to a third party |

That last column is the whole decision. Classifying a payroll line or a privileged
legal note with a hosted model is a **disclosure** — somebody in a regulated estate has
to sign it off — not a latency question. Ollama removes the conversation entirely.

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve
ollama pull mistral:7b-instruct          # ~4GB, one time, no GPU required
export VAULT_MODEL_PROVIDER=ollama       # no API key needed

npm run model -- --probe                 # is it configured, and is it actually there?
```

`VAULT_MODEL_URL` points at any host on your network, so one GPU box can serve the
estate. `VAULT_MODEL` overrides the model. A 7B instruct model at 4-bit runs on a
laptop and files well enough to route a sentence into one of a dozen folders; bigger
models file better.

**`available` is not `reachable`.** The first says the configuration is complete. For a
local model that is much weaker than it sounds — `ollama serve` may not be running, the
weights may never have been pulled — so `--probe` is a separate question that costs a
round trip, and failures name both causes rather than reporting a bare 404.

---

## Why the model never blocks a write

The gate publishes a latency budget (p50 80ms, p95 250ms) and `ingest()` is synchronous.
A model call is hundreds of milliseconds hosted and seconds locally. Putting one inside
the gate would trade a hard guarantee for a soft one, and would mean **a model outage
became a write outage**.

So the order is:

```
message → gate (10 checks, ~80ms) → filed by rules → SAFE
                                          ↓
                                    later, off the write path
                                          ↓
                       memory recall (µs) → model call (only if needed) → refined
```

A fact is never unprotected while it waits. It is already inside a folder, already
behind that folder's wall, already labelled. The model can only move it somewhere else
that exists, or raise its label.

---

## What makes it fast: the memory file

`data/ai-memory.vmem` — a small, signed file holding what filing has learned about
**this** company.

A model call is hundreds of milliseconds. A recall against this file is microseconds.
So filing consults the memory first and only calls the model when the memory has no
confident prior — which, after a few thousand facts, is the minority of them. The model
teaches the file; the file then answers most of the questions the model used to.

**What is in it:** token → folder associations with counts, client and project profiles,
corrections a human made, cases the model was unsure about, aggregate counters.

**What is deliberately not:** claim text. Ever. Tokens carrying three or more
consecutive digits are dropped on the way in, so a salary, an account number or a case
reference cannot survive as vocabulary. No future claim contains the same salary, so
keeping it buys nothing and would put the one part of a sentence worth stealing into the
one file in this system with no wall around it. **The file is built to be boring.**

**Why it stays small:** everything is a counter, nothing is a document. Entries decay
and the weakest are evicted at a hard cap, so the size is bounded however long it runs.
A mature file over a busy estate is tens of kilobytes.

**Why an edit cannot be hidden:** every revision is hash-chained to the last, exactly
like the ledger, and the head is signed with the customer's key. Quietly retraining the
filing to route fraud material somewhere nobody reads breaks the chain, and `verify()`
names the revision that broke. The honest claim: the chain does not *prevent* an edit,
it makes one *impossible to hide*. A valid chain with an invalid signature is reported
separately — that means the file was rebuilt by somebody without your key, which is a
different and worse finding.

**Confidence is not word-counting.** Five words matching from one past filing is five
signals but still one observation, and treating that as strong is how a single filing
becomes a confident prior that then teaches itself. Confidence combines share of the
vote, margin over the runner-up, and how many *past filings* actually back it. Three
observations reach full confidence — or one human correction, which carries five times
the weight because it is the only signal in the system known to be right.

```bash
npm run organize -- --memory      # what it knows, and about whom
```

Deleting the file costs speed and nothing else.

---

## The librarian

The model as a filing clerk with a defined job — and the interesting part of each job is
where the authority stops.

### Tags: invented freely

`client:acme corp`, `project:atlas`, `risk:high`, `topic:renewal`. Unbounded, invented on
the fly, no approval.

That is a real difference in authority from folders, and it is the actual security
property rather than an inconsistency:

> **A folder is a wall. A tag is an index.**
>
> A folder decides *who can read what*, so inventing one invents an access boundary
> nobody approved. A tag decides *what is easy to find*, and every read through a tag is
> still resolved against the folder wall underneath. A wrongly tagged fact is findable by
> the wrong search term. A wrongly foldered fact is readable by the wrong person. Only
> one of those is a breach — and the model gets full freedom on exactly the side that
> isn't.

Tags are typed (`kind:value`) because a bare `acme` is ambiguous forever — client,
project or topic? — and a vocabulary that mixes them is one nobody can search reliably.
Every tag is a new fact version, so "who tagged this `client:acme` and when" has an
answer.

### Folders: proposed, never created

When the model believes a drawer is missing it says so, with evidence: the facts that
would go in it, the wall it thinks it needs, and why the existing folders are wrong.
That proposal **queues** until a named human approves it. Then the folder exists and the
model files into it freely forever.

The regulator's question is never "did a human type the folder name". It is *"who
approved this category, and when"*. A proposal queue answers that with a name and a
timestamp. Silent creation answers it with "the model decided", which is not an answer.

The approver sets the wall, not the model. The model's suggestion is shown and ignored —
an access boundary a model chose is an access boundary nobody chose. Repeat proposals
accumulate evidence on the existing one rather than filling the queue, so an
administrator sees *"the model has wanted this for 50 facts"*, which is what makes the
decision easy.

### Notices: it tells a human, and does nothing else

Legal threats, regulator contact, security incidents, key resignations, contract losses,
money above the ordinary. The model rates significance and raises a notice.

A notice is a **message**, not an action. Nothing about the fact changes because one was
raised. The model gets to have an opinion about significance — something it is genuinely
good at — without that opinion being able to touch the record on its own. Notices quote the fact they are about, so the inbox applies the same folder wall the
fact has — **including for administrators**, because there is no admin bypass anywhere
else in this product and there is not one here.

What you cannot read is summarised rather than merely counted: which folder, how many,
how urgent, and when the latest arrived. The `why` and the excerpt stay hidden, because
those are the content the wall exists to protect; the folder and the count are metadata
about *where attention is needed*. Withholding those protects nothing and costs somebody
the ability to route the message to a person who can act on it — and *"1 notice you
cannot read"* on its own is true, useless, and quickly ignored.

### What it may never touch

| | Why |
|---|---|
| Golden facts | human-attested; that is not this path |
| Facts under legal hold | frozen, with disclosure consequences |
| Facts an administrator **locked** | "this one is right, leave it alone" |
| Anything **out of** an admin-only folder | out is always a widening |

Each is checked in the librarian **and again in the fact store**, because one check is
one bug away from not being a check — and in `refile.js`, the narrower model pass that
`refileWithModel()` still exposes. Two model paths with one guard between them is the
same as no guard: whichever one an operator runs is the one that matters.

A **lock** is the ordinary version of "don't touch this": weaker than golden (no
authority role, no four eyes), weaker than a legal hold (no legal consequence). It stops
every automated pass and nothing else — a human can still revise a locked fact
deliberately.

```bash
npm run organize                    # one pass
npm run organize -- --watch         # keep organising, no button pressing
npm run organize -- --proposals     # what it wants a decision on
npm run organize -- --approve <id> --by ciso --reason "…" --read sales
```

---

## Administrator-only folders

`admin/` ships as one, and any folder can be marked so on approval.

An administrator-only folder **replaces** the read list rather than adding to it — it is
not also readable by whoever happens to be in the right department, or the restriction
would be decorative. Agents never read one, with or without break-glass. Humans get in
by being a named administrator, or through break-glass, which needs two named humans and
logs loudly. `adminOnly` is inherited downward and a child cannot opt out.

Writes are unaffected. Filing *into* one of these is ordinary — that is how something
sensitive lands somewhere safe without a human in the loop — and it is getting things
*out* again that is controlled.

**Name at least one administrator.** An administrator-only folder on a deployment with
nobody named to read it is the one operation in this system that loses data while every
individual check passes: the write succeeds, the ledger is clean, the fact is filed
correctly, and no human or agent can ever retrieve it. So it is reported three ways —
a high finding on the Map, a warning on the Librarian screen, and an alert raised the
moment something is first written there — and the read refusal says *"nobody can"*
rather than *"you cannot"*, because sending somebody to ask an administrator who does
not exist is worse than saying nothing.

```js
new Vault({ administrators: ['ciso'] })   // or grant it through your IdP
```

---

## Ask, restricted

Natural-language questions over the whole memory are limited to administrators and
people named explicitly.

This is deliberately narrower than "may read facts". An ordinary read returns the handful
of facts somebody is cleared for. An ask ranges over everything at once, summarises, and
hands back prose — a larger disclosure, and a much easier one to paste somewhere it
should not go.

Three capabilities are tracked **separately**, not collapsed into one seniority flag:

| Capability | Grants |
|---|---|
| `privilegeCleared` | attorney-client material |
| `administrator` | administrator-only folders |
| `canAsk` | natural-language questions over the whole memory |

A lawyer needs the third and must not get the second. Collapsing them is exactly how a
lawyer ends up reading the board folder.

Every ask is journalled — permitted or refused — with the question, who asked, what was
retrieved, what was withheld, and whether a model composed the answer. The refusal names
the allowlist rather than saying "forbidden", because the person hitting it needs to know
who to go to; hiding that only means they ask around until somebody runs it for them.

---

## What the model cannot do, tested

Every one of these is driven by a deliberately hostile model response in
`test/orchestrate.test.js`, `test/localmodel.test.js` and `test/ai.test.js` — no test in
this repository reaches the network.

- **Invent a folder.** A path outside the offered set is discarded and the fact stays
  where the rules put it.
- **Lower a sensitivity label.** Raising is allowed; a proposal to lower is refused and
  recorded. A classifier may never widen access.
- **Escape the data fence.** Content is passed inside a delimiter the payload cannot
  close, and the system prompt says the delimited region is data. Both halves, locally
  and hosted alike.
- **Cite a fact that was not retrieved.** The *entire* answer is discarded and the
  deterministic one returned — an answer containing one fabricated source cannot be
  trusted on the sentences around it either.
- **Move something sensitive it is unsure about.** That goes to the review queue.
- **Turn an outage into a write outage.** Timeout, bad key, bad status, unparseable
  output and refused values all fall back to the rules.
