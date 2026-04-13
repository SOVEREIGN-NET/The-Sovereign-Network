# SOV, CBE, and SOVRN — Token Architecture

*Event-Driven Model — Canonical Reference*

---

## The three tokens and what they are

The Sovereign Network has three tokens. They have distinct roles and must not be conflated.

SOV is the sovereign reserve token. It is the network's base layer — the settlement currency, the unit of account, the token that every DAO on the network relates to. SOV is not created by a team decision at genesis. It is minted when CBE deposits flow through the on-ramp and generate value for the SOV treasury. Its price is determined by the net asset value of the SOV treasury divided by circulating SOV supply.

CBE is the first for-profit DAO on the Sovereign Network. It exists to bootstrap SOV into existence. CBE is the input token of the on-ramp — buyers acquire CBE and deposit it. SOV mints as the output. CBE is not a general-purpose currency. It is the engine of the bootstrap phase. It has its own price floor, its own reserve, its own liquidity pool, and its own path to graduation onto the AMM.

SOVRN is the audit instrument. It has one purpose: to make the pre-graduation liquidity accumulation cryptographically auditable and to prove at graduation that the AMM opening price for CBE is legitimate — derived from real accumulated value, not set by the team. SOVRN mints during the bonding curve phase and burns at graduation. After graduation it does not exist. Its job is complete.

---

## The on-ramp — the only minting event

Every CBE token that enters the system goes through the on-ramp. There is no other path. The on-ramp executes a deterministic split every time a buyer deposits CBE. The split happens in two stages.

The first split divides the deposit into two pools:

20% goes to the SOV treasury. This is the network tax — the cost of operating a for-profit DAO on the Sovereign Network. It is held in the SOV treasury as CBE tokens. It is not swapped into SOV at the moment of deposit. The SOV treasury accumulates CBE tokens, and the value of those CBE holdings — marked to the current CBE price — is what constitutes the SOV treasury's net asset value.

80% stays within the CBE economy to back the token and fund its graduation.

The second split divides that 80% into two further pools:

40% of the 80% — which equals 32% of the original gross deposit — goes into the CBE strategic reserve. This reserve is locked. It is the backing that makes the CBE floor price real. It never leaves the reserve through any discretionary action. The only thing that can draw from it is a holder selling CBE back through the bonding curve, which redeems from the reserve at the current floor price.

60% of the 80% — which equals 48% of the original gross deposit — goes into the CBE liquidity pool. This pool is liquid during the bonding curve phase in the sense that it accumulates, but it is not accessible to anyone until graduation. At graduation it becomes the CBE side of the AMM seed.

Written out from a deposit of 100 CBE:

- 20 CBE go to the SOV treasury.
- 32 CBE go to the CBE strategic reserve — locked.
- 48 CBE go to the CBE liquidity pool — accumulating toward graduation.
- Total: 100 CBE. Nothing is lost. Everything is accounted for atomically.

Every single on-ramp deposit fires five things simultaneously. The CBE floor price rises because the locked reserve grew. The SOV treasury NAV grows because it holds more CBE at the current CBE price. SOV mints against the 20 CBE deposited, priced at the current SOV NAV model. SOVRN mints against the 48 CBE that entered the liquidity pool, valued at the current CBE price — this is the real-time audit record. And graduation advances because the liquidity pool is larger and the SOVRN accumulation is higher.

There is no neutral action in this system. Every deposit moves every relevant number in the correct direction.

---

## CBE price — the floor and the curve

During the bonding curve phase, CBE has a hard mathematical floor:

```
Floor price = locked reserve / circulating CBE
```

The locked reserve is built by the 32% that goes in on every deposit. Circulating CBE grows as more tokens are minted through on-ramp activity. The floor rises monotonically with every deposit because the reserve always grows in proportion to the new circulating supply. No deposit can lower the floor. No market action can break through it — the reserve is always there to redeem at the floor price for any seller who chooses to exit.

The floor is not a target price. It is the protocol's solvency guarantee. The market price of CBE trades above the floor based on demand, speculation, and network momentum. But the floor is always real, always computable from on-chain state, and always backed by actual locked CBE in the reserve.

---

## SOVRN — audit instrument and graduation proof

SOVRN mints on every on-ramp deposit, against the 48% that flows into the liquidity pool. The mint quantity is not just the number of CBE tokens deposited — it is those tokens multiplied by the current CBE price at the moment of deposit. This makes SOVRN a value-weighted audit record, not just a quantity counter. Early deposits when CBE price is low contribute less SOVRN per token. Later deposits when CBE price is higher contribute more. The total SOVRN supply at any moment is the cumulative record of how much value has flowed into the liquidity pool across the entire history of the bonding curve phase.

Every block, the Sovereign Network's 21 validators non-repudiably attest to the chain's state root through the tension chain. The state root includes SOVRN total supply. This means the SOVRN accumulation record is not a number the team reports — it is a number that 21 validators have cryptographically proven they know, in sequential order, each validator proving they saw every prior validator's acknowledgment before adding their own signature. The audit is structural, not administrative.

At graduation, SOVRN burns. The burn event is what proves the AMM opening price for CBE is legitimate. Without SOVRN, the AMM seed ratio is a team decision — a number chosen at the moment of graduation that participants must trust. With SOVRN, the AMM seed ratio is the mathematical output of every deposit that ever occurred, weighted by the CBE price at the time of each deposit, audited in real time across the entire bonding curve phase.

The AMM opens at P(S graduation) — the final output of the bonding curve's piecewise linear price formula at the total supply accumulated. The liquidity pool CBE balance becomes the CBE side of the AMM. The SOV equivalent at P(S graduation) becomes the SOV side. The pool is permanently locked as protocol-owned liquidity. The SOVRN burn is the proof that this seeding is honest. After graduation SOVRN does not exist. The AMM is now the price truth for CBE.

---

## SOV — how it is valued

SOV price is the net asset value of the SOV treasury divided by circulating SOV supply:

```
SOV price = SOV treasury NAV / SOV circulating supply
```

The SOV treasury NAV is the sum of all assets it holds, marked to their current market prices. At the start this is primarily CBE tokens accumulated as the 20% on-ramp tax. As more DAOs join the Sovereign Network and each pays its 20% tax in its native token into the SOV treasury, the NAV grows into a diversified portfolio. SOV is not a bet on CBE alone — it is a bet on every productive DAO that operates on the network.

Because the SOV treasury holds CBE, and CBE has a hard floor from its locked reserve, SOV inherits that floor transitively. The minimum SOV price is computable from the CBE floor price multiplied by the CBE quantity held by the SOV treasury, divided by circulating SOV supply. This gives SOV a protocol-derived minimum valuation that requires no external price oracle — it is entirely on-chain.

SOV mints when CBE deposits flow into the SOV treasury through the on-ramp. The genesis price of SOV is $0.10 — a one-time protocol decision. From that point forward every SOV mint is priced at the current NAV model. The minting formula is the 20 CBE deposited multiplied by the current CBE price divided by the current SOV price. This keeps SOV supply growth proportional to the real value being contributed to the treasury.

---

## Payroll — Option A: pre-funded at pool creation

Compensation in this system is denominated in CBE. The problem that must be solved is that vesting events — when CBE moves from an unvested pool to an employee's wallet — increase circulating supply without increasing the locked reserve. If the reserve does not grow when supply grows, the floor price drops. Every payroll payment without reserve backing is a small attack on the protocol's solvency invariant.

Option A solves this by making the compensation pool creation itself an on-ramp event. The DAO does not simply declare that 500,000 CBE exist for compensation. It runs 500,000 CBE through the on-ramp protocol at the moment governance approves the pool. The full split executes: 100,000 CBE go to the SOV treasury, 160,000 CBE go into the locked reserve, 240,000 CBE go into the liquidity pool, SOVRN mints against the 240,000 CBE at the current CBE price, and SOV mints for the DAO against the 100,000 CBE treasury deposit.

Then 500,000 CBE are minted into an unvested register — a separate accounting category invisible to the floor price formula. The circulating supply does not increase. The floor price does not move. The reserve is already funded before a single token reaches any employee.

When vesting events occur — monthly, on a cliff, or on milestones — the ProcessPayroll transaction moves CBE from the unvested register to the circulating register and into the employee's wallet. The locked reserve does not change at vesting because it was pre-funded at pool creation. The floor price drops slightly at each vesting event — because circulating supply grows while the reserve stays flat — but this drop is small, predictable, pre-announced in the vesting schedule, and priced in by the market long before it occurs.

The critical property of Option A is that all the price momentum of the compensation fires at governance approval. The moment the DAO commits to paying someone, the liquidity pool advances, SOVRN mints, the reserve grows, and graduation moves closer. The team's compensation is a protocol advance — not a drain on the system. The employee receives CBE that was properly backed by the reserve at the moment they were hired.

---

## Pre-minted model — why it fails

Under a pre-minted model all tokens exist at genesis. The consequences are immediate and structural.

CBE has a floor price of zero. The locked reserve is empty because the on-ramp never ran. Every CBE token in existence was created by fiat. The solvency invariant — the entire value proposition of the bonding curve — does not exist from day one.

SOV at $0.10 is a team claim with nothing behind it. The treasury holds nothing because no deposits have occurred. Any sell pressure below $0.10 has no floor to catch it.

SOVRN cannot do its job. Its defined purpose is to audit the 48% liquidity accumulation as it builds through real sequential deposits, then burn at graduation to prove the AMM genesis price is legitimate. Under pre-mint, the liquidity pool was filled at genesis — not earned through deposits. There is no accumulation to audit. The SOVRN burn at graduation proves nothing. The AMM opening price is a team decision, not a protocol proof.

Payroll under pre-mint is a transfer from a pre-existing pool. The bonding curve does not run. The reserve does not grow. The floor drops with every payment. The team is paid in tokens that structurally weaken the protocol each time compensation is issued.

Price momentum under pre-mint is zero. Supply is fully diluted from genesis. Every on-ramp deposit, every transfer, every governance event, every DAO joining the network — none of it creates supply-side price pressure because the supply is already fully diluted. The protocol's growth is invisible in its token prices.

---

## The five simultaneous forces — event-driven only

The event-driven model is the preferred design because every protocol event moves multiple numbers simultaneously in the correct direction. This is what price momentum means in this context — not speculative momentum driven by market sentiment, but mathematical momentum encoded in the protocol's own minting mechanics.

On every on-ramp deposit: the CBE floor rises, the SOV treasury NAV grows, SOV price rises as NAV outpaces minted supply, graduation advances as the liquidity pool grows, and SOVRN audits the accumulation in real time. On every payroll pool creation under Option A: all five forces fire at the moment of governance approval, not spread across 48 monthly vesting events. On every new DAO that joins the network and pays its 20% tax: SOV treasury NAV grows and SOV price rises. On graduation: SOVRN burns and proves the AMM price is honest, the liquidity pool becomes permanent protocol-owned liquidity, and CBE transitions from a floor-backed bonding curve token to a freely traded AMM token with a provable starting price.

No action in the event-driven model is neutral. Every deposit, every pool creation, every governance decision that touches token mechanics simultaneously advances the protocol across all five dimensions. That is the design.
