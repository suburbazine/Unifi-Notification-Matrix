# Conditions: what this can tell you about

**Generated from the code.** Do not edit by hand -- run
`go test ./internal/event/ -run TestTheConditionReference -update`.

A *condition* is what happened, normalised. It is the thing a rule matches on,
and the interface offers this list in the Rules editor so nobody has to guess
at it or wait for an event to fire and read it out of the log.

## What this list is, and what it is not

**It is** every condition a rule can match. Rules match this build's
vocabulary, and this is all of it.

**It is not** everything your UniFi might send. Firmware emits event types this
build does not map; those are counted as unrecognised rather than becoming a
condition, and they are exactly what gets added in a later release. To ask your
own console what it actually exposes:

```bash
notifymatrix probe
```

## How a rule uses one

A rule narrows by source, condition and entity, and any of the three may be
left empty to mean *anything*. The **entity** is a camera or door name from
your own site, so no list here can supply it -- the Rules editor suggests the
ones this daemon has actually seen events about.

A condition is also part of the stored dedup key, which is why it is a fixed
vocabulary rather than free text: the same real problem arriving by two routes
has to use the same string, or it becomes two incidents that both nag.


## Reachability and health

| Condition | Means | Comes from |
|---|---|---|
| `offline` | A device stopped being reachable -- a camera, a sensor, an Access hub, a Network device. | `protect`, `access`, `network` |
| `battery-low` | A battery-powered sensor is running out. It will stop reporting before it tells you again. | `protect` |
| `battery-connected` | A sensor went back onto external power. The clear for a battery warning. | `protect` |

## Detections

| Condition | Means | Comes from |
|---|---|---|
| `doorbell-ring` | Somebody pressed a doorbell. | `protect` |
| `motion` | Plain motion, with no judgement about what moved. On most sites this is the noisiest condition there is. | `protect` |
| `smart-detect` | Protect classified what it saw -- person, vehicle, animal, package. Which one travels in the detail, not in the condition. | `protect` |
| `loitering` | Somebody stayed in a zone longer than that camera's loitering setting allows. | `protect` |
| `audio-detect` | The camera recognised a sound it was told to listen for. | `protect` |

## Openings

| Condition | Means | Comes from |
|---|---|---|
| `contact-open` | A contact sensor on a door or window opened. No arming state is involved. | `protect` |
| `entry-open` | An alarm hub entry point opened. Unlike a bare contact, the hub knows whether it is armed. | `protect` |

## Life safety

| Condition | Means | Comes from |
|---|---|---|
| `smoke` | A smoke detector is alarming. | `protect` |
| `carbon-monoxide` | A carbon monoxide detector is alarming. | `protect` |
| `glass-break` | A glass-break sensor fired. | `protect` |
| `water-leak` | A leak sensor is wet. | `protect` |
| `sensor-alarm` | A sensor alarmed in a way this build could not classify further. Treated as serious rather than discarded. | `protect` |
| `panic-button` | A panic button was pressed. | `protect` |
| `tamper` | A device reported being interfered with -- opened, removed, or covered. | `protect` |

## Detector self-reporting

| Condition | Means | Comes from |
|---|---|---|
| `smoke-test` | A smoke detector ran its self-test. Routine, and usually worth silencing with a rule. | `protect` |
| `smoke-fault` | A smoke detector says it is faulty. A detector in fault is a detector that will not alarm. | `protect` |
| `co-fault` | A carbon monoxide detector says it is faulty. | `protect` |
| `extreme-values` | A sensor is reading outside its sane range -- a temperature or humidity the room could not actually be. | `protect` |
| `vape` | A vape or air-quality sensor tripped. | `protect` |

## Inputs and credentials

| Condition | Means | Comes from |
|---|---|---|
| `button-press` | A hardware button on a device was pressed. | `protect` |
| `input-changed` | A wired input on a device changed state. | `protect` |
| `relay-switched` | A relay output was switched. | `protect` |
| `credential-scan` | A credential was presented to a reader -- a card, a fob, a code, a face. | `protect` |

## Doors

| Condition | Means | Comes from |
|---|---|---|
| `door-forced-open` | A door opened without being unlocked. NEEDS A POSITION SENSOR fitted, and most doors do not have one. | `access` |
| `door-held-open` | A door was left open longer than allowed. Also needs a position sensor. | `access` |
| `access-denied` | Somebody presented a credential and was refused. | `access` |
| `door-remain-unlocked` | A door was put into remain-unlocked state, so it is standing open to anybody. | `access` |
| `access-critical` | A row from Access's own critical log. One condition for the whole topic; which row it was travels in the detail. | `access` |

## Network

| Condition | Means | Comes from |
|---|---|---|
| `wan-down` | The site's internet connection dropped. Reaches this product only through an Alarm Manager webhook. | `inbound` |
| `threat-detected` | Threat management flagged traffic. Webhook only. | `inbound` |
| `poe-fault` | A PoE port faulted, so whatever it powers is now off. Webhook only, and nothing points a hook at it by default. | inbound webhook only |
| `client-lost` | A client this site watches disappeared from the network. Webhook only, and nothing points a hook at it by default. | inbound webhook only |
| `inbound-alarm` | An alarm arrived on a webhook that was never given a more specific meaning. | `inbound` |

## This product reporting on itself

| Condition | Means | Comes from |
|---|---|---|
| `stream-unintelligible` | A source connected and nothing it sent could be understood. A live-but-mute stream is silent total failure of that source. | `protect`, `access` |
| `source-silent` | A source stopped being in contact with its console for longer than it promised. | `internal` |
| `unclean-shutdown` | The daemon did not shut down cleanly last time -- it crashed, or stopped with an error it recorded -- so alarms may have been missed while it was down. | `internal` |

---

## A note on "comes from"

This is where the condition is observed **in this build**, read off the mapping
tables rather than from intent. Several conditions that a UniFi console can
raise reach this product only as an *inbound webhook* -- you make an Alarm
Manager rule by hand and point it at a hook URL, because the Network
Integration API publishes no events at all. Those are marked *inbound webhook
only*, and a hook has to exist and be pointed at one before it can ever fire.
