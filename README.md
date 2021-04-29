# OpenDrop: an Open Source AirDrop Implementation

[![Release](https://img.shields.io/pypi/v/opendrop?color=%23EC6500&label=release)](https://pypi.org/project/opendrop/)
[![Language grade](https://img.shields.io/lgtm/grade/python/github/seemoo-lab/opendrop?label=code%20quality)](https://lgtm.com/projects/g/seemoo-lab/opendrop/context:python)

*OpenDrop* is a command-line tool that allows sharing files between devices directly over Wi-Fi. Its unique feature is that it is protocol-compatible with Apple AirDrop which allows to share files with Apple devices running iOS and macOS. 
~~Currently (and probably also for the foreseeable future), OpenDrop only supports sending to Apple devices that are discoverable by *everybody* as the default *contacts only* mode requires [Apple-signed certificates](https://www.apple.com/certificateauthority/pdf/Apple_AAI_CPS_v6.1.pdf).~~
We support contacts-only devices by using extracted AirDrop credentials (keys and certificates) from macOS via our [keychain extractor](https://github.com/seemoo-lab/airdrop-keychain-extractor).

## Disclaimer

OpenDrop is experimental software and is the result of reverse engineering efforts by the [Open Wireless Link](https://owlink.org) project.
Therefore, it does not support all features of AirDrop or might be incompatible with future AirDrop versions.
OpenDrop is not affiliated with or endorsed by Apple Inc. Use this code at your own risk.


## Requirements

To achieve compatibility with Apple AirDrop, OpenDrop requires the target platform to support a specific Wi-Fi link layer.
In addition, it requires Python >=3.6 as well as several libraries.

**Apple Wireless Direct Link.**
As AirDrop exclusively runs over Apple Wireless Direct Link (AWDL), OpenDrop is only supported on macOS or on Linux systems running an open re-implementation of AWDL such as [OWL](https://github.com/seemoo-lab/owl).

**Libraries.**
OpenDrop relies on a current version of [libarchive](https://www.libarchive.org).
macOS ships with a rather old version, so you will need to install a newer version, for example, via [Homebrew](https://brew.sh):
```bash
brew install libarchive
```
OpenDrop automatically sets `DYLD_LIBRARY_PATH` to look for the Homebrew version. You may need to update the variable yourself if you install the libraries differently.

Linux distributions should ship with more up-to-date versions, so this won't be necessary.


## Installation 

Installation of the Python package [release](https://pypi.org/project/opendrop/) is straightforward using `pip3`:
```
pip3 install opendrop
```

You can also install the current development version by first cloning this repository, and then installing it via `pip3`:
```
git clone https://github.com/seemoo-lab/opendrop.git
pip3 install ./opendrop
```


## Usage

We briefly explain how to send and receive files using `opendrop`.
To see all command line options, run `opendrop -h`.

### Sending a File or a Link

Sending a file is typically a two-step procedure. You first discover devices in proximity using the `find` command.
Stop the process once you have found the receiver.
```
$ opendrop find
Looking for receivers. Press Ctrl+C to stop ...
Found  index 0  ID eccb2f2dcfe7  name John’s iPhone
Found  index 1  ID e63138ac6ba8  name Jane’s MacBook Pro
```
You can then `send` a file (or link, see below) using 
```
$ opendrop send -r 0 -f /path/to/some/file
Asking receiver to accept ...
Receiver accepted
Uploading file ...
Uploading has been successful
```
Instead of the `index`, you can also use `ID` or `name`.
OpenDrop will try to interpret the input in the order (1) `index`, (2) `ID`, and (3) `name` and fail if no match was found.

**Sending a web link.** Since v0.13, OpenDrop supports sending web links, i.e., URLs, so that receiving Apple devices will immediately open their browser upon accepting. 
(Note that OpenDrop _receivers_ still only support receiving regular files.)

```
$ opendrop send -r 0 -f https://owlink.org --url
```

### Receiving Files

Receiving is much easier. Simply use the `receive` command. OpenDrop will accept all incoming files automatically and put received files in the current directory.
```
$ opendrop receive
```


## Current Limitations/TODOs

OpenDrop is the result of a research project and, thus, has several limitations (non-exhaustive list below). I do not have the capacity to work on them myself but am happy to provide assistance if somebody else want to take them on.

* *Triggering macOS/iOS receivers via Bluetooth Low Energy.* Apple devices start their AWDL interface and AirDrop server only after receiving a custom advertisement via Bluetooth LE (see USENIX paper for details). This means, that Apple AirDrop receivers may not be discovered even if they are discoverable by *everyone*.

* *Sender/Receiver authentication and connection state.* Currently, there is no peer authentication as in Apple's AirDrop, in particular, (1) OpenDrop does not verify that the TLS certificate is signed by [Apple's root](opendrop/certs/apple_root_ca.pem) and (2) that the Apple ID validation record is correct (see USENIX paper for details). In addition, OpenDrop automatically accepts any file that it receives due to a missing connection state.

* *Sending multiple files.* Apple AirDrop supports sending multiple files at once, OpenDrop does not (would require adding more files to the archive, modify HTTP /Ask request, etc.).


## Our Papers

* Alexander Heinrich, Matthias Hollick, Thomas Schneider, Milan Stute, and Christian Weinert. **PrivateDrop: Practical Privacy-Preserving Authentication for Apple AirDrop.** *30th USENIX Security Symposium (USENIX Security ’21)*, August 14–16, 2019, virtual Event. [Paper](https://www.usenix.org/conference/usenixsecurity21/presentation/heinrich) [Website](https://privatedrop.github.io) [Code](https://github.com/seemoo-lab/privatedrop)
* Milan Stute, Sashank Narain, Alex Mariotto, Alexander Heinrich, David Kreitschmann, Guevara Noubir, and Matthias Hollick. **A Billion Open Interfaces for Eve and Mallory: MitM, DoS, and Tracking Attacks on iOS and macOS Through Apple Wireless Direct Link.** *28th USENIX Security Symposium (USENIX Security ’19)*, August 14–16, 2019, Santa Clara, CA, USA. [Paper](https://www.usenix.org/conference/usenixsecurity19/presentation/stute)


## Authors

* **Milan Stute** ([email](mailto:mstute@seemoo.tu-darmstadt.de), [web](https://seemoo.de/mstute))
* **Alexander Heinrich**


## License

OpenDrop is licensed under the [**GNU General Public License v3.0**](LICENSE).
