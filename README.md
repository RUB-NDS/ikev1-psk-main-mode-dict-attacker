# IKEv1 dictionary attacker (main mode with PSK)

This repository contains a python 3 attacker against IKEv1 in main mode with pre-shared keys (passwords). 
- Purpose
- Usergroup
- Usage
- Directory Structure
- Future Work

## Purpose
- This is a PoC (Proof-of-Concept) to show that main mode psk can be cracked

## Usergroup
- Researcher, IT-Administrators, etc.

## Usage
- Specify the *.pcapng file and dict.txt file in main.py and the script tries every password in the dictionary
- The pcap must contain a ikev1 psk main mode handshake, where the attacker was the responder (via Man-in-the-Middle)
- The captured must contain at least the first 5 Handshake messages of the IKEv1 Phase 1
- The 5. message containts the required encrypted data from the initiator
- You must be the responder during the handshake to know the shared Diffie-Hellman Secret (g^xy)
- This Diffie-Hellman secret must be specified in the main.py
- The ID value also needs to be given in the main.py (the structure for StrongSwan can be found in the main.py and logs)

## Directory Structure

##### Dictionary Python Attacker Files
- main.py loades a pcapng file from pcaps directory
- computes the hashes corresponding to the passwords found in a given list.txt file from the dict directory 

```bash
├── main.py
├── ikev1_payloadParser.py
├── ikev1_pcapReader.py
├── pcaps
│   ├── *.pcapng
├── dict
│   ├── *.txt
```
## FAQ
- Is it also possible to be the initiator during the handshake?
    - No, only if you are the responder you get the required 5. handshake message
- Is it enough to only passivly capture the handshake
    - No, because you need to know the Diffie-Hellman Secret
