# Version 1.1.0

* Added proof of work checking. The dissector will know if the conversation is tezos once it intercept first 60 bytes. It allows do not touch irrelevant data at all.
* Added fuzz.
* Fixed some rarely crashes. Improved stability.
* Changed interface. Messages branch goes before chunks branch.
