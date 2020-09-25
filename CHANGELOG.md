# Version 1.1.0

* Added proof of work checking. The dissector will know whether the conversation is associated with Tezos once it intercepts the first 60 bytes. This improves the dissector's ability to filter out irrelevant data.
* Added fuzzing to locate crashes and incorrect corner states
* Fixed some rare crashes and improved stability.
* Changed the user interface. The messages branch goes before the chunks branch.
