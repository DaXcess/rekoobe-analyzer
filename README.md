# Rekoobe Analyzer

Rekoobe Analyzer is a network inspection tool can that identify and decrypt C2 packets sent by the [Rekoobe](https://asec.ahnlab.com/en/55229/) backdoor.

## Usage

```sh
rekoobe-analyzer --file <path to pcap> --secret <decryption secret> [--signature <optional signature>]
```

*Or in short form*:
```sh
rekoobe-analyzer -f <pcap> -s <secret> [--signature <signature>]
```

> [!NOTE]
> The `--signature` flag is optional, and is intended to be used for additional validation of the tcp stream

Rekoobe Analyzer supports both "plain" ethernet frames and IP packets captured using Linux cooked capture.

## Attribution

This repo is based off of [alexander-utkov's](https://github.com/alexander-utkov) rekoobe-analyzer written in Python, however the original repository seems to have vanished

## License

This software is licenses under the [MIT License](LICENSE)
