# How to use

Fos-R contains several subcommands.

## Pcap creation

Check the ["Configuration file" section](#configuration-file) for more information on how to customize the generation.

If you want to generate a large pcap file, you may not have enough RAM to fit the entire dataset. In that case, use the `-p efficient --no-order-pcap` to generate an out-of-order pcap, and then use a tool like [reordercap](https://www.wireshark.org/docs/man-pages/reordercap.html) to reorder the pcap file. The RAM usage is minimal and is constant relative to the output pcap with these options.

```console
