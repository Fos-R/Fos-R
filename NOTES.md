# TODO

Créer les namespace via le rust, un thread par IP/machine qui gère les transferts, comme ça pas besoin de sync

Drop les namespace à la fin

Voir pour la fragmentation des packets, potentiellement flag fragment more à côté du taint. Peut être ok de mettre gros mtu temporairement dans les namespaces.

# Eval

- 17 décembre petite soutenance
- 12 février démo
- soutenance final : 15 avril + démo

# Infos

Pour lancer avec --netns, il faut sudo donc lancer cargo run en privilégié. Cela se fait avec par exemple:

```sh
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E" cargo run --release -p fosr-cli --features net_injection -- inject-across -m ccd -n crates/fosr-lib/default_topologies/lab-across.yaml -s 42 -d 2min -o out.pcap --netns
```

Ou en créant un alias:

```sh
alias cargo-root='CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E" cargo'
cargo-root run --release -p fosr-cli --features net_injection -- …
```
