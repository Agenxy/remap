# Linux platform

This directory will contain native resolver, service-manager, credential,
keystore, packaging, installation, and removal adapters introduced at M1 and M2.

The reference resolver path targets systemd-resolved first. NetworkManager and
non-systemd environments receive explicit adapters. The portable core does not
shell out to resolver-management commands or silently edit `/etc/hosts`.

