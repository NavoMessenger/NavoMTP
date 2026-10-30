# Live ad tags on existing client connections

This patch passes the existing runtime configuration watch to the Middle-End
sender. Each active sender caches a decoded tag and refreshes it when a newer
configuration is available, before its next queued data request is sent. There
is no new polling task, packet injection, or connection teardown.

Per-user tags take precedence over the global tag. Removing an override restores
the global fallback; removing both clears the wire tag flag, including when the
ME pool still has an older immutable fallback. Protocol, quick-ack, encryption,
connection identity, queue permits, and ordering are preserved. A send already
in progress finishes with the metadata it captured; later sends use the latest
observed snapshot. Intermediate rapid configuration changes may be coalesced.
Without outbound traffic there is nothing to send. A closed configuration watch
retains its final value rather than terminating the client connection.

The runtime TCP/FakeTLS and WEB admission paths carry the live watch. Standalone
stream entry points, including the UNIX socket listener, retain their existing
pinned configuration behavior. This patch does not extend generation lifetimes
or override the normal cancellation/draining behavior of a full generation swap.

This only controls outgoing RPC_PROXY_REQ metadata. Telegram's acceptance of a
new tag on an existing connection and client promotion cache/display behavior
require live testing. This does not promise immediate UI changes and does not
forge encrypted client API calls such as help.getPromoData.

## Build the patched source

The upstream Dockerfile downloads release binaries. It does **not** compile this
patch. Use the source-build Dockerfile from this checkout instead, on the target
Linux architecture (amd64 or arm64):

```sh
docker build -f Dockerfile.live-tag -t navomtp-telemt:live-tag .
```

The current NavoMTP wizard also supports managed source builds: upload this
complete checkout to the proxy server, run `bash navomtp.sh configure`, select
`source`, and provide its absolute path. The script builds this Dockerfile,
validates the result, and deploys a uniquely tagged local image without pulling
an official Telemt image. It preserves Compose security settings, the read-only
configuration-directory mount, tmpfs, and health check. No registry push or
manual state-file edits are required.

The selected mode and source path persist. The image update command rebuilds
that directory in source mode without running git pull. Old builds remain
available for rollback; automatic tag-rotation ticks do not rebuild. Selecting
`official` explicitly returns to the official image, which does not contain this
patch. Existing deployments without a mode field remain in official mode.

## Acceptance

1. Run `cargo test --locked live_ad_tag` and compile the binary on Linux.
2. Use two independently validated promotion tags A and B and an existing user
   secret. Establish one client connection using A.
3. Change only the tag to B and trigger the existing config hot reload. Do not
   restart the container, recreate the connection, change the key, or rotate ME
   writers during this test.
4. Generate client traffic. The regression test checks that subsequent serialized
   requests retain their connection ID and payload but carry B. For live evidence,
   use a debugger or dedicated instrumented development build at the sender/wire
   boundary, without logging secrets or payloads. Compare the client TCP lifetime
   and ME connection ID before and after; container uptime alone is insufficient.
5. Verify uploads, downloads, quick acknowledgements, tag removal/global fallback,
   and repeated updates while traffic is queued. Record server acceptance and
   actual promotion display separately, including time until client refresh.
6. If Telegram ignores updated metadata for the same connection, record that
   outcome instead of treating a local hot-reload log as successful promotion
   rotation. Roll back to the previous image if transport errors appear.
