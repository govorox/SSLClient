# Publishing a patch release

1. Update `library.properties` and `library.json` to the same new version. Keep the registered names `GovoroxSSLClient` (Arduino) and `SSLClient` under `digitaldragon` (PlatformIO).
2. Update the README installation version, PlatformIO example dependencies, and changelog. Keep the PlatformIO example CI override aligned with the example dependency version.
3. Wait for all PR checks to pass, merge into `master`, and tag the merged commit using the existing convention, for example `1.3.3`.

## Arduino Library Manager

Push the tag containing the updated `library.properties`. For an already registered library, Arduino checks for new tags every hour and indexes compliant versions automatically; no new submission is required.

Check [the indexer logs](https://downloads.arduino.cc/libraries/logs/github.com/govorox/SSLClient/) and confirm the version appears in Library Manager. A pushed tag does not by itself confirm successful indexing.

Source: [Arduino Library Manager FAQ](https://github.com/arduino/library-registry/blob/main/FAQ.md#how-can-i-publish-a-new-release-once-my-library-is-in-the-list).

## PlatformIO Registry

A Git tag alone does not publish the package. From a clean checkout of the release tag, authenticate with a PlatformIO account permitted to publish under `digitaldragon`, inspect the archive, then publish:

```sh
pio account login
pio pkg pack --output SSLClient-1.3.3.tar.gz
# Inspect the archive contents before publishing.
pio pkg publish SSLClient-1.3.3.tar.gz --owner digitaldragon --type library
```

Confirm `1.3.3` appears in [the PlatformIO listing](https://registry.platformio.org/libraries/digitaldragon/SSLClient), then verify installation with `digitaldragon/SSLClient@1.3.3`. Published name/version pairs cannot be reused, even after unpublishing.

Source: [PlatformIO publishing documentation](https://docs.platformio.org/en/latest/core/userguide/pkg/cmd_publish.html).
