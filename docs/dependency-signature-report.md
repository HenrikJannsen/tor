# Dependency Signature Report

Generated from `gradle/verification-metadata.xml` after resolving 195 configurations.

Signer metadata is loaded from `gradle/verification-keyring.keys`; names and emails come from the first OpenPGP user ID, and creation dates come from the public key packet.

Checksum-only review rationales are loaded from `gradle/dependency-checksum-fallback-allowlist.tsv`.

Refresh the metadata before regenerating this report:

```bash
./gradlew refreshDependencyVerificationKeyring
./gradlew resolveAndVerifyDependencies --write-verification-metadata pgp,sha256
./gradlew verifyDependencySignaturePolicy
./gradlew dependencySignatureReport
```

## Summary

| Metric | Count |
| --- | ---: |
| Resolved external modules | 69 |
| Modules with PGP-signed artifacts only | 68 |
| Modules using checksum-only artifacts only | 1 |
| Modules with mixed signed/checksum-only artifacts | 0 |
| Modules missing verification metadata | 0 |
| Verified artifacts | 115 |
| PGP-signed artifacts | 114 |
| Checksum-only artifacts | 1 |
| Resolved executable artifacts missing explicit metadata | 0 |
| Stale executable metadata entries for unresolved versions | 0 |
| Signer keys found in exported keyring | 20 / 20 |
| Signer keys with name or email | 14 / 20 |
| Signer keys with creation date | 20 / 20 |

## Handling Transitive Dependencies

Treat transitive dependencies the same as direct dependencies. Gradle verifies the resolved artifact graph, so a transitive artifact with a published signature should be PGP-verified, and an unsigned artifact should keep an explicit SHA-256 checksum-only fallback. Review metadata changes separately when dependency versions change, especially new trusted keys and new checksum-only artifacts.

## Checksum-Only Dependencies

| Dependency | Scope | Checksum-only artifacts and review rationale |
| --- | --- | --- |
| `org.gradle.kotlin.kotlin-dsl:org.gradle.kotlin.kotlin-dsl.gradle.plugin:4.4.0` | direct | `org.gradle.kotlin.kotlin-dsl.gradle.plugin-4.4.0.pom`<br>Gradle plugin marker POM has no detached signature; marker is pinned by SHA-256. |

## Checksum-Only Metadata Outside the Resolved Graph

Gradle also verifies parent POMs, imported BOMs and artifacts of other platforms against the metadata. These checksum-only entries are not part of the resolved dependency graph.

| Dependency | Artifact and review rationale |
| --- | --- |
| `com.gradleup.shadow:com.gradleup.shadow.gradle.plugin:9.4.1` | `com.gradleup.shadow.gradle.plugin-9.4.1.pom`<br>Gradle plugin marker POM has no detached signature; marker is pinned by SHA-256. |
| `org.openjfx.javafxplugin:org.openjfx.javafxplugin.gradle.plugin:0.1.0` | `org.openjfx.javafxplugin.gradle.plugin-0.1.0.pom`<br>Gradle plugin marker POM has no detached signature; marker is pinned by SHA-256. |
| `org.openjfx:javafx-plugin:0.1.0` | `javafx-plugin-0.1.0-sources.jar`<br>Publisher does not provide a detached PGP signature for this Gradle plugin source artifact; source artifact is pinned by SHA-256. |
| `org.openjfx:javafx-plugin:0.1.0` | `javafx-plugin-0.1.0.jar`<br>Publisher does not provide a detached PGP signature for this Gradle plugin artifact; artifact is pinned by SHA-256. |
| `org.openjfx:javafx-plugin:0.1.0` | `javafx-plugin-0.1.0.module`<br>Publisher does not provide a detached PGP signature for this Gradle module metadata; module metadata is pinned by SHA-256. |
| `org.sonatype.oss:oss-parent:7` | `oss-parent-7.pom`<br>Parent POM has no detached signature on Maven Central; POM is pinned by SHA-256. |
| `org.testfx:openjfx-monocle:21.0.2` | `openjfx-monocle-21.0.2-javadoc.jar`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |
| `org.testfx:openjfx-monocle:21.0.2` | `openjfx-monocle-21.0.2-sources.jar`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |
| `org.testfx:openjfx-monocle:21.0.2` | `openjfx-monocle-21.0.2.jar`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |
| `org.testfx:openjfx-monocle:21.0.2` | `openjfx-monocle-21.0.2.pom`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |
| `org.testfx:testfx-core:4.0.18` | `testfx-core-4.0.18-sources.jar`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |
| `org.testfx:testfx-core:4.0.18` | `testfx-core-4.0.18.jar`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |
| `org.testfx:testfx-core:4.0.18` | `testfx-core-4.0.18.pom`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |
| `org.testfx:testfx-junit5:4.0.18` | `testfx-junit5-4.0.18-sources.jar`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |
| `org.testfx:testfx-junit5:4.0.18` | `testfx-junit5-4.0.18.jar`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |
| `org.testfx:testfx-junit5:4.0.18` | `testfx-junit5-4.0.18.pom`<br>Signed with key 61651257058D3757, which is not available from the key servers; artifact is pinned by SHA-256. |

## Full Resolved Dependency Inventory

| Dependency | Scope | Status | Artifacts | Signer key and metadata |
| --- | --- | --- | ---: | --- |
| `ch.qos.logback:logback-classic:1.5.32` | direct | PGP signed | 1 signed / 0 checksum | `60200AC4AE761F1614D6C46766D68DAA073BE985`<br>Ceki Gulcu<br>`ceki@qos.ch`<br>created 2022-08-08 |
| `ch.qos.logback:logback-core:1.5.32` | direct | PGP signed | 1 signed / 0 checksum | `60200AC4AE761F1614D6C46766D68DAA073BE985`<br>Ceki Gulcu<br>`ceki@qos.ch`<br>created 2022-08-08 |
| `com.google.code.findbugs:jsr305:3.0.2` | direct | PGP signed | 2 signed / 0 checksum | `7616EB882DAF57A11477AAF559A252FB1199D873`<br>Tagir Valeev<br>`lany@ngs.ru`<br>created 2015-03-12<br><br>`BDB5FA4FE719D787FB3D3197F6D4A1D411E9D1AE`<br>Christopher Povirk<br>`cpovirk@google.com`<br>created 2012-02-16 |
| `com.google.errorprone:error_prone_annotations:2.49.0` | transitive | PGP signed | 1 signed / 0 checksum | `BDB5FA4FE719D787FB3D3197F6D4A1D411E9D1AE`<br>Christopher Povirk<br>`cpovirk@google.com`<br>created 2012-02-16<br><br>`EE0CA873074092F806F59B65D364ABAA39A47320`<br>created 2022-01-28 |
| `com.google.guava:failureaccess:1.0.3` | transitive | PGP signed | 1 signed / 0 checksum | `BDB5FA4FE719D787FB3D3197F6D4A1D411E9D1AE`<br>Christopher Povirk<br>`cpovirk@google.com`<br>created 2012-02-16 |
| `com.google.guava:guava:33.6.0-jre` | direct | PGP signed | 1 signed / 0 checksum | `BDB5FA4FE719D787FB3D3197F6D4A1D411E9D1AE`<br>Christopher Povirk<br>`cpovirk@google.com`<br>created 2012-02-16 |
| `com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava` | transitive | PGP signed | 2 signed / 0 checksum | `BDB5FA4FE719D787FB3D3197F6D4A1D411E9D1AE`<br>Christopher Povirk<br>`cpovirk@google.com`<br>created 2012-02-16 |
| `com.google.j2objc:j2objc-annotations:3.1` | transitive | PGP signed | 1 signed / 0 checksum | `BDB5FA4FE719D787FB3D3197F6D4A1D411E9D1AE`<br>Christopher Povirk<br>`cpovirk@google.com`<br>created 2012-02-16<br><br>`C3259D20DAEC4ACE6D57CC83340B090F727518D8`<br>Thomas Ball<br>`tball@google.com`<br>created 2025-08-13 |
| `com.typesafe:config:1.4.8` | direct | PGP signed | 1 signed / 0 checksum | `DFD60A08EC2B0CECED24A01F36A22209606109DC`<br>Secure Bot<br>`lightbend-tools-secure@lightbend.com`<br>created 2025-07-10 |
| `net.bytebuddy:byte-buddy-agent:1.17.7` | transitive | PGP signed | 1 signed / 0 checksum | `A7892505CF1A58076453E52D7999BEFBA1039E8B`<br>Rafael Winterhalter<br>`rafael.wth@gmail.com`<br>created 2019-11-07 |
| `net.bytebuddy:byte-buddy:1.18.3` | transitive | PGP signed | 1 signed / 0 checksum | `A7892505CF1A58076453E52D7999BEFBA1039E8B`<br>Rafael Winterhalter<br>`rafael.wth@gmail.com`<br>created 2019-11-07 |
| `org.apiguardian:apiguardian-api:1.1.2` | transitive | PGP signed | 2 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.assertj:assertj-core:3.27.7` | direct | PGP signed | 1 signed / 0 checksum | `BE685132AFD2740D9095F9040CC0B712FEE75827`<br>created 2020-10-12 |
| `org.bouncycastle:bcpg-jdk18on:1.84` | direct | PGP signed | 1 signed / 0 checksum | `7B121B76A7ED6CE6E60AD51784E913A8E3A748C0`<br>The Legion of the Bouncy Castle Inc. (Maven Repository Artifact Signer)<br>`bcmavensync@bouncycastle.org`<br>created 2023-06-07 |
| `org.bouncycastle:bcprov-jdk18on:1.84` | transitive | PGP signed | 1 signed / 0 checksum | `7B121B76A7ED6CE6E60AD51784E913A8E3A748C0`<br>The Legion of the Bouncy Castle Inc. (Maven Repository Artifact Signer)<br>`bcmavensync@bouncycastle.org`<br>created 2023-06-07 |
| `org.bouncycastle:bcutil-jdk18on:1.84` | transitive | PGP signed | 1 signed / 0 checksum | `7B121B76A7ED6CE6E60AD51784E913A8E3A748C0`<br>The Legion of the Bouncy Castle Inc. (Maven Repository Artifact Signer)<br>`bcmavensync@bouncycastle.org`<br>created 2023-06-07 |
| `org.gradle.kotlin.kotlin-dsl:org.gradle.kotlin.kotlin-dsl.gradle.plugin:4.4.0` | direct | checksum fallback | 0 signed / 1 checksum | - |
| `org.gradle.kotlin:gradle-kotlin-dsl-plugins:4.4.0` | transitive | PGP signed | 2 signed / 0 checksum | `1BD97A6A154E7810EE0BC832E2F38302C8075E3D`<br>Gradle Inc.<br>`maven-publishing@gradle.com`<br>created 2022-12-29 |
| `org.jetbrains.intellij.deps:trove4j:1.0.20200330` | transitive | PGP signed | 2 signed / 0 checksum | `8756C4F765C9AC3CB6B85D62379CE192D401AB61`<br>Bintray (by JFrog)<br>`bintray@bintray.com`<br>created 2015-02-17 |
| `org.jetbrains.kotlin:kotlin-android-extensions:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-assignment-compiler-plugin-embeddable:1.9.23` | direct | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-assignment:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-build-common:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-build-tools-api:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-build-tools-impl:1.9.23` | direct | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-compiler-embeddable:1.9.23` | direct | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-compiler-runner:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-daemon-client:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-daemon-embeddable:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-gradle-plugin-annotations:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-gradle-plugin-api:1.9.23` | transitive | PGP signed | 3 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-gradle-plugin-idea-proto:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-gradle-plugin-idea:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-gradle-plugin-model:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-gradle-plugins-bom:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-klib-commonizer-api:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-klib-commonizer-embeddable:1.9.23` | direct | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-native-utils:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-project-model:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-reflect:1.6.10` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-reflect:1.9.23` | direct | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-sam-with-receiver-compiler-plugin-embeddable:1.9.23` | direct | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-sam-with-receiver:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-script-runtime:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-scripting-common:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-scripting-compiler-embeddable:1.9.23` | direct | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-scripting-compiler-impl-embeddable:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-scripting-jvm:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-stdlib:1.9.23` | direct | PGP signed | 4 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-tooling-core:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-util-io:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlin:kotlin-util-klib:1.9.23` | transitive | PGP signed | 2 signed / 0 checksum | `6F538074CCEBF35F28AF9B066A0975F8B1127B83`<br>Kotlin Release<br>`kt-a@jetbrains.com`<br>created 2019-06-01 |
| `org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.5.0` | transitive | PGP signed | 2 signed / 0 checksum | `E7DC75FC24FB3C8DFE8086AD3D5839A2262CBBFB`<br>created 2020-12-09 |
| `org.jetbrains:annotations:13.0` | direct | PGP signed | 2 signed / 0 checksum | `2E3A1AFFE42B5F53AF19F780BCF4173966770193`<br>IntelliJ IDEA Sign Key<br>`intellij-idea-sign-key-noreply@jetbrains.com`<br>created 2013-12-10 |
| `org.jspecify:jspecify:1.0.0` | transitive | PGP signed | 3 signed / 0 checksum | `41CD49B4EF5876F9E9F691DABAC30622339994C4`<br>Chris Povirk<br>`cpovirk@google.com`<br>created 2017-06-22 |
| `org.junit.jupiter:junit-jupiter-api:6.0.3` | transitive | PGP signed | 1 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.junit.jupiter:junit-jupiter-engine:6.0.3` | transitive | PGP signed | 1 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.junit.jupiter:junit-jupiter-params:6.0.3` | transitive | PGP signed | 1 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.junit.jupiter:junit-jupiter:6.0.3` | direct | PGP signed | 1 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.junit.platform:junit-platform-commons:6.0.3` | transitive | PGP signed | 1 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.junit.platform:junit-platform-engine:6.0.3` | transitive | PGP signed | 1 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.junit.platform:junit-platform-launcher:6.0.3` | direct | PGP signed | 1 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.junit:junit-bom:6.0.3` | transitive | PGP signed | 0 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.mockito:mockito-core:5.23.0` | direct | PGP signed | 1 signed / 0 checksum | `147B691A19097624902F4EA9689CBE64F4BC997F`<br>Szczepan Faber<br>`szczepiq@gmail.com`<br>created 2021-02-14 |
| `org.objenesis:objenesis:3.3` | transitive | PGP signed | 2 signed / 0 checksum | `E85AED155021AF8A6C6B7A4A7C7D8456294423BA`<br>created 2010-05-13 |
| `org.opentest4j:opentest4j:1.3.0` | transitive | PGP signed | 1 signed / 0 checksum | `FF6E2C001948C5F2F38B0CC385911F425EC61B51`<br>Marc Philipp<br>`marc@junit.org`<br>created 2018-04-08 |
| `org.projectlombok:lombok:1.18.46` | direct | PGP signed | 1 signed / 0 checksum | `D421D1DF4570BFB13E485D0BF95ADD0A28D2F139`<br>created 2011-03-08 |
| `org.slf4j:slf4j-api:2.0.18` | direct | PGP signed | 1 signed / 0 checksum | `475F3B8E59E6E63AA78067482C7B12F2A511E325`<br>created 2012-04-26<br><br>`60200AC4AE761F1614D6C46766D68DAA073BE985`<br>Ceki Gulcu<br>`ceki@qos.ch`<br>created 2022-08-08 |
