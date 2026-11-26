// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Sascha Daemgen / IT & MORE Systems

import java.io.File
import java.util.Properties

plugins {
    id("com.android.application") version "9.5.1"
}

val agentPackage = providers.gradleProperty("sxprov.agentPackage").get()

// ---- signing: values come only from outside the repository -----------------
//
// Either SXPROV_AGENT_SIGNING_PROPERTIES points to a properties file outside
// the repository with storeFile, storePassword, keyAlias, keyPassword, or the
// four environment variables below are set. Switching to the production key
// changes only these external values. There is no debug key fallback.

data class Signing(val storeFile: File, val storePassword: String, val keyAlias: String, val keyPassword: String)

// The agent project sits in agent/ at the repository root.
val repoRoot: File = rootDir.resolve("..").canonicalFile

fun insideRepo(f: File): Boolean = f.canonicalFile.toPath().startsWith(repoRoot.toPath())

fun loadSigning(): Pair<Signing?, String> {
    val propsPath = System.getenv("SXPROV_AGENT_SIGNING_PROPERTIES")
    val values: Map<String, String?> = if (!propsPath.isNullOrEmpty()) {
        val f = File(propsPath)
        if (!f.isFile) return null to "SXPROV_AGENT_SIGNING_PROPERTIES points to a missing file"
        if (insideRepo(f)) return null to "the signing properties file must be outside the repository"
        val p = Properties()
        f.inputStream().use { p.load(it) }
        mapOf(
            "storeFile" to p.getProperty("storeFile"),
            "storePassword" to p.getProperty("storePassword"),
            "keyAlias" to p.getProperty("keyAlias"),
            "keyPassword" to p.getProperty("keyPassword"),
        )
    } else {
        mapOf(
            "storeFile" to System.getenv("SXPROV_AGENT_KEYSTORE"),
            "storePassword" to System.getenv("SXPROV_AGENT_KEYSTORE_PASSWORD"),
            "keyAlias" to System.getenv("SXPROV_AGENT_KEY_ALIAS"),
            "keyPassword" to System.getenv("SXPROV_AGENT_KEY_PASSWORD"),
        )
    }
    val missing = values.filterValues { it.isNullOrEmpty() }.keys
    if (missing.isNotEmpty()) {
        return null to "agent signing values missing: ${missing.joinToString()}. Set " +
            "SXPROV_AGENT_SIGNING_PROPERTIES, or SXPROV_AGENT_KEYSTORE, SXPROV_AGENT_KEYSTORE_PASSWORD, " +
            "SXPROV_AGENT_KEY_ALIAS and SXPROV_AGENT_KEY_PASSWORD (see docs/DEVELOPMENT.md)."
    }
    val store = File(values["storeFile"]!!)
    if (!store.isFile) return null to "agent keystore not found"
    if (insideRepo(store)) return null to "the agent keystore must be outside the repository"
    return Signing(store, values["storePassword"]!!, values["keyAlias"]!!, values["keyPassword"]!!) to ""
}

val (signing, signingProblem) = loadSigning()

android {
    namespace = "dev.simplego.provisioning.agent"
    compileSdk = 36

    defaultConfig {
        applicationId = agentPackage
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-alpha"
    }

    signingConfigs {
        if (signing != null) {
            create("external") {
                storeFile = signing.storeFile
                storePassword = signing.storePassword
                keyAlias = signing.keyAlias
                keyPassword = signing.keyPassword
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            // No repository commit metadata in the APK.
            vcsInfo.include = false
            if (signing != null) {
                signingConfig = signingConfigs.getByName("external")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
    }
}

// Only the release variant exists: no debug build, no debug key.
androidComponents {
    beforeVariants(selector().withBuildType("debug")) { it.enable = false }
}

val checkAgentSigning = tasks.register("checkAgentSigning") {
    val problem = signingProblem
    doLast {
        if (problem.isNotEmpty()) throw GradleException(problem)
    }
}

tasks.named("preBuild") { dependsOn(checkAgentSigning) }
