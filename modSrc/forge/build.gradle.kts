plugins {
    id("com.gradleup.shadow")
}

configure<net.fabricmc.loom.api.LoomGradleExtensionAPI> {
    forge {
        mixinConfig("beaconauth.mixins.json")
    }
    
    runs {
        named("server") {
            property("online-mode", "false")
        }
    }
}

architectury {
    platformSetupLoomIde()
    forge()
}

val common: Configuration by configurations.creating {
    isCanBeResolved = true
    isCanBeConsumed = false
}

val shadowBundle: Configuration by configurations.creating {
    isCanBeResolved = true
    isCanBeConsumed = false
}

configurations {
    compileClasspath.get().extendsFrom(common)
    runtimeClasspath.get().extendsFrom(common)
    named("developmentForge") {
        extendsFrom(common)
    }
}

repositories {
    maven {
        name = "Kotlin for Forge"
        url = uri("https://thedarkcolour.github.io/KotlinForForge/")
    }
}

dependencies {
    forge("net.minecraftforge:forge:${rootProject.property("forge_version")}")
    
    implementation("thedarkcolour:kotlinforforge:4.10.0")

    modImplementation("dev.architectury:architectury-forge:${rootProject.property("architectury_api_version")}")

    common(project(path = ":common", configuration = "namedElements")) {
        isTransitive = false
    }
    shadowBundle(project(path = ":common", configuration = "transformProductionForge"))

    implementation("com.nimbusds:nimbus-jose-jwt:10.6")

    forgeRuntimeLibrary("com.nimbusds:nimbus-jose-jwt:10.6")
}

tasks.processResources {
    inputs.property("version", project.version)

    filesMatching("META-INF/mods.toml") {
        expand("version" to project.version)
    }
}

tasks.shadowJar {
    configurations = listOf(shadowBundle)
    archiveClassifier.set("dev-shadow")
    minimize()
}

tasks.remapJar {
    inputFile.set(tasks.shadowJar.get().archiveFile)
}
