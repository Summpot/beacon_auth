plugins {
    id("com.gradleup.shadow")
}

architectury {
    platformSetupLoomIde()
    fabric()
}

loom {
    runs {
        named("server") {
            property("online-mode", "false")
        }
    }
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
    named("developmentFabric") {
        extendsFrom(common)
    }
}

dependencies {
    modImplementation("net.fabricmc:fabric-loader:${rootProject.property("fabric_loader_version")}")

    modImplementation("net.fabricmc.fabric-api:fabric-api:${rootProject.property("fabric_api_version")}")
    
    modImplementation("net.fabricmc:fabric-language-kotlin:1.13.7+kotlin.2.2.21")

    modImplementation("dev.architectury:architectury-fabric:${rootProject.property("architectury_api_version")}")

    common(project(path = ":common", configuration = "namedElements")) {
        isTransitive = false
    }
    shadowBundle(project(path = ":common", configuration = "transformProductionFabric"))

    modApi("fuzs.forgeconfigapiport:forgeconfigapiport-fabric:8.0.2")

    implementation("com.nimbusds:nimbus-jose-jwt:10.6")

    include("fuzs.forgeconfigapiport:forgeconfigapiport-fabric:8.0.2")
    include("com.nimbusds:nimbus-jose-jwt:10.6")
}

tasks.processResources {
    inputs.property("version", project.version)

    filesMatching("fabric.mod.json") {
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
