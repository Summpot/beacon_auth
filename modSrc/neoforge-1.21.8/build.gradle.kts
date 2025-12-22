plugins {
    id("com.gradleup.shadow")
}

val minecraftVersion = "1.21.8"
val neoForgeVersion = "21.8.52"
val architecturyVersion = "17.0.8"
val nimbusJwtVersion = "10.6"

configure<net.fabricmc.loom.api.LoomGradleExtensionAPI> {
    runs {
        named("server") {
            property("online-mode", "false")
        }
    }
}

architectury {
    minecraft = minecraftVersion
    platformSetupLoomIde()
    neoForge()
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
    named("developmentNeoForge") {
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
    "minecraft"("net.minecraft:minecraft:$minecraftVersion")
    "mappings"(project.extensions.getByType<net.fabricmc.loom.api.LoomGradleExtensionAPI>().officialMojangMappings())

    neoForge("net.neoforged:neoforge:$neoForgeVersion")

    modImplementation("dev.architectury:architectury-neoforge:$architecturyVersion")

    common(project(path = ":common-1.21.8", configuration = "namedElements")) {
        isTransitive = false
    }
    shadowBundle(project(path = ":common-1.21.8", configuration = "transformProductionNeoForge"))

    // NeoForge does not ship with a Kotlin language provider by default.
    // Bundle Kotlin stdlib directly to keep this jar self-contained.
    implementation(kotlin("stdlib"))
    shadowBundle(kotlin("stdlib"))

    implementation("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")
    shadowBundle("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")
}

tasks.processResources {
    inputs.property("version", project.version)

    filesMatching(listOf("META-INF/neoforge.mods.toml", "META-INF/mods.toml")) {
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
