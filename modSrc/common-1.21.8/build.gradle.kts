val minecraftVersion = "1.21.8"
val architecturyVersion = "17.0.8"
val fabricLoaderVersion = "0.16.14"
val forgeConfigApiPortVersion = "21.8.2"
val nimbusJwtVersion = "10.6"

architectury {
    minecraft = minecraftVersion
    common(listOf("fabric", "neoforge"))
}

dependencies {
    "minecraft"("net.minecraft:minecraft:$minecraftVersion")
    "mappings"(project.extensions.getByType<net.fabricmc.loom.api.LoomGradleExtensionAPI>().officialMojangMappings())

    modImplementation("net.fabricmc:fabric-loader:$fabricLoaderVersion")

    modImplementation("dev.architectury:architectury:$architecturyVersion")

    modImplementation("com.nimbusds:nimbus-jose-jwt:$nimbusJwtVersion")

    modApi("fuzs.forgeconfigapiport:forgeconfigapiport-common:$forgeConfigApiPortVersion")

    compileOnly("org.slf4j:slf4j-api:2.0.16")
}

// Reuse shared implementation from the unversioned common sources folder.
// Each Minecraft version still compiles these sources against its own mappings/dependencies.
sourceSets {
    named("main") {
        // IMPORTANT: setSrcDirs replaces the default src/main/** to avoid duplicate classes/resources.
        java.setSrcDirs(
            listOf(
                rootProject.file("common/src/main/java"),
                project.file("src/versioned/java")
            )
        )
        resources.setSrcDirs(
            listOf(
                rootProject.file("common/src/main/resources")
            )
        )
    }
}

kotlin {
    sourceSets {
        named("main") {
            // IMPORTANT: setSrcDirs replaces the default src/main/** to avoid duplicate classes/resources.
            kotlin.setSrcDirs(
                listOf(
                    rootProject.file("common/src/main/kotlin"),
                    project.file("src/versioned/kotlin")
                )
            )
        }
    }
}
