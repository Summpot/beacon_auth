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
