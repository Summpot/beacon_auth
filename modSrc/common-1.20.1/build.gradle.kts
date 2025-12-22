val minecraftVersion = "1.20.1"
val architecturyVersion = "9.2.14"
val fabricLoaderVersion = "0.18.0"
val forgeConfigApiPortVersion = "8.0.2"
val nimbusJwtVersion = "10.6"

architectury {
    minecraft = minecraftVersion
    common(listOf("fabric", "forge"))
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
