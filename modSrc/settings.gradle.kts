pluginManagement {
    repositories {
        maven { url = uri("https://maven.fabricmc.net/") }
        maven { url = uri("https://maven.architectury.dev/") }
        maven { url = uri("https://files.minecraftforge.net/maven/") }
        maven { url = uri("https://maven.neoforged.net/releases/") }
        gradlePluginPortal()
    }
}

rootProject.name = "beaconauth"

include("common-1.20.1")
include("fabric-1.20.1")
include("forge-1.20.1")

include("common-1.21.1")
include("fabric-1.21.1")
include("neoforge-1.21.1")

include("common-1.21.8")
include("fabric-1.21.8")
include("neoforge-1.21.8")