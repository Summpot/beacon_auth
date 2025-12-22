architectury {
    common(rootProject.property("enabled_platforms").toString().split(","))
}

dependencies {
    modImplementation("net.fabricmc:fabric-loader:${rootProject.property("fabric_loader_version")}")

    modImplementation("dev.architectury:architectury:${rootProject.property("architectury_api_version")}")

    modImplementation("com.nimbusds:nimbus-jose-jwt:10.6")

    modApi("fuzs.forgeconfigapiport:forgeconfigapiport-common:8.0.2")

    compileOnly("org.slf4j:slf4j-api:2.0.16")
}
