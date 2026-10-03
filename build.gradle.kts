plugins {
    kotlin("jvm") version "2.1.0"
    kotlin("plugin.serialization") version "2.1.0"
    id("com.gradleup.shadow") version "8.3.6"
}

group = "com.redcell"
// Overridable for releases: -PreleaseVersion=0.2.0 (CI tags strip the leading "v").
version = (findProperty("releaseVersion") as String?)?.takeIf { it.isNotBlank() } ?: "0.6.0"

repositories {
    mavenCentral()
    maven("https://repo.portswigger.net/burp/releases/")
}

dependencies {
    // Burp Montoya extension API — provided by Burp at runtime, so compileOnly.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.8")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testImplementation("io.mockk:mockk:1.13.13")
    // Montoya types are referenced in unit tests (mocked), so needed on test classpath.
    testImplementation("net.portswigger.burp.extensions:montoya-api:2025.8")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveClassifier.set("all")
    // Montoya API is provided by Burp; never bundle it.
    mergeServiceFiles()
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
