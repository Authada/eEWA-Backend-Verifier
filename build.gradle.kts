import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage
import kotlin.jvm.optionals.getOrNull

plugins {
    base
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.kotlin.plugin.serialization)
}

repositories {
    mavenCentral()
    mavenLocal()
    maven {
        url = uri("https://maven.walt.id/repository/waltid/")
        mavenContent {
        }
    }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation(libs.presentation.exchange)
    implementation(libs.nimbusds.oauth2.oidc.sdk)
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation(libs.bouncy.castle)
    implementation(libs.arrow.core)
    implementation(libs.arrow.fx.coroutines)
    implementation(libs.spring.boot.devtools)
    implementation(libs.jsonpath)
    implementation(libs.eudi.lib.jvm.sdjwt.kt)
    implementation(libs.waltid.mdoc.credentials)
    implementation(libs.upokecenter.cbor)
    implementation(libs.cbor)
    implementation(libs.cose.java)
}

java {
    val javaVersion = getVersionFromCatalog("java")
    sourceCompatibility = JavaVersion.toVersion(javaVersion)
}

kotlin {

    jvmToolchain {
        val javaVersion = getVersionFromCatalog("java")
        languageVersion.set(JavaLanguageVersion.of(javaVersion))
    }
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions {
        freeCompilerArgs += "-Xcontext-receivers"
        freeCompilerArgs += "-Xjsr305=strict"
    }
}

springBoot {
    buildInfo()
}

tasks.named<BootBuildImage>("bootBuildImage") {
    // get the BP_OCI_* from env, for https://github.com/paketo-buildpacks/image-labels
    // get the BP_JVM_* from env, jlink optimisation
    environment.set(System.getenv())
    val env = environment.get()
    docker {
        publishRegistry {
            env["REGISTRY_URL"]?.let { url = it }
            env["REGISTRY_USERNAME"]?.let { username = it }
            env["REGISTRY_PASSWORD"]?.let { password = it }
        }
        env["DOCKER_METADATA_OUTPUT_TAGS"]?.let { tagStr ->
            tags = tagStr.split(delimiters = arrayOf("\n", " ")).onEach { println("Tag: $it") }
        }
    }
}

fun getVersionFromCatalog(lookup: String): String {
    val versionCatalog: VersionCatalog = extensions.getByType<VersionCatalogsExtension>().named("libs")
    return versionCatalog
        .findVersion(lookup)
        .getOrNull()
        ?.requiredVersion
        ?: throw GradleException("Version '$lookup' is not specified in the version catalog")
}
