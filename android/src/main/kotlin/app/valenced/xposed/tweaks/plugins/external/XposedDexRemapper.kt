package app.valenced.xposed.tweaks.plugins.external

import android.app.AndroidAppHelper
import android.content.res.XModuleResources
import android.content.res.XResources
import app.valenced.plugins.pluginLog
import com.android.tools.smali.dexlib2.ReferenceType
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21c
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction31c
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.iface.value.EncodedValue
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.immutable.value.ImmutableStringEncodedValue
import com.android.tools.smali.dexlib2.rewriter.DexRewriter
import com.android.tools.smali.dexlib2.rewriter.EncodedValueRewriter
import com.android.tools.smali.dexlib2.rewriter.InstructionRewriter
import com.android.tools.smali.dexlib2.rewriter.Rewriter
import com.android.tools.smali.dexlib2.rewriter.RewriterModule
import com.android.tools.smali.dexlib2.rewriter.Rewriters
import com.android.tools.smali.dexlib2.rewriter.TypeRewriter
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import de.robv.android.xposed.XposedBridge
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

private const val REMAPPED_DIR_PREFIX = "remapped-"

internal data class PrefixMapping(
    val originalDescriptorPrefix: String,
    val runtimeDescriptorPrefix: String,
    val originalJavaPrefix: String,
    val runtimeJavaPrefix: String,
)

private val runtimeXposedMappings: List<PrefixMapping> by lazy { detectRuntimeXposedMappings() }

internal fun remapJarForObfuscatedXposedIfNeeded(
    jar: File,
    dexCache: File,
    pluginId: String,
): File = remapPluginJar(jar, dexCache, pluginId, runtimeXposedMappings)

internal fun detectRuntimeXposedMappings(): List<PrefixMapping> = listOfNotNull(
    detectClass(descriptorPrefix("de", "robv", "android", "xposed", ""), "XposedBridge") {
        XposedBridge::class.java.name
    },
    detectClass(descriptorPrefix("android", "app", "AndroidApp"), "Helper") {
        AndroidAppHelper::class.java.name
    },
    detectClass(descriptorPrefix("android", "content", "res", "XRes"), "ources") {
        XResources::class.java.name
    },
    detectClass(descriptorPrefix("android", "content", "res", "XModule"), "Resources") {
        XModuleResources::class.java.name
    },
)

// Build prefixes at runtime so framework DEX string obfuscation (e.g. Vector/LSPosed) does not
// rewrite our original-prefix constants inside this module's own DEX.
private fun descriptorPrefix(vararg segments: String): String = "L" + segments.joinToString("/")

private fun detectClass(
    originalDescriptorPrefix: String,
    unchangedSuffix: String,
    classNameProvider: () -> String,
): PrefixMapping? = runCatching {
    detectPrefixMapping(classNameProvider(), originalDescriptorPrefix, unchangedSuffix)
}.getOrNull()

internal fun detectPrefixMapping(
    runtimeClassName: String,
    originalDescriptorPrefix: String,
    unchangedSuffix: String,
): PrefixMapping? {
    if (!runtimeClassName.endsWith(unchangedSuffix)) return null
    val runtimeJavaPrefix = runtimeClassName.removeSuffix(unchangedSuffix)
    val runtimeDescriptorPrefix = "L" + runtimeJavaPrefix.replace('.', '/')
    if (runtimeDescriptorPrefix == originalDescriptorPrefix) return null
    val originalJavaPrefix = originalDescriptorPrefix.removePrefix("L").replace('/', '.')
    return PrefixMapping(
        originalDescriptorPrefix = originalDescriptorPrefix,
        runtimeDescriptorPrefix = runtimeDescriptorPrefix,
        originalJavaPrefix = originalJavaPrefix,
        runtimeJavaPrefix = runtimeJavaPrefix,
    )
}

internal fun remapPluginJar(
    jar: File,
    dexCache: File,
    pluginId: String,
    mappings: List<PrefixMapping>,
): File {
    if (mappings.isEmpty()) return jar

    val bootKey = sha256Hex(
        mappings.joinToString("\n") { "${it.originalDescriptorPrefix}->${it.runtimeDescriptorPrefix}" }
            .toByteArray(Charsets.UTF_8),
    ).take(16)
    val bootDirName = "$REMAPPED_DIR_PREFIX$bootKey"
    val bootDir = File(dexCache, bootDirName).apply { mkdirs() }
    pruneStaleRemappedDirs(dexCache, bootDirName)

    val safePluginId = pluginId.replace(Regex("[^A-Za-z0-9._-]"), "_")
    val jarHash = sha256Hex(jar).take(16)
    val cachedJar = File(bootDir, "$safePluginId-$jarHash.jar")
    if (cachedJar.isFile) {
        cachedJar.setReadOnly()
        return cachedJar
    }

    val asciiNeedles = mappings.flatMap {
        listOf(
            it.originalDescriptorPrefix.toByteArray(Charsets.UTF_8),
            it.originalJavaPrefix.toByteArray(Charsets.UTF_8),
        )
    }

    val entries = mutableListOf<Pair<String, ByteArray>>()
    var anyRemapped = false

    ZipInputStream(FileInputStream(jar).buffered()).use { zis ->
        while (true) {
            val entry = zis.nextEntry ?: break
            if (entry.isDirectory) {
                zis.closeEntry()
                continue
            }
            val raw = zis.readBytes()
            zis.closeEntry()

            val processed = if (entry.name.endsWith(".dex") && containsAnyBytes(raw, asciiNeedles)) {
                anyRemapped = true
                remapDexBytes(raw, mappings)
            } else {
                raw
            }
            entries += entry.name to processed
        }
    }

    if (!anyRemapped) return jar

    val tmp = File(bootDir, ".${cachedJar.name}.${UUID.randomUUID()}.tmp")
    try {
        ZipOutputStream(FileOutputStream(tmp).buffered()).use { zos ->
            for ((name, data) in entries) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(data)
                zos.closeEntry()
            }
        }
        tmp.setReadOnly()
        if (!tmp.renameTo(cachedJar)) {
            tmp.delete()
            if (!cachedJar.isFile) {
                throw IllegalStateException("Failed to move remapped jar into place: $cachedJar")
            }
        }
        cachedJar.setReadOnly()
    } catch (t: Throwable) {
        tmp.delete()
        throw t
    }

    pluginLog.i("Remapped plugin DEX for obfuscated Xposed runtime: $pluginId -> ${cachedJar.name}")
    return cachedJar
}

internal fun remapDexBytes(dexBytes: ByteArray, mappings: List<PrefixMapping>): ByteArray {
    val dexFile = DexBackedDexFile(null, dexBytes)
    val rewriter = DexRewriter(
        object : RewriterModule() {
            override fun getTypeRewriter(rewriters: Rewriters): Rewriter<String> = object : TypeRewriter() {
                override fun rewriteUnwrappedType(type: String): String {
                    for (m in mappings) {
                        if (type.startsWith(m.originalDescriptorPrefix)) {
                            return m.runtimeDescriptorPrefix + type.substring(m.originalDescriptorPrefix.length)
                        }
                    }
                    return type
                }
            }

            override fun getEncodedValueRewriter(rewriters: Rewriters): Rewriter<EncodedValue> =
                object : EncodedValueRewriter(rewriters) {
                    override fun rewrite(value: EncodedValue): EncodedValue {
                        if (value is StringEncodedValue) {
                            val remapped = remapString(value.value, mappings)
                            if (remapped != value.value) return ImmutableStringEncodedValue(remapped)
                            return value
                        }
                        return super.rewrite(value)
                    }
                }

            override fun getInstructionRewriter(rewriters: Rewriters): Rewriter<Instruction> =
                object : InstructionRewriter(rewriters) {
                    override fun rewrite(instruction: Instruction): Instruction {
                        if (instruction is ReferenceInstruction && instruction.referenceType == ReferenceType.STRING) {
                            val ref = instruction.reference as StringReference
                            val remapped = remapString(ref.string, mappings)
                            if (remapped != ref.string) {
                                val newRef = ImmutableStringReference(remapped)
                                return when (instruction) {
                                    is Instruction21c -> ImmutableInstruction21c(
                                        instruction.opcode,
                                        instruction.registerA,
                                        newRef,
                                    )
                                    is Instruction31c -> ImmutableInstruction31c(
                                        instruction.opcode,
                                        instruction.registerA,
                                        newRef,
                                    )
                                    else -> super.rewrite(instruction)
                                }
                            }
                        }
                        return super.rewrite(instruction)
                    }
                }
        },
    )

    val rewritten = rewriter.dexFileRewriter.rewrite(dexFile)
    val store = MemoryDataStore()
    DexPool.writeTo(store, rewritten)
    return store.data
}

private fun remapString(input: String, mappings: List<PrefixMapping>): String {
    var result = input
    for (m in mappings) {
        if (m.originalDescriptorPrefix in result) {
            result = result.replace(m.originalDescriptorPrefix, m.runtimeDescriptorPrefix)
        }
        if (m.originalJavaPrefix in result) {
            result = result.replace(m.originalJavaPrefix, m.runtimeJavaPrefix)
        }
    }
    return result
}

private fun pruneStaleRemappedDirs(dexCache: File, keepDirName: String) {
    dexCache.listFiles()?.forEach { child ->
        if (child.isDirectory && child.name.startsWith(REMAPPED_DIR_PREFIX) && child.name != keepDirName) {
            runCatching { child.deleteRecursively() }
        }
    }
}

private fun containsAnyBytes(haystack: ByteArray, needles: List<ByteArray>): Boolean {
    for (needle in needles) {
        if (indexOfBytes(haystack, needle) >= 0) return true
    }
    return false
}

private fun indexOfBytes(haystack: ByteArray, needle: ByteArray): Int {
    if (needle.isEmpty()) return 0
    val limit = haystack.size - needle.size
    if (limit < 0) return -1
    val first = needle[0]
    var i = 0
    while (i <= limit) {
        if (haystack[i] == first) {
            var j = 1
            while (j < needle.size && haystack[i + j] == needle[j]) j++
            if (j == needle.size) return i
        }
        i++
    }
    return -1
}

private fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

private fun sha256Hex(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buf = ByteArray(8192)
    FileInputStream(file).use { input ->
        while (true) {
            val read = input.read(buf)
            if (read <= 0) break
            digest.update(buf, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
