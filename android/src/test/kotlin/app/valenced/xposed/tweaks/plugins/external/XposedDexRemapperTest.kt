package app.valenced.xposed.tweaks.plugins.external

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.AnnotationVisibility
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.iface.value.ArrayEncodedValue
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue
import com.android.tools.smali.dexlib2.immutable.ImmutableAnnotation
import com.android.tools.smali.dexlib2.immutable.ImmutableAnnotationElement
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableField
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference
import com.android.tools.smali.dexlib2.immutable.value.ImmutableArrayEncodedValue
import com.android.tools.smali.dexlib2.immutable.value.ImmutableStringEncodedValue
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlin.test.*

class XposedDexRemapperTest {
    private val tempDir: File = Files.createTempDirectory("valenced-dex-remap-test").toFile()

    @AfterTest
    fun cleanup() {
        tempDir.walkBottomUp().forEach { it.setWritable(true) }
        tempDir.deleteRecursively()
    }

    private fun testMappings(
        xposedObf: String = "LfG/BTZaGQKuxQfpF/zjyXZ/",
        appHelperObf: String = "LaB/cDefGhIjKlMnOpQrStU",
    ): List<PrefixMapping> = listOf(
        PrefixMapping(
            originalDescriptorPrefix = "Lde/robv/android/xposed/",
            runtimeDescriptorPrefix = xposedObf,
            originalJavaPrefix = "de.robv.android.xposed.",
            runtimeJavaPrefix = xposedObf.removePrefix("L").replace('/', '.'),
        ),
        PrefixMapping(
            originalDescriptorPrefix = "Landroid/app/AndroidApp",
            runtimeDescriptorPrefix = appHelperObf,
            originalJavaPrefix = "android.app.AndroidApp",
            runtimeJavaPrefix = appHelperObf.removePrefix("L").replace('/', '.'),
        ),
    )

    private fun buildDexBytes(includeXposedRefs: Boolean): ByteArray {
        val className = "Lme/example/PluginHooks;"
        val classDef = if (includeXposedRefs) {
            val unhooksField = ImmutableField(
                className,
                "unhooks",
                "[Lde/robv/android/xposed/XC_MethodHook\$Unhook;",
                AccessFlags.PRIVATE.value,
                null,
                listOf(
                    ImmutableAnnotation(
                        AnnotationVisibility.SYSTEM,
                        "Ldalvik/annotation/Signature;",
                        listOf(
                            ImmutableAnnotationElement(
                                "value",
                                ImmutableArrayEncodedValue(
                                    listOf(
                                        ImmutableStringEncodedValue(
                                            "Ljava/util/List<Lde/robv/android/xposed/XC_MethodHook\$Unhook;>;",
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                null,
            )

            val runMethod = ImmutableMethod(
                className,
                "run",
                listOf(ImmutableMethodParameter("Lde/robv/android/xposed/XC_MethodHook\$MethodHookParam;", emptySet<ImmutableAnnotation>(), "param")),
                "Lde/robv/android/xposed/XC_MethodHook\$Unhook;",
                AccessFlags.PUBLIC.value or AccessFlags.STATIC.value,
                emptySet<ImmutableAnnotation>(),
                null,
                ImmutableMethodImplementation(
                    3,
                    listOf(
                        ImmutableInstruction21c(
                            Opcode.CONST_STRING,
                            0,
                            ImmutableStringReference("de.robv.android.xposed.XposedBridge"),
                        ),
                        ImmutableInstruction35c(
                            Opcode.INVOKE_STATIC,
                            1,
                            0,
                            0,
                            0,
                            0,
                            0,
                            ImmutableMethodReference(
                                "Lde/robv/android/xposed/XposedBridge;",
                                "log",
                                listOf("Ljava/lang/String;"),
                                "V",
                            ),
                        ),
                        ImmutableInstruction35c(
                            Opcode.INVOKE_STATIC,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            ImmutableMethodReference(
                                "Landroid/app/AndroidAppHelper;",
                                "currentApplication",
                                emptyList<String>(),
                                "Landroid/app/Application;",
                            ),
                        ),
                        ImmutableInstruction21c(
                            Opcode.CONST_STRING,
                            1,
                            ImmutableStringReference("unchanged-literal"),
                        ),
                        ImmutableInstruction10x(Opcode.RETURN_VOID),
                    ),
                    emptyList(),
                    emptyList(),
                ),
            )

            ImmutableClassDef(
                className,
                AccessFlags.PUBLIC.value,
                "Lde/robv/android/xposed/XC_MethodHook;",
                emptyList(),
                "PluginHooks.kt",
                emptyList(),
                listOf(unhooksField),
                listOf(runMethod),
            )
        } else {
            ImmutableClassDef(
                className,
                AccessFlags.PUBLIC.value,
                "Ljava/lang/Object;",
                emptyList(),
                "Plain.kt",
                emptyList(),
                emptyList(),
                emptyList(),
            )
        }

        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.forDexVersion(37), listOf(classDef)))
        return store.data
    }

    private fun writeJar(file: File, vararg entries: Pair<String, ByteArray>): File {
        ZipOutputStream(FileOutputStream(file)).use { zos ->
            for ((name, bytes) in entries) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(bytes)
                zos.closeEntry()
            }
        }
        return file
    }

    private fun readJarEntries(file: File): Map<String, ByteArray> {
        val result = linkedMapOf<String, ByteArray>()
        ZipInputStream(FileInputStream(file)).use { zis ->
            while (true) {
                val entry = zis.nextEntry ?: break
                result[entry.name] = zis.readBytes()
                zis.closeEntry()
            }
        }
        return result
    }

    @Test
    fun `detectPrefixMapping returns null when class names are not obfuscated`() {
        assertNull(detectPrefixMapping("de.robv.android.xposed.XposedBridge", "Lde/robv/android/xposed/", "XposedBridge"))
        assertNull(detectPrefixMapping("android.app.AndroidAppHelper", "Landroid/app/AndroidApp", "Helper"))
        assertNull(detectPrefixMapping("android.content.res.XResources", "Landroid/content/res/XRes", "ources"))
        assertNull(detectPrefixMapping("android.content.res.XModuleResources", "Landroid/content/res/XModule", "Resources"))
    }

    @Test
    fun `detectPrefixMapping recovers descriptor and Java prefixes from obfuscated runtime names`() {
        val xposed = detectPrefixMapping(
            "fG.BTZaGQKuxQfpF.zjyXZ.XposedBridge",
            "Lde/robv/android/xposed/",
            "XposedBridge",
        )
        assertNotNull(xposed)
        assertEquals("LfG/BTZaGQKuxQfpF/zjyXZ/", xposed.runtimeDescriptorPrefix)
        assertEquals("fG.BTZaGQKuxQfpF.zjyXZ.", xposed.runtimeJavaPrefix)

        val helper = detectPrefixMapping(
            "aB.cDefGhIjKlMnOpQrStUHelper",
            "Landroid/app/AndroidApp",
            "Helper",
        )
        assertNotNull(helper)
        assertEquals("LaB/cDefGhIjKlMnOpQrStU", helper.runtimeDescriptorPrefix)
        assertEquals("aB.cDefGhIjKlMnOpQrStU", helper.runtimeJavaPrefix)
    }

    @Test
    fun `remapPluginJar rewrites types, arrays, method calls, annotations, and strings while preserving non-dex entries`() {
        val jar = writeJar(
            File(tempDir, "plugin.jar"),
            "classes.dex" to buildDexBytes(includeXposedRefs = true),
            "assets/info.txt" to "keep-me".toByteArray(),
        )
        val dexCache = File(tempDir, ".dex-cache").apply { mkdirs() }
        val mappings = testMappings()

        val remapped = remapPluginJar(jar, dexCache, "palmdevs.who-reacted", mappings)

        assertNotEquals(jar, remapped)
        assertTrue(remapped.isFile)
        assertFalse(remapped.canWrite(), "remapped jar must be read-only for Android 14+ DCL")

        val entries = readJarEntries(remapped)
        assertEquals("keep-me", entries.getValue("assets/info.txt").decodeToString())

        val dex = DexBackedDexFile(null, entries.getValue("classes.dex"))
        val cls = dex.classes.single()
        assertEquals("LfG/BTZaGQKuxQfpF/zjyXZ/XC_MethodHook;", cls.superclass)

        val field = cls.instanceFields.single()
        assertEquals("[LfG/BTZaGQKuxQfpF/zjyXZ/XC_MethodHook\$Unhook;", field.type)
        val sigAnnotation = field.annotations.single()
        val sigValues = (sigAnnotation.elements.single().value as ArrayEncodedValue).value
            .map { (it as StringEncodedValue).value }
        assertEquals(listOf("Ljava/util/List<LfG/BTZaGQKuxQfpF/zjyXZ/XC_MethodHook\$Unhook;>;"), sigValues)

        val method = cls.directMethods.single()
        assertEquals(
            listOf("LfG/BTZaGQKuxQfpF/zjyXZ/XC_MethodHook\$MethodHookParam;"),
            method.parameterTypes.map { it.toString() },
        )
        assertEquals("LfG/BTZaGQKuxQfpF/zjyXZ/XC_MethodHook\$Unhook;", method.returnType)

        val instructions = method.implementation!!.instructions.toList()
        val stringLiterals = instructions.filterIsInstance<ReferenceInstruction>()
            .mapNotNull { (it.reference as? StringReference)?.string }
        assertEquals(listOf("fG.BTZaGQKuxQfpF.zjyXZ.XposedBridge", "unchanged-literal"), stringLiterals)

        val calledClasses = instructions.filterIsInstance<ReferenceInstruction>()
            .mapNotNull { (it.reference as? MethodReference)?.definingClass }
        assertEquals(
            listOf("LfG/BTZaGQKuxQfpF/zjyXZ/XposedBridge;", "LaB/cDefGhIjKlMnOpQrStUHelper;"),
            calledClasses,
        )

        val allStrings = (0 until dex.stringSection.size).map { dex.stringSection[it] }
        assertTrue(allStrings.none { "de/robv/android/xposed" in it || "de.robv.android.xposed" in it })
        assertTrue(allStrings.none { "android/app/AndroidApp" in it || "android.app.AndroidApp" in it })
    }

    @Test
    fun `remapPluginJar caches per boot mapping, invalidates on update, and prunes stale boot dirs`() {
        val jar = writeJar(File(tempDir, "plugin.jar"), "classes.dex" to buildDexBytes(includeXposedRefs = true))
        val dexCache = File(tempDir, ".dex-cache").apply { mkdirs() }

        val firstMappings = testMappings(xposedObf = "LaA/aaaaaaaaaaaaa/aaaaa/")
        val first = remapPluginJar(jar, dexCache, "palmdevs.who-reacted", firstMappings)
        val cached = remapPluginJar(jar, dexCache, "palmdevs.who-reacted", firstMappings)
        assertEquals(first, cached)

        val secondMappings = testMappings(xposedObf = "LbB/bbbbbbbbbbbbb/bbbbb/")
        val afterReboot = remapPluginJar(jar, dexCache, "palmdevs.who-reacted", secondMappings)
        assertNotEquals(first.parentFile, afterReboot.parentFile)
        assertFalse(first.parentFile.exists(), "stale boot cache dir should be pruned")

        jar.setWritable(true)
        writeJar(
            jar,
            "classes.dex" to buildDexBytes(includeXposedRefs = true),
            "version.txt" to "2".toByteArray(),
        )
        val afterUpdate = remapPluginJar(jar, dexCache, "palmdevs.who-reacted", secondMappings)
        assertEquals(afterReboot.parentFile, afterUpdate.parentFile)
        assertNotEquals(afterReboot.name, afterUpdate.name)
    }

    @Test
    fun `remapPluginJar passes through unchanged jars and empty mappings`() {
        val plainJar = writeJar(File(tempDir, "plain.jar"), "classes.dex" to buildDexBytes(includeXposedRefs = false))
        val xposedJar = writeJar(File(tempDir, "xposed.jar"), "classes.dex" to buildDexBytes(includeXposedRefs = true))
        val dexCache = File(tempDir, ".dex-cache").apply { mkdirs() }

        assertEquals(plainJar, remapPluginJar(plainJar, dexCache, "plain", testMappings()))
        assertEquals(xposedJar, remapPluginJar(xposedJar, dexCache, "xposed", emptyList()))
    }
}
