package abc.kplusgen.kplusgen

import androidx.annotation.NonNull
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import libkplusgenerator.Generator


class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            "generator"
        ).setMethodCallHandler { call, result ->
            if (call.method.equals("register")) {
                try {
                    val generator = Generator()
                    val accountNumber: String = call.argument("accountNumber")!!
                    val documentId: String = call.argument("documentId")!!
                    val pin: String = call.argument("pin")!!

                    result.success(generator.register(accountNumber, documentId, pin))
                } catch (e: Exception) {
                    result.error("register", e.message, null)
                }
            }
        }
    }

}
