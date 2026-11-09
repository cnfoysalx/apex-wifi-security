package com.apex.security

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.NetworkInterface
import java.security.SecureRandom
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

private val Bg = Color(0xFF080D16)
private val Panel = Color(0xFF111B2B)
private val Accent = Color(0xFF31E6A0)
private val Muted = Color(0xFF9AA9BD)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { ApexApp() }
    }
}

@Composable
private fun ApexApp() {
    var output by remember { mutableStateOf("APEX is ready. Choose a security check.") }
    var host by remember { mutableStateOf("example.com") }
    var passphrase by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    MaterialTheme(colorScheme = darkColorScheme(
        background = Bg, surface = Panel, primary = Accent,
        onBackground = Color.White, onSurface = Color.White
    )) {
        Column(
            Modifier.fillMaxSize().background(Bg).verticalScroll(rememberScrollState()).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("APEX", color = Accent, fontSize = 30.sp, fontWeight = FontWeight.Black)
                    Text("ANDROID SECURITY AUDITOR  •  v1.0", color = Muted, fontSize = 11.sp)
                }
                Surface(color = Color(0xFF123A30), shape = RoundedCornerShape(50)) {
                    Text("● READY", color = Accent, modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp), fontSize = 11.sp)
                }
            }
            Card(colors = CardDefaults.cardColors(containerColor = Panel)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("DEFENSIVE SECURITY CONSOLE", color = Muted, fontSize = 11.sp)
                    Text("Your network. Your security.", fontSize = 21.sp, fontWeight = FontWeight.Bold)
                    Text("Read-only diagnostics for networks and websites you own or are authorized to assess.", color = Muted, fontSize = 13.sp)
                }
            }
            Text("NETWORK DIAGNOSTICS", color = Accent, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                ActionButton("Network info", Modifier.weight(1f), busy) {
                    runCheck(scope, { networkSummary() }, { output = it }, { busy = it })
                }
                ActionButton("Router checklist", Modifier.weight(1f), busy) {
                    output = listOf(
                        "Use WPA3-Personal or WPA2-AES/CCMP",
                        "Disable WPS if not needed",
                        "Set a unique router admin password",
                        "Install official firmware updates",
                        "Disable remote admin unless required",
                        "Review connected devices in router settings",
                        "Use a separate guest network"
                    ).mapIndexed { i, s -> "${i + 1}. $s" }.joinToString("\n")
                }
            }
            Text("WEBSITE CHECKS", color = Accent, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            OutlinedTextField(
                value = host, onValueChange = { host = it }, label = { Text("Hostname (e.g. example.com)") },
                modifier = Modifier.fillMaxWidth(), singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Accent, focusedLabelColor = Accent,
                    unfocusedBorderColor = Muted, focusedTextColor = Color.White, unfocusedTextColor = Color.White
                )
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                ActionButton("DNS lookup", Modifier.weight(1f), busy) {
                    runCheck(scope, { dnsSummary(host) }, { output = it }, { busy = it })
                }
                ActionButton("TLS audit", Modifier.weight(1f), busy) {
                    runCheck(scope, { tlsSummary(host) }, { output = it }, { busy = it })
                }
            }
            Text("PASSPHRASE AUDIT", color = Accent, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            OutlinedTextField(
                value = passphrase, onValueChange = { passphrase = it },
                label = { Text("Enter passphrase (processed locally)") },
                modifier = Modifier.fillMaxWidth(), singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Accent, focusedLabelColor = Accent,
                    unfocusedBorderColor = Muted, focusedTextColor = Color.White, unfocusedTextColor = Color.White
                )
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                ActionButton("Check strength", Modifier.weight(1f), busy) {
                    output = auditPassphrase(passphrase)
                }
                ActionButton("Generate", Modifier.weight(1f), busy) {
                    passphrase = securePassphrase()
                    output = "Generated a new passphrase. Store it securely; it is not uploaded."
                }
            }
            Card(colors = CardDefaults.cardColors(containerColor = Panel)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(if (busy) "RUNNING CHECK…" else "RESULT / OUTPUT", color = Accent, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    Text(output, color = Color(0xFFE1E8F0), fontSize = 13.sp)
                }
            }
            Text("APEX performs non-destructive checks only. No Wi-Fi cracking, packet capture, deauthentication, exploitation or unauthorized access.", color = Muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun ActionButton(label: String, modifier: Modifier, disabled: Boolean, action: () -> Unit) {
    Button(onClick = action, enabled = !disabled, modifier = modifier.heightIn(min = 48.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF153C35), contentColor = Accent),
        shape = RoundedCornerShape(12.dp)) { Text(label, fontWeight = FontWeight.SemiBold, fontSize = 12.sp) }
}

private fun runCheck(
    scope: kotlinx.coroutines.CoroutineScope,
    task: suspend () -> String,
    onResult: (String) -> Unit,
    onBusy: (Boolean) -> Unit
) {
    scope.launch {
        onBusy(true)
        val result = withContext(Dispatchers.IO) { runCatching { task() }.getOrElse { "Check failed: ${it.message ?: "unknown error"}" } }
        onResult(result)
        onBusy(false)
    }
}

private fun networkSummary(): String {
    val lines = mutableListOf("DEVICE: ${android.os.Build.MODEL}", "ANDROID: ${android.os.Build.VERSION.RELEASE}")
    val interfaces = NetworkInterface.getNetworkInterfaces()
    while (interfaces.hasMoreElements()) {
        val item = interfaces.nextElement()
        val addresses = item.inetAddresses
        while (addresses.hasMoreElements()) {
            val address = addresses.nextElement()
            if (!address.isLoopbackAddress && address is java.net.Inet4Address) {
                lines += "INTERFACE: ${item.name}"
                lines += "LOCAL IPv4: ${address.hostAddress}"
            }
        }
    }
    return lines.distinct().joinToString("\n")
}

private fun dnsSummary(hostInput: String): String {
    val host = hostInput.trim().removePrefix("https://").removePrefix("http://").substringBefore("/")
    require(host.isNotBlank() && !host.contains(" ")) { "Enter a valid hostname." }
    val addresses = InetAddress.getAllByName(host)
    return "DNS: $host\n" + addresses.joinToString("\n") { it.hostAddress }
}

private fun tlsSummary(hostInput: String): String {
    val host = hostInput.trim().removePrefix("https://").removePrefix("http://").substringBefore("/").substringBefore(":")
    require(host.isNotBlank() && !host.contains(" ")) { "Enter a valid hostname." }
    val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
    val socket = factory.createSocket(host, 443) as SSLSocket
    socket.soTimeout = 7000
    socket.use {
        it.startHandshake()
        val cert = it.session.peerCertificates.first()
        return "TLS HOST: $host\nTLS VERSION: ${it.session.protocol}\nCIPHER: ${it.session.cipherSuite}\nCERTIFICATE: ${cert.type}\nVALIDATION: system trust checks passed"
    }
}

private fun auditPassphrase(value: String): String {
    if (value.isEmpty()) return "Enter a passphrase to audit."
    val findings = mutableListOf<String>()
    if (value.length < 8) findings += "Below the 8-character Wi-Fi passphrase minimum."
    if (value.length > 63) findings += "Over the 63-character Wi-Fi passphrase limit."
    val lower = value.lowercase()
    if (listOf("password", "12345678", "qwerty", "admin", "welcome").any { it in lower }) findings += "Contains a common word or predictable sequence."
    if (value.toSet().size <= 2) findings += "Uses too few distinct characters."
    if (value.all { it.isLetter() } || value.all { it.isDigit() }) findings += "Uses only one character category."
    return "Length: ${value.length}\nAssessment: ${if (findings.isEmpty() && value.length >= 16) "Stronger (heuristic)" else "Needs improvement"}\n" +
        (if (findings.isEmpty()) "No obvious weak patterns found." else findings.joinToString("\n- ", prefix = "- ")) +
        "\n\nOffline heuristic only; not a crack-time prediction. The passphrase is not sent anywhere."
}

private fun securePassphrase(): String {
    val random = SecureRandom()
    val groups = listOf("abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%*-_+=")
    val all = groups.joinToString("")
    val chars = groups.map { it[random.nextInt(it.length)] }.toMutableList()
    repeat(20) { chars += all[random.nextInt(all.length)] }
    chars.shuffle(random)
    return chars.joinToString("")
}
