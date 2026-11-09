package com.apex.security

import android.os.Bundle
import android.content.Intent
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.Inet4Address
import java.net.Socket
import java.net.InetSocketAddress
import java.util.concurrent.Callable
import java.util.concurrent.Executors
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
    var subnet by remember { mutableStateOf("192.168.1.0/24") }
    var targetIp by remember { mutableStateOf("192.168.1.1") }
    val context = LocalContext.current
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
            Text("ENTERPRISE LAN INVENTORY", color = Accent, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            OutlinedTextField(
                value = subnet, onValueChange = { subnet = it }, label = { Text("Private LAN subnet (e.g. 192.168.1.0/24)") },
                modifier = Modifier.fillMaxWidth(), singleLine = true
            )
            ActionButton("Discover LAN devices", Modifier.fillMaxWidth(), busy) {
                runCheck(scope, { discoverLan(subnet) }, { output = it }, { busy = it })
            }
            OutlinedTextField(
                value = targetIp, onValueChange = { targetIp = it }, label = { Text("Private IPv4 target for port audit") },
                modifier = Modifier.fillMaxWidth(), singleLine = true
            )
            ActionButton("Audit common TCP ports", Modifier.fillMaxWidth(), busy) {
                runCheck(scope, { portAudit(targetIp) }, { output = it }, { busy = it })
            }
            ActionButton("Share current report", Modifier.fillMaxWidth(), busy) {
                val share = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, "APEX Enterprise Security Report")
                    putExtra(Intent.EXTRA_TEXT, output)
                }
                context.startActivity(Intent.createChooser(share, "Share APEX report"))
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
    for (i in chars.lastIndex downTo 1) {
        val j = random.nextInt(i + 1)
        val temp = chars[i]
        chars[i] = chars[j]
        chars[j] = temp
    }
    return chars.joinToString("")
}


private fun isPrivateAddress(ip: Inet4Address): Boolean {
    val b = ip.address.map { it.toInt() and 0xff }
    return b[0] == 10 || (b[0] == 172 && b[1] in 16..31) || (b[0] == 192 && b[1] == 168)
}

private fun tcpConnects(host: String, port: Int): Boolean = try {
    Socket().use { it.connect(InetSocketAddress(host, port), 300) }
    true
} catch (_: Exception) { false }

private fun discoverLan(input: String): String {
    val parts = input.trim().split("/")
    require(parts.size == 2 && parts[1] == "24") { "Enter a private IPv4 /24 subnet, e.g. 192.168.1.0/24." }
    val network = InetAddress.getByName(parts[0]) as? Inet4Address ?: error("IPv4 required.")
    require(isPrivateAddress(network)) { "Only private RFC1918 IPv4 ranges are allowed." }
    val b = network.address
    require((b[3].toInt() and 0xff) == 0) { "Use the network address ending in .0/24." }
    val prefix = "${b[0].toInt() and 255}.${b[1].toInt() and 255}.${b[2].toInt() and 255}"
    val local = NetworkInterface.getNetworkInterfaces().toList().flatMap { it.inetAddresses.toList() }
        .filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress }.toSet()
    val pool = Executors.newFixedThreadPool(32)
    try {
        val tasks = (1..254).filter { "$prefix.$it" !in local }.map { n ->
            Callable {
                val ip = "$prefix.$n"
                val ports = listOf(22, 80, 443, 445, 8080, 8443).filter { tcpConnects(ip, it) }
                if (ports.isEmpty()) null else "$ip  |  TCP open: ${ports.joinToString(",")}"
            }
        }
        val found = pool.invokeAll(tasks).mapNotNull { it.get() }
        "LAN INVENTORY: $input\nResponsive hosts: ${found.size}\n\n" +
            (if (found.isEmpty()) "No hosts responded on the tested ports. Firewalls may hide active devices." else found.joinToString("\n")) +
            "\n\nOnly the explicitly entered private /24 was checked. This is not a full device census."
    } finally { pool.shutdownNow() }
}

private fun portAudit(input: String): String {
    val ip = InetAddress.getByName(input.trim()) as? Inet4Address ?: error("Enter a private IPv4 address.")
    require(isPrivateAddress(ip)) { "Port audit is restricted to private RFC1918 IPv4 addresses." }
    val ports = listOf(22, 53, 80, 443, 445, 8080, 8443)
    val open = ports.filter { tcpConnects(ip.hostAddress, it) }
    return "TARGET: ${ip.hostAddress}\nCHECKED TCP: ${ports.joinToString(", ")}\nOPEN: ${if (open.isEmpty()) "None detected" else open.joinToString(", ")}\n\nAn open port is not automatically a vulnerability. Verify the service and restrict unnecessary exposure."
}

private fun <T> java.util.Enumeration<T>.toList(): List<T> {
    val values = mutableListOf<T>()
    while (hasMoreElements()) values += nextElement()
    return values
}
