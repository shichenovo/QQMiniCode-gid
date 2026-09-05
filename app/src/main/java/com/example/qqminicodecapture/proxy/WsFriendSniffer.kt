// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.proxy

import org.json.JSONArray
import org.json.JSONObject

/**
 * v2.1 "抓包即解析"核心 —— WebSocket 下行帧嗅探器。
 *
 * 背景（对照实验已验证）：
 *   QQ 客户端登录农场后会自动发 SyncAll(带全量 open_id)，服务器明文回 145 位好友
 *   （GameFriend: gid/open_id/name/level…），与翻不翻页无关。服务器→客户端方向
 *   的 WS payload（gatepb.Message）不加密，MITM 解密后的明文中即可直接提取。
 *
 * 本类挂在 MitmTunnel 的"服务器→客户端"泵上，只读不改：
 *   1) HTTP/1.1 101 响应头（WebSocket 升级）→ 之后按 RFC6455 解析服务端帧
 *   2) binary 帧 payload → 极简 protobuf 扫描（不引第三方库）
 *   3) 命中 FriendService.{SyncAll,GetAll,GetGameFriends} 响应 → 提取好友列表
 *      （Login 响应顺带取自身 gid 用于排除）
 *   4) 结果经 [onFriends] 回调上抛（由 MitmTunnel 转发 CodeBus 广播到主进程 UI）
 *
 * 帧可能跨多个 TLS 明文块、一块也可能含多帧：全部走缓冲按需消费。
 * 服务端帧无掩码（RFC6455 仅客户端→服务端加掩码）；若 RSV1 置位(permessage-deflate，
 * 实测握手未协商)则跳过不解，保证不误读。
 *
 * 依赖注入设计：本类不引用任何 Android 框架类，便于 JVM 单测
 * （用真实抓包字节离线验证解析正确性）。
 */
class WsFriendSniffer(private val tag: String) {

    /** 解出一批好友时的回调：(selfGid, friendsJsonArray) */
    var onFriends: (Long, String) -> Unit = { _, _ -> }

    /** 日志回调（可注入 AppLogger / 测试打印） */
    var logger: (String) -> Unit = {}

    /** 日志限频间隔(ms)，测试可置 0 关闭限频 */
    var minLogIntervalMs: Long = 500

    companion object {
        private const val OP_CONT = 0x0
        private const val OP_TEXT = 0x1
        private const val OP_BINARY = 0x2
        private const val OP_CLOSE = 0x8
        private const val OP_PING = 0x9
        private const val OP_PONG = 0xA

        private val FRIEND_METHODS = setOf("SyncAll", "GetAll", "GetGameFriends")

        // 阶段
        private const val PH_HEAD = 0
        private const val PH_EXT = 1
        private const val PH_PAYLOAD = 2
    }

    @Volatile var selfGid: Long = 0
        private set

    /** 统计：已解析完整 WS 消息数（测试/诊断用） */
    @Volatile var wsMessagesParsed: Int = 0
        private set

    /** 统计：命中 FriendService 响应并解出好友的批次数 */
    @Volatile var friendBatches: Int = 0
        private set

    private val buf = java.io.ByteArrayOutputStream()
    private var httpHeadDone = false
    private var upgraded = false

    // WS 解析状态
    private var phase = PH_HEAD
    private var extNeed = 0
    private var frameOpcode = 0
    private var frameFin = true
    private var frameSkip = false
    private var payloadLen = 0L

    private var contBuf = java.io.ByteArrayOutputStream()
    private var contOpen = false
    private var contOpcode = 0

    private var lastLogTs = 0L

    private fun log(msg: String) {
        val now = System.currentTimeMillis()
        if (minLogIntervalMs > 0 && now - lastLogTs < minLogIntervalMs) return
        lastLogTs = now
        try { logger("[$tag] $msg") } catch (_: Throwable) {}
    }

    /** 由 MitmTunnel u2c 泵逐块喂入明文数据（服务器→客户端方向）。任何异常都吞，绝不影响转发。 */
    fun feed(data: ByteArray) {
        try {
            buf.write(data)
            if (!httpHeadDone) {
                if (!tryParseHttpHead()) return
            }
            if (!upgraded) return
            pumpWs()
        } catch (_: Throwable) {
        }
    }

    /** 消费缓冲前 n 字节并返回 */
    private fun take(n: Int): ByteArray {
        val bytes = buf.toByteArray()
        val out = bytes.copyOfRange(0, n)
        val rest = bytes.size - n
        buf.reset()
        if (rest > 0) buf.write(bytes, n, rest)
        return out
    }

    private fun tryParseHttpHead(): Boolean {
        val bytes = buf.toByteArray()
        var end = -1
        var i = 0
        while (i <= bytes.size - 4) {
            if (bytes[i] == 0x0d.toByte() && bytes[i + 1] == 0x0a.toByte() &&
                bytes[i + 2] == 0x0d.toByte() && bytes[i + 3] == 0x0a.toByte()
            ) { end = i + 4; break }
            i++
        }
        if (end < 0) {
            if (bytes.size > 65536) httpHeadDone = true
            return false
        }
        val head = String(bytes, 0, end, Charsets.ISO_8859_1)
        httpHeadDone = true
        upgraded = head.startsWith("HTTP/1.1 101") || head.startsWith("HTTP/1.0 101") ||
            Regex("(?i)^upgrade:\\s*websocket", RegexOption.MULTILINE).containsMatchIn(head)
        val rest = bytes.copyOfRange(end, bytes.size)
        buf.reset()
        if (upgraded) {
            if (rest.isNotEmpty()) buf.write(rest)
            log("WS 升级成功，开始嗅探下行帧 (${rest.size}B 余量)")
        }
        return true
    }

    // ------------------------------------------------------------------ WS 帧

    private fun pumpWs() {
        while (true) {
            val avail = buf.size()
            when (phase) {
                PH_HEAD -> {
                    if (avail < 2) return
                    val b0 = buf.toByteArray()[0].toInt() and 0xFF
                    val b1 = buf.toByteArray()[1].toInt() and 0xFF
                    frameFin = (b0 and 0x80) != 0
                    val rsv = b0 and 0x70
                    frameOpcode = b0 and 0x0F
                    val masked = (b1 and 0x80) != 0
                    val len7 = (b1 and 0x7F).toLong()
                    frameSkip = rsv != 0
                    take(2)
                    if (masked) {
                        // 服务端帧不应有掩码；保守停嗅探（不影响转发）
                        phase = PH_HEAD
                        return
                    }
                    when {
                        len7 < 126 -> {
                            payloadLen = len7
                            phase = PH_PAYLOAD
                        }
                        len7 == 126L -> { extNeed = 2; phase = PH_EXT }
                        else -> { extNeed = 8; phase = PH_EXT }
                    }
                }
                PH_EXT -> {
                    if (avail < extNeed) return
                    val ext = take(extNeed)
                    var v = 0L
                    for (b in ext) v = (v shl 8) or (b.toLong() and 0xFF)
                    payloadLen = v
                    phase = PH_PAYLOAD
                }
                PH_PAYLOAD -> {
                    if (payloadLen == 0L) {
                        phase = PH_HEAD
                        onFrameComplete(ByteArray(0))
                        continue
                    }
                    if (payloadLen > Int.MAX_VALUE) { phase = PH_HEAD; return } // 异常大帧，放弃
                    if (avail < payloadLen.toInt()) return
                    val payload = take(payloadLen.toInt())
                    phase = PH_HEAD
                    onFrameComplete(payload)
                }
            }
        }
    }

    private fun onFrameComplete(payload: ByteArray) {
        if (frameSkip) return
        when (frameOpcode) {
            OP_TEXT, OP_BINARY -> {
                if (frameFin) {
                    handleMessage(payload)
                } else {
                    contBuf.reset()
                    contBuf.write(payload)
                    contOpcode = frameOpcode
                    contOpen = true
                }
            }
            OP_CONT -> {
                if (contOpen) {
                    contBuf.write(payload)
                    if (frameFin) {
                        val full = contBuf.toByteArray()
                        contBuf.reset()
                        contOpen = false
                        handleMessage(full)
                    }
                }
            }
            else -> { /* 控制帧忽略 */ }
        }
    }

    // ------------------------------------------------------------------ proto

    private fun handleMessage(payload: ByteArray) {
        wsMessagesParsed++
        try {
            val gm = scanGateMessage(payload) ?: return
            if (gm.metaMsgType != 2 && gm.metaMsgType != 3) return
            val svc = gm.serviceName
            val mtd = gm.methodName
            if (svc.endsWith("FriendService") && FRIEND_METHODS.contains(mtd)) {
                val friends = scanGameFriends(gm.body)
                if (friends.isNotEmpty()) {
                    friendBatches++
                    log("解析到 $mtd 好友 ${friends.size} 个")
                    try { onFriends(selfGid, JSONArray(friends).toString()) } catch (_: Throwable) {}
                }
            } else if (svc.endsWith("UserService") && mtd == "Login") {
                val gid = scanLoginSelfGid(gm.body)
                if (gid > 0) {
                    selfGid = gid
                    log("自身 gid = $gid")
                }
            }
        } catch (_: Throwable) {
        }
    }

    private class GateMsg {
        var serviceName = ""
        var methodName = ""
        var metaMsgType = 0
        var body = ByteArray(0)
    }

    // gatepb.Message: meta=1(msg), body=2(bytes), token=3
    private fun scanGateMessage(data: ByteArray): GateMsg? {
        val gm = GateMsg()
        var pos = 0
        while (pos < data.size) {
            val (tag, tLen) = readTag(data, pos) ?: return gm
            pos += tLen
            val field = (tag ushr 3).toInt()
            val wire = (tag and 7).toInt()
            when (wire) {
                0 -> { val r = readVarint(data, pos) ?: return gm; pos += r.second }
                1 -> { if (pos + 8 > data.size) return gm; pos += 8 }
                2 -> {
                    val len = readVarint(data, pos)?.first?.toInt() ?: return gm
                    pos += varintLenAt(data, pos)
                    if (pos + len > data.size) return gm
                    val sub = data.copyOfRange(pos, pos + len)
                    when (field) {
                        1 -> {
                            val meta = scanMeta(sub)
                            gm.serviceName = meta.first
                            gm.methodName = meta.second
                            gm.metaMsgType = meta.third
                        }
                        2 -> gm.body = sub
                    }
                    pos += len
                }
                5 -> { if (pos + 4 > data.size) return gm; pos += 4 }
                else -> return gm
            }
        }
        return gm
    }

    private fun scanMeta(data: ByteArray): Triple<String, String, Int> {
        var svc = ""; var mtd = ""; var mt = 0
        var pos = 0
        while (pos < data.size) {
            val (tag, tLen) = readTag(data, pos) ?: break
            pos += tLen
            val field = (tag ushr 3).toInt()
            val wire = (tag and 7).toInt()
            when (wire) {
                0 -> {
                    val r = readVarint(data, pos) ?: break
                    if (field == 3) mt = r.first.toInt()
                    pos += r.second
                }
                1 -> { if (pos + 8 > data.size) break; pos += 8 }
                2 -> {
                    val len = readVarint(data, pos)?.first?.toInt() ?: break
                    pos += varintLenAt(data, pos)
                    if (pos + len > data.size) break
                    when (field) {
                        1 -> svc = String(data, pos, len, Charsets.UTF_8)
                        2 -> mtd = String(data, pos, len, Charsets.UTF_8)
                    }
                    pos += len
                }
                5 -> { if (pos + 4 > data.size) break; pos += 4 }
                else -> break
            }
        }
        return Triple(svc, mtd, mt)
    }

    // SyncAllReply/GetAllReply/GetGameFriendsReply: game_friends=1(repeated GameFriend)
    // GameFriend: gid=1(int64), open_id=2(str), name=3(str), level=6(int64)
    private fun scanGameFriends(data: ByteArray): List<JSONObject> {
        val out = ArrayList<JSONObject>()
        var pos = 0
        while (pos < data.size) {
            val (tag, tLen) = readTag(data, pos) ?: break
            pos += tLen
            val field = (tag ushr 3).toInt()
            val wire = (tag and 7).toInt()
            when (wire) {
                0 -> { val r = readVarint(data, pos) ?: break; pos += r.second }
                1 -> { if (pos + 8 > data.size) break; pos += 8 }
                2 -> {
                    val len = readVarint(data, pos)?.first?.toInt() ?: break
                    pos += varintLenAt(data, pos)
                    if (pos + len > data.size) break
                    if (field == 1) {
                        val gf = scanGameFriend(data.copyOfRange(pos, pos + len))
                        if (gf != null) out.add(gf)
                    }
                    pos += len
                }
                5 -> { if (pos + 4 > data.size) break; pos += 4 }
                else -> break
            }
        }
        return out
    }

    private fun scanGameFriend(data: ByteArray): JSONObject? {
        var gid = 0L; var openId = ""; var name = ""; var level = 0L
        var pos = 0
        while (pos < data.size) {
            val (tag, tLen) = readTag(data, pos) ?: break
            pos += tLen
            val field = (tag ushr 3).toInt()
            val wire = (tag and 7).toInt()
            when (wire) {
                0 -> {
                    val r = readVarint(data, pos) ?: break
                    pos += r.second
                    when (field) { 1 -> gid = r.first; 6 -> level = r.first }
                }
                1 -> { if (pos + 8 > data.size) break; pos += 8 }
                2 -> {
                    val len = readVarint(data, pos)?.first?.toInt() ?: break
                    pos += varintLenAt(data, pos)
                    if (pos + len > data.size) break
                    when (field) {
                        2 -> openId = String(data, pos, len, Charsets.UTF_8)
                        3 -> name = String(data, pos, len, Charsets.UTF_8)
                    }
                    pos += len
                }
                5 -> { if (pos + 4 > data.size) break; pos += 4 }
                else -> break
            }
        }
        if (gid <= 0) return null
        return JSONObject().put("gid", gid).put("open_id", openId).put("name", name).put("level", level)
    }

    // LoginReply: basic=1(BasicInfo); BasicInfo.gid=1(int64)
    private fun scanLoginSelfGid(data: ByteArray): Long {
        var pos = 0
        while (pos < data.size) {
            val (tag, tLen) = readTag(data, pos) ?: return 0L
            pos += tLen
            val field = (tag ushr 3).toInt()
            val wire = (tag and 7).toInt()
            when (wire) {
                0 -> { val r = readVarint(data, pos) ?: return 0L; pos += r.second }
                1 -> { if (pos + 8 > data.size) return 0L; pos += 8 }
                2 -> {
                    val len = readVarint(data, pos)?.first?.toInt() ?: return 0L
                    pos += varintLenAt(data, pos)
                    if (pos + len > data.size) return 0L
                    if (field == 1) {
                        val inner = data.copyOfRange(pos, pos + len)
                        var p = 0
                        while (p < inner.size) {
                            val (t2, t2Len) = readTag(inner, p) ?: break
                            p += t2Len
                            val f2 = (t2 ushr 3).toInt()
                            val w2 = (t2 and 7).toInt()
                            if (w2 == 0) {
                                val r2 = readVarint(inner, p) ?: break
                                if (f2 == 1 && r2.first > 0) return r2.first
                                p += r2.second
                            } else if (w2 == 1) p += 8
                            else if (w2 == 2) {
                                val l2 = readVarint(inner, p)?.first?.toInt() ?: break
                                p += varintLenAt(inner, p)
                                p += l2
                            } else if (w2 == 5) p += 4
                            else break
                        }
                    }
                    pos += len
                }
                5 -> { if (pos + 4 > data.size) return 0L; pos += 4 }
                else -> return 0L
            }
        }
        return 0L
    }

    // ------------------------------------------------------------------ varint

    private data class TagVal(val tag: Long, val len: Int)

    private fun readTag(data: ByteArray, pos: Int): TagVal? {
        val r = readVarint(data, pos) ?: return null
        return TagVal(r.first, r.second)
    }

    private fun varintLenAt(data: ByteArray, pos: Int): Int {
        var i = pos
        while (i < data.size && i - pos < 10) {
            if ((data[i].toInt() and 0x80) == 0) return i - pos + 1
            i++
        }
        return 1
    }

    /** 返回 (值, 占用字节数)；不完整返回 null */
    private fun readVarint(data: ByteArray, pos: Int): Pair<Long, Int>? {
        var result = 0L
        var shift = 0
        var i = pos
        while (i < data.size && shift < 64) {
            val b = data[i].toInt() and 0xFF
            if (shift == 63 && (b and 0xFE) != 0) return null
            result = result or ((b and 0x7F).toLong() shl shift)
            i++
            if ((b and 0x80) == 0) return Pair(result, i - pos)
            shift += 7
        }
        return null
    }
}
