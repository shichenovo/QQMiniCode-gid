// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.proxy

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Random

/**
 * WsFriendSniffer 的字节级验证：
 * 喂入“脱敏合成”的服务器→客户端下行流
 * （HTTP/1.1 101 升级响应 + RFC6455 服务端帧 + gatepb.Message 明文响应）。
 *
 * fixture（ws_downstream_key.bin）由真实抓包重编码生成：结构与规模完全保留
 * （Login + SyncAll 全量 145 好友），但身份已替换为测试值：
 *   自身 gid → 9000000001；真人好友 → 1000000001…1000000144；内置 NPC 小果 10001 保留。
 */
class WsFriendSnifferTest {

    private fun load(name: String): ByteArray =
        File("src/test/resources/$name").readBytes()

    @Test
    fun parseLoginAndSyncAll() {
        val sniffer = WsFriendSniffer("key")
        sniffer.minLogIntervalMs = 0
        var selfGid = 0L
        val all = mutableListOf<Long>()
        sniffer.onFriends = { g, json ->
            if (g > 0) selfGid = g
            val arr = JSONArray(json)
            for (i in 0 until arr.length()) all.add(arr.getJSONObject(i).getLong("gid"))
        }
        val key = load("ws_downstream_key.bin")
        // 整块一次性喂入（贴近小响应场景）
        sniffer.feed(key)

        println("selfGid=$selfGid 好友=${all.distinct().size}")
        // 嗅探器应从 Login 响应动态取自身 gid（不硬编码任何账号）
        assertEquals(9000000001L, selfGid)
        assertTrue("SyncAll 应解出全量好友，实际 ${all.distinct().size}", all.distinct().size >= 140)
    }

    @Test
    fun parseWithRandomChunks() {
        val sniffer = WsFriendSniffer("test")
        sniffer.minLogIntervalMs = 0
        val friendsByCall = mutableListOf<Pair<Long, JSONArray>>()
        sniffer.logger = { _ -> }
        sniffer.onFriends = { gid, json ->
            friendsByCall.add(gid to JSONArray(json))
        }

        val data = load("ws_downstream_key.bin")
        // 模拟 TLS 分块：随机切成 1..8000 字节的块喂入（贴近 readApp 真实行为）
        var off = 0
        val rnd = Random(42)
        while (off < data.size) {
            val n = minOf(1 + rnd.nextInt(8000), data.size - off)
            sniffer.feed(data.copyOfRange(off, off + n))
            off += n
        }

        assertTrue("应至少解析出一批好友", friendsByCall.isNotEmpty())
        // 合并所有批
        val merged = LinkedHashMap<Long, JSONObject>()
        var selfGid = 0L
        for ((g, arr) in friendsByCall) {
            if (g > 0) selfGid = g
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                merged[o.getLong("gid")] = o
            }
        }
        println("selfGid=$selfGid 好友批次=${friendsByCall.size} 去重好友=${merged.size}")
        assertTrue("应解出接近全量的好友（145），实际 ${merged.size}", merged.size >= 140)
        // 不应出现任何真实账号 gid（脱敏有效）
        assertTrue("不应含真实账号 gid", !merged.containsKey(1003815821L) && !merged.containsKey(1230215608L))
    }

    @Test
    fun nonUpgradeIgnored() {
        val sniffer = WsFriendSniffer("noop")
        var fired = false
        sniffer.onFriends = { _, _ -> fired = true }
        // 普通 HTTP 响应（非 WS 升级）
        val http = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".toByteArray()
        sniffer.feed(http)
        sniffer.feed(ByteArray(64) { 1 })
        assertTrue(!fired)
    }
}
