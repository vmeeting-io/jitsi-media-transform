/*
 * Copyright @ 2018 - Present, 8x8 Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jitsi.nlj.transform.node

import java.net.Inet4Address
import org.jitsi.nlj.PacketInfo
import org.jitsi.nlj.rtp.codec.vp8.Vp8Packet
import org.jitsi.nlj.rtp.codec.vp9.Vp9Packet
import org.jitsi.utils.logging.DiagnosticContext
import org.jitsi.utils.logging2.createChildLogger
import org.jitsi.utils.logging2.Logger
import org.pcap4j.core.PcapDumper
import org.pcap4j.core.PcapHandle
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.EthernetPacket
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV4Rfc1349Tos
import org.pcap4j.packet.UdpPacket
import org.pcap4j.packet.UnknownPacket
import org.pcap4j.packet.namednumber.DataLinkType
import org.pcap4j.packet.namednumber.EtherType
import org.pcap4j.packet.namednumber.IpNumber
import org.pcap4j.packet.namednumber.IpVersion
import org.pcap4j.packet.namednumber.UdpPort
import org.pcap4j.util.MacAddress
import java.io.File

class VideoPcapWriter(
        parentLogger: Logger,
        endPointID: String,
        videoPcapDir: String,
        diagnosticContext: DiagnosticContext
) : ObserverNode("PCAP writer") {
    private val logger = createChildLogger(parentLogger)
    // get the conference name only from conf JID
    // e.g.,: test@muc.trial.vmeeting.io -> muc
    private val confName = diagnosticContext["conf_name"].toString().split("@")[0]
    private val confSite = diagnosticContext["conf_name"].toString().split("@")[1].split(".")[1]
    private val confId = diagnosticContext["conf_id"]
    private val videoPcapDir = videoPcapDir
    private val endPointID = endPointID
    private var handle: PcapHandle? = null
    private var writer: PcapDumper? = null
    private var filePath: String? = null

    companion object {
        private val localhost = Inet4Address.getByName("127.0.0.1") as Inet4Address
    }

    private var vp8SsrcToCap: Long? = null
    private var curPacketType: String? = null
    private var pcapFileIndex = 0

    override fun observe(packetInfo: PacketInfo) {
        // for VP8, simulcast is used, therefore we do not capture VP8 packets that do not have desired resolution
        if (packetInfo.packet is Vp8Packet) {
            if (curPacketType != "VP8") {
                closeOldWriter()
                createNewWriter("VP8")
            }

            val vp8Packet = packetInfo.packetAs<Vp8Packet>()
            if (vp8SsrcToCap == null && vp8Packet.height == 180)
                vp8SsrcToCap = vp8Packet.ssrc

            if (vp8Packet.ssrc != vp8SsrcToCap)
                return
        }

        if (packetInfo.packet is Vp9Packet) {
            if (curPacketType != "VP9") {
                closeOldWriter()
                createNewWriter("VP9")
            }
        }

        // if not VP8 or VP9, then do not capture
        if (!(packetInfo.packet is Vp8Packet || packetInfo.packet is Vp9Packet))
            return

        val udpPayload = UnknownPacket.Builder()
        // We can't pass offset/limit values to udpPayload.rawData, so we need to create an array that contains
        // only exactly what we want to write
        val subBuf = ByteArray(packetInfo.packet.length)
        System.arraycopy(packetInfo.packet.buffer, packetInfo.packet.offset, subBuf, 0, packetInfo.packet.length)
        udpPayload.rawData(subBuf)
        val udp = UdpPacket.Builder()
                .srcPort(UdpPort(123, "blah"))
                .dstPort(UdpPort(456, "blah"))
                .srcAddr(localhost)
                .dstAddr(localhost)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(udpPayload)

        val ipPacket = IpV4Packet.Builder()
                .srcAddr(localhost)
                .dstAddr(localhost)
                .protocol(IpNumber.UDP)
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc1349Tos.newInstance(0))
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true)
                .payloadBuilder(udp)

        val eth = EthernetPacket.Builder()
                .srcAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .type(EtherType.IPV4)
                .paddingAtBuild(true)
                .payloadBuilder(ipPacket)
                .build()

        writer!!.dump(eth)
    }

    override fun trace(f: () -> Unit) = f.invoke()

    private fun closeOldWriter() {
        if (writer != null && writer!!.isOpen)
            writer!!.close()

        if (handle !=null && handle!!.isOpen) {
            handle!!.close()
            renamePcap(filePath!!, "${filePath}.pcap")
        }
    }

    fun close() {
        closeOldWriter()
        // user finish text to indicate finish recording for this participant ID
        renamePcap("$filePath.pcap", "${filePath}finish.pcap")
    }

    private fun createNewWriter(newPacketType: String) {
        curPacketType = newPacketType
        filePath = "$videoPcapDir/${confSite}_${confName}__${confId}__${endPointID}__${pcapFileIndex}__${newPacketType}__"
        handle = Pcaps.openDead(DataLinkType.EN10MB, 65536)
        writer = handle!!.dumpOpen(filePath)
        pcapFileIndex += 1
    }

    private fun renamePcap(oldFilePath: String, newFilePath: String): Boolean {
        val oldFile = File(oldFilePath)
        val newFile =  File(newFilePath)
        return oldFile.renameTo(newFile)
    }
}
