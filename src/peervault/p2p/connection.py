"""WebRTC peer connection management and signaling negotiation."""

import asyncio
import logging

from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription
from aiortc.rtcdatachannel import RTCDataChannel

from peervault.config import DEFAULT_NETWORK_CONFIG, NetworkConfig
from peervault.signaling.client import SignalingClient

logger = logging.getLogger(__name__)


def create_peer_connection(
    network_config: NetworkConfig = DEFAULT_NETWORK_CONFIG,
) -> RTCPeerConnection:
    """Instantiates an RTCPeerConnection with configured public STUN servers."""
    ice_servers = [RTCIceServer(urls=url) for url in network_config.stun_servers]
    config = RTCConfiguration(iceServers=ice_servers)
    return RTCPeerConnection(configuration=config)


async def negotiate_sender(
    pc: RTCPeerConnection,
    signaling: SignalingClient,
    timeout: float = 30.0,
) -> RTCDataChannel:
    """Sender side: creates DataChannel, creates offer, gathers ICE, and awaits answer."""
    channel = pc.createDataChannel("peervault", ordered=True)
    channel_open_event = asyncio.Event()
    if channel.readyState == "open":
        channel_open_event.set()

    @channel.on("open")
    def on_open() -> None:
        channel_open_event.set()

    # Create offer and gather ICE candidates
    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    if pc.localDescription is None:
        raise RuntimeError("Failed to set local description for offer")

    # Send encrypted offer over signaling relay
    await signaling.send_signal(
        {
            "type": "offer",
            "sdp": pc.localDescription.sdp,
        }
    )

    # Receive encrypted answer from receiver
    answer_msg = await signaling.receive_signal(timeout=timeout)
    if answer_msg.get("type") != "answer" or not answer_msg.get("sdp"):
        raise ValueError(f"Expected SDP answer, received: {answer_msg}")

    answer = RTCSessionDescription(sdp=answer_msg["sdp"], type="answer")
    await pc.setRemoteDescription(answer)

    # Wait until the direct DataChannel is fully established
    try:
        await asyncio.wait_for(channel_open_event.wait(), timeout=timeout)
    except asyncio.TimeoutError as err:
        raise TimeoutError("Timed out waiting for WebRTC DataChannel to open") from err

    return channel


async def negotiate_receiver(
    pc: RTCPeerConnection,
    signaling: SignalingClient,
    timeout: float = 30.0,
) -> RTCDataChannel:
    """Receiver side: receives offer, creates answer, gathers ICE,
    and awaits incoming DataChannel.
    """
    channel_future: asyncio.Future[RTCDataChannel] = asyncio.get_running_loop().create_future()
    channel_open_event = asyncio.Event()

    @pc.on("datachannel")
    def on_datachannel(incoming_channel: RTCDataChannel) -> None:
        if incoming_channel.readyState == "open":
            channel_open_event.set()

        @incoming_channel.on("open")
        def on_open() -> None:
            channel_open_event.set()

        if not channel_future.done():
            channel_future.set_result(incoming_channel)

    # Receive encrypted offer from sender
    offer_msg = await signaling.receive_signal(timeout=timeout)
    if offer_msg.get("type") != "offer" or not offer_msg.get("sdp"):
        raise ValueError(f"Expected SDP offer, received: {offer_msg}")

    offer = RTCSessionDescription(sdp=offer_msg["sdp"], type="offer")
    await pc.setRemoteDescription(offer)

    # Create answer and gather local ICE candidates
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)

    if pc.localDescription is None:
        raise RuntimeError("Failed to set local description for answer")

    # Send encrypted answer over signaling relay
    await signaling.send_signal(
        {
            "type": "answer",
            "sdp": pc.localDescription.sdp,
        }
    )

    # Await incoming datachannel
    try:
        channel = await asyncio.wait_for(channel_future, timeout=timeout)
    except asyncio.TimeoutError as err:
        raise TimeoutError("Timed out waiting for incoming DataChannel") from err

    if channel.readyState != "open":
        try:
            await asyncio.wait_for(channel_open_event.wait(), timeout=timeout)
        except asyncio.TimeoutError as err:
            raise TimeoutError("Timed out waiting for DataChannel open event") from err

    return channel
