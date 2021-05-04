from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..buffer import Buffer, size_uint_var
from ..tls import Epoch
from .crypto import CryptoPair
from .logger import QuicLoggerTrace
from .packet import (
    NON_ACK_ELICITING_FRAME_TYPES,
    NON_IN_FLIGHT_FRAME_TYPES,
    PACKET_NUMBER_MAX_SIZE,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_REPAIR,
    PACKET_TYPE_MASK,
    QuicFrameType,
    is_long_header,
    is_repair_header
)

PACKET_MAX_SIZE = 1280
PACKET_LENGTH_SEND_SIZE = 2
PACKET_NUMBER_SEND_SIZE = 2


QuicDeliveryHandler = Callable[..., None]


class QuicDeliveryState(Enum):
    ACKED = 0
    LOST = 1
    EXPIRED = 2


@dataclass
class QuicSentPacket:
    epoch: Epoch
    in_flight: bool
    is_ack_eliciting: bool
    is_crypto_packet: bool
    packet_number: int
    packet_type: int
    sent_time: Optional[float] = None
    sent_bytes: int = 0

    delivery_handlers: List[Tuple[QuicDeliveryHandler, Any]] = field(
        default_factory=list
    )
    quic_logger_frames: List[Dict] = field(default_factory=list)


class QuicPacketBuilderStop(Exception):
    pass


class QuicPacketBuilder:
    """
    Helper for building QUIC packets.
    """

    def __init__(
        self,
        *,
        host_cid: bytes,
        peer_cid: bytes,
        version: int,
        is_client: bool,
        packet_number_initial: int = 0,
        packet_number_handshake: int = 0,
        packet_number_onertt: int = 0,
        peer_token: bytes = b"",
        quic_logger: Optional[QuicLoggerTrace] = None,
        spin_bit: bool = False,
    ):
        self.max_flight_bytes: Optional[int] = None
        self.max_total_bytes: Optional[int] = None
        self.quic_logger_frames: Optional[List[Dict]] = None

        self._host_cid = host_cid
        self._is_client = is_client
        self._peer_cid = peer_cid
        self._peer_token = peer_token
        self._quic_logger = quic_logger
        self._spin_bit = spin_bit
        self._version = version

        # assembled datagrams and packets
        self._datagrams: List[bytes] = []
        self._datagram_flight_bytes = 0
        self._datagram_init = True
        self._packets: List[QuicSentPacket] = []
        self._flight_bytes = 0
        self._total_bytes = 0

        # current packet
        self._header_size = 0
        self._packet: Optional[QuicSentPacket] = None
        self._packet_crypto: Optional[CryptoPair] = None
        self._packet_long_header = False
        self._packet_repair_header = False
        self._packet_number_initial = packet_number_initial
        self._packet_number_handshake = packet_number_handshake
        self._packet_number_onertt = packet_number_onertt
        self._packet_start = 0
        self._packet_type = 0
        self._space = Epoch.INITIAL

        # short header datagram record (used by fec)
        self.current_short_header_packet_payload = Optional[bytes]
        self.current_short_header_packet_num = 0

        self._buffer = Buffer(PACKET_MAX_SIZE)
        self._buffer_capacity = PACKET_MAX_SIZE
        self._flight_capacity = PACKET_MAX_SIZE

    @property
    def packet_is_empty(self) -> bool:
        """
        Returns `True` if the current packet is empty.
        """
        assert self._packet is not None
        packet_size = self._buffer.tell() - self._packet_start
        return packet_size <= self._header_size

    @property
    def packet_number(self) -> int:
        """
        Returns the packet number for the next packet.
        """
        return self._get_packet_number()

    def _get_packet_number(self) -> int:
        if self._space == Epoch.INITIAL:
            return self._packet_number_initial
        elif self._space == Epoch.HANDSHAKE:
            return self._packet_number_handshake
        else:
            return self._packet_number_onertt

    @property
    def packet_number_initial(self) -> int:
        return self._packet_number_initial

    @property
    def packet_number_handshake(self) -> int:
        return self._packet_number_handshake

    def get_packet_numbers(self) -> tuple:
        return self._packet_number_initial, self._packet_number_handshake, self._packet_number_onertt

    @property
    def remaining_buffer_space(self) -> int:
        """
        Returns the remaining number of bytes which can be used in
        the current packet.
        """
        return (
            self._buffer_capacity
            - self._buffer.tell()
            - self._packet_crypto.aead_tag_size
        )

    @property
    def remaining_flight_space(self) -> int:
        """
        Returns the remaining number of bytes which can be used in
        the current packet.
        """
        return (
            self._flight_capacity
            - self._buffer.tell()
            - self._packet_crypto.aead_tag_size
        )

    def try_end_packet(self) -> None:
        if self._packet is not None:
            self._end_packet()

    def flush(self) -> Tuple[List[bytes], List[QuicSentPacket]]:
        """
        Returns the assembled datagrams.
        """
        if self._packet is not None:
            self._end_packet()
        self._flush_current_datagram()

        datagrams = self._datagrams
        packets = self._packets
        self._datagrams = []
        self._packets = []
        return datagrams, packets

    def start_frame(
        self,
        frame_type: int,
        capacity: int = 1,
        handler: Optional[QuicDeliveryHandler] = None,
        handler_args: Sequence[Any] = [],
    ) -> Buffer:
        """
        Starts a new frame.
        """
        if self.remaining_buffer_space < capacity or (
            frame_type not in NON_IN_FLIGHT_FRAME_TYPES
            and self.remaining_flight_space < capacity
        ):
            raise QuicPacketBuilderStop

        self._buffer.push_uint_var(frame_type)
        if frame_type not in NON_ACK_ELICITING_FRAME_TYPES:
            self._packet.is_ack_eliciting = True
        if frame_type not in NON_IN_FLIGHT_FRAME_TYPES:
            self._packet.in_flight = True
        if frame_type == QuicFrameType.CRYPTO:
            self._packet.is_crypto_packet = True
        if handler is not None:
            self._packet.delivery_handlers.append((handler, handler_args))
        return self._buffer

    def build_repair_packet(self, crypto: CryptoPair, fss_esi, nss, repair_key, payload) -> None:
        """
        Build a repair packet
        """
        packet_type = PACKET_TYPE_REPAIR

        # start a new datagram to send repair packet (non-collapse)
        self._flush_current_datagram()

        # start the packet and manually set fss_esi
        self.start_packet(packet_type, crypto)
        self._packet.packet_number = fss_esi

        # insert nss, repair_key
        # header structure: ...nss (1 byte) + repair_key (1 byte) + packet_number (2 byte)
        # nss starts at packet_start + header_size - 4
        buf = self._buffer
        buf.seek(self._packet_start + self._header_size - 4)
        buf.push_uint8(nss)
        buf.push_uint8(repair_key)

        # push payload
        buf.seek(self._packet_start + self._header_size)
        buf.push_bytes(payload)

        # end packet (This is force flush datagram because it is not long header)
        self._end_packet()

    def start_packet(self, packet_type: int, crypto: CryptoPair) -> None:
        """
        Starts a new packet.
        """
        buf = self._buffer

        # finish previous datagram
        if self._packet is not None:
            self._end_packet()

        # clear previous short header packet record
        self.current_short_header_packet_payload = None

        # if there is too little space remaining, start a new datagram
        # FIXME: the limit is arbitrary!
        packet_start = buf.tell()
        if self._buffer_capacity - packet_start < 128:
            self._flush_current_datagram()
            packet_start = 0

        # initialize datagram if needed
        if self._datagram_init:
            if self.max_total_bytes is not None:
                remaining_total_bytes = self.max_total_bytes - self._total_bytes
                if remaining_total_bytes < self._buffer_capacity:
                    self._buffer_capacity = remaining_total_bytes

            self._flight_capacity = self._buffer_capacity
            if self.max_flight_bytes is not None:
                remaining_flight_bytes = self.max_flight_bytes - self._flight_bytes
                if remaining_flight_bytes < self._flight_capacity:
                    self._flight_capacity = remaining_flight_bytes
            self._datagram_flight_bytes = 0
            self._datagram_init = False

        # calculate header size
        packet_long_header = is_long_header(packet_type)
        if packet_long_header:
            header_size = 11 + len(self._peer_cid) + len(self._host_cid)
            if (packet_type & PACKET_TYPE_MASK) == PACKET_TYPE_INITIAL:
                token_length = len(self._peer_token)
                header_size += size_uint_var(token_length) + token_length
        else:
            # keep short header size consistent with repair header
            # as this ensures the repair packet can be sent in one packet
            header_size = 3 + 2 + len(self._peer_cid)

        # check we have enough space
        if packet_start + header_size >= self._buffer_capacity:
            raise QuicPacketBuilderStop

        # determine ack epoch
        if packet_type == PACKET_TYPE_INITIAL:
            epoch = Epoch.INITIAL
        elif packet_type == PACKET_TYPE_HANDSHAKE:
            epoch = Epoch.HANDSHAKE
        else:
            epoch = Epoch.ONE_RTT

        # switch space if needed
        self._space = epoch

        self._header_size = header_size

        self._packet = QuicSentPacket(
            epoch=epoch,
            in_flight=False,
            is_ack_eliciting=False,
            is_crypto_packet=False,
            packet_number=self._get_packet_number(),
            packet_type=packet_type,
        )
        self._packet_crypto = crypto
        self._packet_long_header = packet_long_header
        self._packet_repair_header = is_repair_header(packet_type)
        self._packet_start = packet_start
        self._packet_type = packet_type
        self.quic_logger_frames = self._packet.quic_logger_frames

        buf.seek(self._packet_start + self._header_size)

    def _increment_packet_number(self) -> None:
        if self._space == Epoch.INITIAL:
            self._packet_number_initial += 1
        elif self._space == Epoch.HANDSHAKE:
            self._packet_number_handshake += 1
        else:
            self._packet_number_onertt += 1

    def _end_packet(self) -> None:
        """
        Ends the current packet.
        """
        buf = self._buffer
        packet_size = buf.tell() - self._packet_start
        if packet_size > self._header_size:
            # padding to ensure sufficient sample size
            padding_size = (
                PACKET_NUMBER_MAX_SIZE
                - PACKET_NUMBER_SEND_SIZE
                + self._header_size
                - packet_size
            )

            # padding for initial datagram
            if (
                self._is_client
                and self._packet_type == PACKET_TYPE_INITIAL
                and self._packet.is_ack_eliciting
                and self.remaining_flight_space
                and self.remaining_flight_space > padding_size
            ):
                padding_size = self.remaining_flight_space

            # write padding
            if padding_size > 0:
                buf.push_bytes(bytes(padding_size))
                packet_size += padding_size
                self._packet.in_flight = True

                # log frame
                if self._quic_logger is not None:
                    self._packet.quic_logger_frames.append(
                        self._quic_logger.encode_padding_frame()
                    )

            # write header
            if self._packet_long_header:
                length = (
                    packet_size
                    - self._header_size
                    + PACKET_NUMBER_SEND_SIZE
                    + self._packet_crypto.aead_tag_size
                )

                buf.seek(self._packet_start)
                buf.push_uint8(self._packet_type | (PACKET_NUMBER_SEND_SIZE - 1))
                buf.push_uint32(self._version)
                buf.push_uint8(len(self._peer_cid))
                buf.push_bytes(self._peer_cid)
                buf.push_uint8(len(self._host_cid))
                buf.push_bytes(self._host_cid)
                if (self._packet_type & PACKET_TYPE_MASK) == PACKET_TYPE_INITIAL:
                    buf.push_uint_var(len(self._peer_token))
                    buf.push_bytes(self._peer_token)
                buf.push_uint16(length | 0x4000)
                buf.push_uint16(self._get_packet_number() & 0xFFFF)
            else:
                buf.seek(self._packet_start)
                buf.push_uint8(
                    self._packet_type
                    | (self._spin_bit << 5)
                    | (self._packet_crypto.key_phase << 2)
                    | (PACKET_NUMBER_SEND_SIZE - 1)
                )
                buf.push_bytes(self._peer_cid)

                # the following two bytes will be used by repair header to set nss and repair_key
                # we need to jump over two bytes to ensure consistency between short header and repair header
                # this will ensure the repair packet can be sent in one single packet
                buf.seek(buf.tell() + 2)

                buf.push_uint16(self._get_packet_number() & 0xFFFF)

            # encrypt in place
            plain = buf.data_slice(self._packet_start, self._packet_start + packet_size)
            buf.seek(self._packet_start)
            buf.push_bytes(
                self._packet_crypto.encrypt_packet(
                    plain[0 : self._header_size],
                    plain[self._header_size : packet_size],
                    self._get_packet_number(),
                )
            )
            self._packet.sent_bytes = buf.tell() - self._packet_start
            self._packets.append(self._packet)
            if self._packet.in_flight:
                self._datagram_flight_bytes += self._packet.sent_bytes

            # short header packets cannot be coallesced, we need a new datagram
            if not self._packet_long_header:
                # record the short header packet
                if not self._packet_repair_header:
                    self._record_short_header_packet()

                # flush the datagram
                self._flush_current_datagram()

            # do not increase packet number in case of repair packet
            if not self._packet_repair_header:
                self._increment_packet_number()

        else:
            # "cancel" the packet
            buf.seek(self._packet_start)

        self._packet = None
        self.quic_logger_frames = None

    def _record_short_header_packet(self) -> None:
        payload_start = self._packet_start + self._header_size
        payload_end = self._buffer.tell()

        # record the payload and the packet number
        self.current_short_header_packet_payload = self._buffer.data[payload_start:payload_end]
        self.current_short_header_packet_num = self._packet.packet_number

    def _flush_current_datagram(self) -> None:
        datagram_bytes = self._buffer.tell()
        if datagram_bytes:
            self._datagrams.append(self._buffer.data)
            self._flight_bytes += self._datagram_flight_bytes
            self._total_bytes += datagram_bytes
            self._datagram_init = True
            self._buffer.seek(0)
