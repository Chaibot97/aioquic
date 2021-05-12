from .gf256_op import GF256PacketRecover, GF256LinearCombination
from .tiny_mt_32 import generate_coding_coefficients
from ..quic.crypto import CryptoPair

FEC_MAX_DENSITY = 15
EW_SIZE = 5
FEC_PACE = 2
NUM_REPAIR = 2
FEC_REPAIR_KEY_UPPER_BOUND = 2 ** 8  # we only have 8 bits to store this value
PADDING_FRAME_TYPE = 0x40


class RepairSymbol:
    def __init__(self, fss_esi, nss, repair_key, data):
        self.fss_esi = fss_esi
        self.nss = nss
        self.repair_key = repair_key
        self.data = data


class SourceSymbol:
    def __init__(self, packet_number, data):
        self.packet_number = packet_number
        self.data = data


class FECRecoverer:
    def __init__(self):
        self._source_symbols_start = 0
        self._source_symbols = []
        self._repair_symbols = []

    def add_source_symbol(self, symbol):
        pos = symbol.packet_number - self._source_symbols_start

        if pos < 0:
            return

        if len(self._source_symbols) < pos + 1:
            self._source_symbols += [None] * (pos - len(self._source_symbols) + 1)

        self._source_symbols.insert(pos, symbol)

    def add_repair_symbol(self, symbol):
        new_source_symbols_start = symbol.fss_esi - symbol.nss + 1
        # if advancing repair symbol is received, clear symbols associated with the old repair symbol
        if len(self._repair_symbols) > 0 and (symbol.fss_esi > self._repair_symbols[
            0].fss_esi or new_source_symbols_start > self._source_symbols_start):
            self._repair_symbols = []
            move_step = new_source_symbols_start - self._source_symbols_start
            self._source_symbols = self._source_symbols[move_step:] if len(self._source_symbols) > move_step else []
            self._source_symbols_start = new_source_symbols_start

        self._repair_symbols.append(symbol)

    def recover(self):
        if len(self._repair_symbols) == 0:
            return None

        nss = self._repair_symbols[0].nss

        if len(self._source_symbols) < nss:
            self._source_symbols += [None] * (nss - len(self._source_symbols))
        window = self._source_symbols[:nss]
        
        missing_symbols_indices = [i for i, s in enumerate(window) if s is None]
        received_symbols = [s for i, s in enumerate(window) if s != None]

        # if can recover
        if len(missing_symbols_indices) <= len(self._repair_symbols) and len(missing_symbols_indices) > 0:
            # remove extra repair symbols
            repair_symbols = self._repair_symbols[:len(missing_symbols_indices)]

            # prepare data from recovery
            repair_data = [s.data for s in repair_symbols]
            received_data = [s.data for s in received_symbols]
            received_coefficients = []
            lost_coefficients = []
            for repair_symbol in repair_symbols:
                coefficients = generate_coding_coefficients(repair_symbol.repair_key, nss, 15)
                received_coefficients.append(
                    [c for i, c in enumerate(coefficients) if i not in missing_symbols_indices])
                lost_coefficients.append([c for i, c in enumerate(coefficients) if i in missing_symbols_indices])

            # try to recover
            recovered_data = GF256PacketRecover(repair_data, received_data, received_coefficients, lost_coefficients)

            if recovered_data:
                symbols_to_return = []
                for i, d in enumerate(recovered_data):
                    window_index = missing_symbols_indices[i]
                    recovered_symbol = SourceSymbol(window_index + self._source_symbols_start, d)
                    self._source_symbols[window_index] = recovered_symbol
                    symbols_to_return.append(recovered_symbol)
                return symbols_to_return

        return None


class FECEncoder:

    def __init__(self):
        self._fec_window = []
        self._fec_window_last_packet_num = None
        self._fec_ew_size = EW_SIZE
        self._fec_pace = FEC_PACE
        self._fec_src_cnt = 0
        self._fec_repair_key = 0

    def try_add_repair_packet(self, builder, crypto: CryptoPair):
        payload = builder.current_short_header_packet_payload

        if payload is not None:
            if ((self._fec_window_last_packet_num is not None)
                    and (self._fec_window_last_packet_num == builder.current_short_header_packet_num)):
                return

            # increase the src_cnt (the number of consecutive short header packet without sending repair packet)
            self._fec_src_cnt += 1

            # record last short header packet sent
            self._fec_window.append(payload)
            self._fec_window_last_packet_num = builder.current_short_header_packet_num

            # adjust the window
            while len(self._fec_window) > self._fec_ew_size:
                self._fec_window.pop(0)

            # send repair if possible
            if len(self._fec_window) == self._fec_ew_size and self._fec_src_cnt >= self._fec_pace:
                # clear src sent cnt
                self._fec_src_cnt = 0

                for i in range(NUM_REPAIR):
                    # repair key
                    repair_key = self._fec_repair_key
                    self._fec_repair_key = (repair_key + 1) % FEC_REPAIR_KEY_UPPER_BOUND

                    fss_esi = self._fec_window_last_packet_num
                    nss = len(self._fec_window)

                    # get coeffs
                    window_size = len(self._fec_window)
                    coeffs = generate_coding_coefficients(repair_key, window_size, FEC_MAX_DENSITY)

                    # compute repair payload
                    payload = GF256LinearCombination(self._fec_window, coeffs)

                    builder.build_repair_packet(crypto, fss_esi, nss, repair_key, payload)
