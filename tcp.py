

import asyncio
import random
import time  
from tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segment com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))

class Conexao:
    def __init__(self, servidor, id_conexao, seq_no_cliente):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.estado = 'ABERTA'
        
        # Controle de transmissão
        self.timer = None
        self.segments_nao_confirmados = []  # [(seq_no, segment, tempo_envio)]
        self.buffer_envio = b''
        self.enviando = False

        # Controle de RTT (Passo 6)
        self.estimated_rtt = None
        self.dev_rtt = None
        self.alpha = 0.125
        self.beta = 0.25

        # Controle de congestionamento (Passo 7)
        self.cwnd = 1 * MSS
        self.ssthresh = 65535  # Valor inicial alto
        self.duplicate_acks = 0
        self.last_ack = None  # Último ACK recebido

        # Estabelecimento de conexão (Passo 1)
        self.src_addr, self.src_port, self.dst_addr, self.dst_port = id_conexao
        self.seq_no = random.randint(0, 0xffff)
        self.ack_no = seq_no_cliente + 1

        # Envia SYN+ACK
        flags = FLAGS_SYN | FLAGS_ACK
        header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, flags)
        segment = fix_checksum(header, self.dst_addr, self.src_addr)
        self.servidor.rede.enviar(segment, self.src_addr)
        self.seq_no += 1

    def _iniciar_timer(self):
        self._cancelar_timer()
        timeout = self._timeout_interval()
        loop = asyncio.get_event_loop()
        self.timer = loop.call_later(timeout, self._timeout)
    
    def _cancelar_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None
    
    def _timeout(self):
        """Trata timeout com redução da janela de congestionamento"""
        self._atualizar_janela_congest(False)
        if self.segments_nao_confirmados:
            # Retransmite o primeiro segmento não confirmado
            seq_no, segment, _ = self.segments_nao_confirmados[0]
            self.servidor.rede.enviar(segment, self.src_addr)
            # Marca como retransmitido (não usará para cálculo RTT)
            self.segments_nao_confirmados[0] = (seq_no, segment, None)
            self._iniciar_timer()

    def _timeout_interval(self):
        """Calcula o timeout baseado no RTT estimado e no desvio"""
        if self.estimated_rtt is None:
            return 1.0  # Valor padrão inicial
        return max(0.1, self.estimated_rtt + 4 * self.dev_rtt)  # Mínimo de 100ms

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if self.estado == 'FECHADA':
            return

        # Tratamento de FIN (Passo 4)
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no = seq_no + 1
            header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segment = fix_checksum(header, self.dst_addr, self.src_addr)
            self.servidor.rede.enviar(segment, self.src_addr)

            if self.callback:
                self.callback(self, b'')

            self.estado = 'FECHANDO'
            return

        # Tratamento de ACKs (Passo 2, 5, 6, 7)
        cabecalho = 4 * (flags >> 12)
        if (flags & FLAGS_ACK) == FLAGS_ACK:
            # Controle de ACKs duplicados (Fast Retransmit)
            if ack_no == self.last_ack:
                self.duplicate_acks += 1
                if self.duplicate_acks == 3:
                    self._fast_retransmit()
            else:
                self.duplicate_acks = 0
                self.last_ack = ack_no

            # Processa segmentos confirmados
            novos_segments = []
            ack_avancou = False
            for seq, segment, tempo_envio in self.segments_nao_confirmados:
                if seq + len(segment[cabecalho:]) <= ack_no:
                    ack_avancou = True
                    # Atualiza RTT (Passo 6)
                    if tempo_envio is not None:
                        self._atualizar_rtt(time.time() - tempo_envio)
                else:
                    novos_segments.append((seq, segment, tempo_envio))

            if ack_avancou:
                self.segments_nao_confirmados = novos_segments
                self._cancelar_timer()
                if self.segments_nao_confirmados:
                    self._iniciar_timer()
                else:
                    self.enviando = False
                    self._atualizar_janela_congest(True)
                self._tentar_enviar()

        # Tratamento de dados recebidos (Passo 2)
        if seq_no == self.ack_no and self.estado == 'ABERTA' and payload:
            self.ack_no += len(payload)
            if self.callback:
                self.callback(self, payload)
            header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segment = fix_checksum(header, self.dst_addr, self.src_addr)
            self.servidor.rede.enviar(segment, self.src_addr)

        # Finalização de conexão
        if self.estado == 'FECHANDO' and (flags & FLAGS_ACK) == FLAGS_ACK and ack_no == self.seq_no:
            self.estado = 'FECHADA'

    def _atualizar_rtt(self, sample_rtt):
        """Atualiza as estimativas de RTT (Passo 6)"""
        if self.estimated_rtt is None:
            # Primeira medição
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            # Atualizações subsequentes
            self.dev_rtt = (1 - self.beta) * self.dev_rtt + self.beta * abs(sample_rtt - self.estimated_rtt)
            self.estimated_rtt = (1 - self.alpha) * self.estimated_rtt + self.alpha * sample_rtt
    
    def _atualizar_janela_congest(self, ack_recebido):
        """Atualiza a janela de congestionamento (Passo 7)"""
        if ack_recebido:
            # Slow Start ou Congestion Avoidance
            if self.cwnd < self.ssthresh:
                self.cwnd += MSS  # Slow Start
            else:
                self.cwnd += MSS * MSS / self.cwnd  # Congestion Avoidance
        else:
            # Timeout ou Fast Retransmit
            self.ssthresh = max(self.cwnd // 2, 2 * MSS)
            self.cwnd = MSS

    def _fast_retransmit(self):
        """Implementa Fast Retransmit (Passo 7)"""
        if self.segments_nao_confirmados:
            self._atualizar_janela_congest(False)
            seq, segment, _ = self.segments_nao_confirmados[0]
            self.servidor.rede.enviar(segment, self.src_addr)
            self.duplicate_acks = 0
            self._cancelar_timer()
            self._iniciar_timer()

    # Métodos restantes permanecem iguais
    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        self.buffer_envio += dados
        if not self.enviando:
            self._tentar_enviar()

    def _tentar_enviar(self):
        bytes_nao_confirmados = sum(
            len(segment[4*(segment[12]>>12):]) 
            for _, segment, _ in self.segments_nao_confirmados
        )

        while self.buffer_envio and bytes_nao_confirmados < self.cwnd:
            pedaco = self.buffer_envio[:MSS]
            self.buffer_envio = self.buffer_envio[MSS:]

            header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segment = fix_checksum(header + pedaco, self.dst_addr, self.src_addr)
            self.servidor.rede.enviar(segment, self.src_addr)

            self.segments_nao_confirmados.append((self.seq_no, segment, time.time()))
            self._iniciar_timer()
            self.enviando = True
            self.seq_no += len(pedaco)
            bytes_nao_confirmados += len(pedaco)

    def fechar(self):
        if self.estado != 'FECHADA':
            flags = FLAGS_FIN | FLAGS_ACK
            header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, flags)
            segment = fix_checksum(header, self.dst_addr, self.src_addr)
            self.servidor.rede.enviar(segment, self.src_addr)
            self.seq_no += 1
            self.estado = 'FECHANDO'