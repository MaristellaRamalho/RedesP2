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
        #PASSO5
        self.timer = None
        self.segments_nao_confirmados = [] #[(seq_no, segment, tempo_envio)]
        self.buffer_envio = b''
        self.enviando = False


        #PASSO6
        self.estimated_rtt = 1.0
        self.dev_rtt = 0.5
        self.alpha = 0.125
        self.beta = 0.25
        self.TIMEOUT = 1

        #PASSO1

        #desempacotando conexao
        self.src_addr, self.src_port, self.dst_addr, self.dst_port = id_conexao

        #setando números de sequência
        self.seq_no = random.randint(0, 0xffff)
        self.ack_no = seq_no_cliente + 1

        #cabeçaljo
        flags = FLAGS_SYN | FLAGS_ACK
        header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, flags)
        segment = fix_checksum(header, self.dst_addr, self.src_addr)

        #Enviando SYN+ACK
        self.servidor.rede.enviar(segment, self.src_addr)
        self.seq_no += 1

    def _iniciar_timer(self):
        self._cancelar_timer()
        self.TIMEOUT = self._timeout_interval()
        self.timer = asyncio.get_event_loop().call_later(self.TIMEOUT, self._timeout)
    
    def _cancelar_timer(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _timeout(self):
        if self.segments_nao_confirmados:
            #retransmitir primeiro segmento não confirmado
            seq_no, segment, _  = self.segments_nao_confirmados[0] #ignora tempo_envio
            self.servidor.rede.enviar(segment, self.src_addr)
            self.segments_nao_confirmados[0] = (seq_no, segment, None)
            self._iniciar_timer()

    # PASSO6: calcula o timeout baseado no RTT estimado e no desvio
    def _timeout_interval(self):
        return self.estimated_rtt + 4 * self.dev_rtt

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if self.estado == 'FECHADA':
            return

        if (flags & FLAGS_FIN) == FLAGS_FIN: #PASSO4 (cliente enviou FIN)
            self.ack_no = seq_no + 1
            header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segment = fix_checksum(header, self.dst_addr, self.src_addr)
            self.servidor.rede.enviar(segment, self.src_addr)

            if self.callback:
                self.callback(self, b'')

            self.estado = 'FECHANDO'
            return

        #controle de retransmissao
        cabecalho = 4 * (flags >> 12) 
        if (flags & FLAGS_ACK) == FLAGS_ACK:
            novos_segments_nao_confirmados = []
            ack_avancou = False
            for seq, segment, tempo_envio in self.segments_nao_confirmados:
                if seq + len(segment[cabecalho:]) <= ack_no:
                    ack_avancou = True

                    #PASSO6
                    if tempo_envio is not None:
                        sample_rtt = time.time() - tempo_envio
                        if self.estimated_rtt == 1.0 and self.dev_rtt == 0.5:
                            self.estimated_rtt = sample_rtt
                            self.dev_rtt = sample_rtt / 2
                        else:
                            self.estimated_rtt = (1 - self.alpha) * self.estimated_rtt + self.alpha * sample_rtt
                            self.dev_rtt = (1 - self.beta) * self.dev_rtt + self.beta * abs(sample_rtt - self.estimated_rtt)
                            
                    continue 
                novos_segments_nao_confirmados.append((seq, segment, tempo_envio))

            if ack_avancou:
                self.segments_nao_confirmados = novos_segments_nao_confirmados
                self._cancelar_timer()
                if self.segments_nao_confirmados:
                    self._iniciar_timer()
                else:
                    self.enviando = False

                    if self.buffer_envio:
                        pedaco = self.buffer_envio[:MSS]
                        self.buffer_envio = self.buffer_envio[MSS:]

                        header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, FLAGS_ACK)
                        segment = fix_checksum(header + pedaco, self.dst_addr, self.src_addr)
                        self.servidor.rede.enviar(segment, self.src_addr)

                        tempo_envio = time.time()
                        self.segments_nao_confirmados.append((self.seq_no, segment, tempo_envio))
                        self._iniciar_timer()
                        self.enviando = True    

                        self.seq_no += len(pedaco)

        if self.estado == 'FECHANDO':
            if payload:
                return
            if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no == self.seq_no:
                self.estado = 'FECHADA'
            return

        if seq_no == self.ack_no and self.estado == 'ABERTA': #PASSO2 (recebendo dados)
            if payload:
                self.ack_no += len(payload)
                if self.callback:
                    self.callback(self, payload)
                header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, FLAGS_ACK)
                segment = fix_checksum(header, self.dst_addr, self.src_addr)
                self.servidor.rede.enviar(segment, self.src_addr)
   

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        self.buffer_envio += dados

        # Só envia se nada estiver pendente
        if self.enviando or not self.buffer_envio:
            return

        pedaco = self.buffer_envio[:MSS]
        self.buffer_envio = self.buffer_envio[MSS:]

        header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, FLAGS_ACK)
        segment = fix_checksum(header + pedaco, self.dst_addr, self.src_addr)
        self.servidor.rede.enviar(segment, self.src_addr)
        
        tempo_envio = time.time()
        
        self.segments_nao_confirmados.append((self.seq_no, segment, tempo_envio))
        self._iniciar_timer()
        self.enviando = True

        self.seq_no += len(pedaco)


    def fechar(self):
        #PASSO4
        if self.estado == 'FECHADA':
            return

        flags = FLAGS_FIN | FLAGS_ACK
        header = make_header(self.dst_port, self.src_port, self.seq_no, self.ack_no, flags)
        segment = fix_checksum(header, self.dst_addr, self.src_addr)
        self.servidor.rede.enviar(segment, self.src_addr)
        self.seq_no += 1
        self.estado = 'FECHANDO'
