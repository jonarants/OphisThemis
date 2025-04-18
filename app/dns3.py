import asyncio
import socket
import struct

class DNSHeader:
    def __init__(
        self,
        hid: int = 1234,
        qr: int = 0,  # 0 para consulta, 1 para respuesta
        opcode: int = 0,
        aa: int = 0,
        tc: int = 0,
        rd: int = 1,  # Desired recursion
        ra: int = 0,
        z: int = 0,
        rcode: int = 0,
        qdcount: int = 1,
        ancount: int = 0,
        nscount: int = 0,
        arcount: int = 0,
    ):
        self.id = hid
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.z = z
        self.rcode = rcode
        self.ancount = ancount
        self.qdcount = qdcount
        self.nscount = nscount
        self.arcount = arcount

    @staticmethod
    def from_bytes(message: bytes) -> "DNSHeader":
        if len(message) < 12:
            raise ValueError("Mensaje DNS demasiado corto para el encabezado")
        hid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", message[:12]
        )
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF
        return DNSHeader(
            hid,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        )

    def to_bytes(self) -> bytes:
        flags = (
            (self.qr << 15)
            | (self.opcode << 11)
            | (self.aa << 10)
            | (self.tc << 9)
            | (self.rd << 8)
            | (self.ra << 7)
            | (self.z << 4)
            | (self.rcode)
        )
        return struct.pack(
            "!HHHHHH",
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

def decode_bytes_to_str(data: bytes) -> str:
    parts = []
    i = 0
    while i < len(data):
        length = data[i]
        if length == 0:
            break
        parts.append(data[i+1:i+1+length].decode())
        i += 1 + length
    return ".".join(parts).lower()

def build_nxdomain_response(header: DNSHeader, data: bytes) -> bytes:
    header.qr = 1  # Response
    header.rcode = 3  # NXDOMAIN
    header.ancount = 0
    header.nscount = 0
    header.arcount = 0
    response = header.to_bytes()
    # Añadir la pregunta original (la copiamos directamente de los datos recibidos después del encabezado)
    response += data[12:]
    return response

class DNSServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, blacklist, block_page_ip):
        self.blacklist = blacklist
        self.block_page_ip = block_page_ip
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        print(f"Servidor DNS iniciado en {transport.get_extra_info('sockname')}")

    def datagram_received(self, data, addr):
        try:
            header = DNSHeader.from_bytes(data)
            # Simple extracción del nombre de dominio (asumiendo un solo nombre en la pregunta)
            name_encoded = data[12:]
            # Find the end of the QNAME
            i = 0
            while i < len(name_encoded) and name_encoded[i] != 0:
                length = name_encoded[i]
                i += 1 + length
            qname_bytes = name_encoded[:i+1]
            name = decode_bytes_to_str(qname_bytes)

            print(f"Consulta recibida para: {name} de {addr}")

            if name in self.blacklist:
                # Construir la respuesta de bloqueo
                header.qr = 1  # Response
                header.rcode = 0  # No error
                header.ancount = 1
                response = header.to_bytes()
                response += qname_bytes  # Añadir la pregunta original
                response += b'\x00\x01'  # QTYPE A (1)
                response += b'\x00\x01'  # QCLASS IN (1)
                response += b'\x00\x00\x00\x3c'  # TTL (60 seconds)
                response += b'\x00\x04'  # RDLENGTH (4 bytes for IPv4)
                response += socket.inet_aton(self.block_page_ip) # RDATA (la IP de bloqueo)
                self.transport.sendto(response, addr)
                print(f"Bloqueado: {name} -> {self.block_page_ip} para {addr}")
            else:
                # Si no está en la lista negra, devolvemos NXDOMAIN
                response = build_nxdomain_response(header, data)
                self.transport.sendto(response, addr)
                print(f"No bloqueado: {name} -> NXDOMAIN para {addr}")

        except ValueError as e:
            print(f"Consulta mal formada de {addr}: {e}")
        except Exception as e:
            print(f"Error al procesar la consulta de {addr}: {e}")

async def main():
    blacklist = ["example.com", "malicious.net", "pronhub.com", "pornhub.com", "xvideos.com"]
    block_page_ip = "127.0.0.1"
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSServerProtocol(blacklist, block_page_ip),
        local_addr=('0.0.0.0', 8053)
    )
    try:
        await asyncio.Future()
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main()) 