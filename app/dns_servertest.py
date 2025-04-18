import asyncio
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.flags
from dns.rdtypes.IN import A as dns_rdtypes_IN_A

# Lista negra de dominios
blacklist = ["pornhub.com","xvideos.com", "malicious.net"]

# IP de la página de bloqueo
block_page_ip = "127.0.0.1"

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
            request = dns.message.from_bytes(data)
            response = self.handle_query(request)
            self.transport.sendto(response.to_bytes(), addr)
            print(f"Respondido a {addr} para {request.question[0].name}")
        except dns.message.BadFormedMessage:
            print(f"Consulta mal formada de {addr}")
        except Exception as e:
            print(f"Error al procesar la consulta de {addr}: {e}")

    def handle_query(self, request):
        query_name = request.question[0].name.to_text().lower()
        query_type = request.question[0].rdtype
        response = dns.message.make_response(request)
        response.flags |= dns.flags.RA  # Recursion Available

        if query_type == dns.rdatatype.A:
            print(f"Consulta de tipo A recibada para: {query_name}")
            if query_name in self.blacklist:
                a = dns_rdtypes_IN_A(dns.rdataclass.IN, dns.rdatatype.A, dns_rdtypes_IN_A.from_text(self.block_page_ip))
                response.answer.append(dns.rrset.RRset(query_name, dns.rdataclass.IN, dns.rdatatype.A, a))
                print(f"Bloqueado: {query_name} -> {self.block_page_ip}")
            else:
                response.flags |= dns.flags.Rcode.NXDOMAIN # Non-Existent Domain
        else:
            response.flags |= dns.flags.Rcode.REFUSED # Refused

        return response

async def main():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSServerProtocol(blacklist, block_page_ip),
        local_addr=('0.0.0.0', 8053)  # Usando el puerto alternativo
    )
    try:
        await asyncio.Future()  # Mantener el servidor corriendo indefinidamente
    finally:
        transport.close()

if __name__ == "__main__":
    asyncio.run(main())