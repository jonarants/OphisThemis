# app/dns_server.py

import asyncio
import dns
from dns.asyncio import DNSDatagramProtocol
from dns import rdataclass
from dns import rdatatype
from dns import rrset
from dns import flags
from dns import message
from dns.rdtypes.IN import A as dns_rdtypes_IN_A
# Blacklist domains

blacklist = ["pornhub.com, xvideos.com"]

# Redireccionamiento del server

block_page_ip = "127.0.0.1"

async def handle_query(request, protocol, addr):
    "Entra la petición de dns"
    print (f"Procesando {addr} para: {request.question[0].name}")

    response = dns.message.make_response(request)
    response.flags |= dns.flags.RA #Recursion Available

    query_name = request.question[0].name.to_text().lower
    query_type = request.question[0].rdtype

    if query_type == dns.rdatatype.A:
        if query_name in blacklist:
            # Responder con la IP de la página de bloqueo
            a = dns.rdtypes.IN.A.A(dns.rdataclasss.IN, dns.rdatatype.A, dns.rdtypes.IN.A.A.from_text(block_page_ip))
            response.answer.append(dns.rrset.RRset(query_name, dns.rdataclass.IN, dns.rdatatype.A, a))
            print(f"Bloqueado: {query_name} --> {block_page_ip}")
        else:
            # Por ahora no no respondemos para dominios no bloqueado
            print (f"Permitido: {query_name}")
            response.flags |= dns.flags.Rcode.NXDOMAIN #Non-Existant Domain
    else:
        # Otro tipo de consultas
        print(f"TIpo de consulta no manejado: {dns.rdatatype.to_text(query_type)}")
        response.flags |= dns.flags.Rcode.REFUSED # Refused

    await protocol.send_response(response)

async def main():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: dns.asyncio.DNSDatagramProtocol(handle_query),
        local_addr=('0.0.0.0', 53)
    )
    print("Servidor de DNS escuchando en el puerto 53")
    try:
        await asyncio.Event().wait() # Mantener el servidor corriendo
    finally:
        transport.close()
if __name__ == "__main__":
    asyncio.run(main())