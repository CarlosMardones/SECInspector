import socket


class PortScanner:

    def __init__(self):
        print("Escaneo de puertos inicializado")

    def scan(self):
        for i in range(1,65535):
            info = self.get_service(i)
            if info != "Desconocido":
                print("PORT: " + str(i) + " INFO: " + info)


    def get_service(self,port):
        try:
            return socket.getservbyport(port)
        except OSError:
            return "Desconocido"