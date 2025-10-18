BENIGN_PAYLOAD_SAMPLES = [
    [
        "http://localhost:8080/tienda1/publico/anadir.jsp HTTP/1.1",
        "POST",
        "id=3&nombre=Vino+Rioja&precio=100&cantidad=55&B1=A%F1adir+al+carrito",
        "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
    ],
    [
        "http://localhost:8080/tienda1/publico/autenticar.jsp HTTP/1.1",
        "POST",
        "modo=entrar&login=choong&pwd=d1se3ci%F3n&remember=off&B1=Entrar",
        "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
    ],
    [
        "http://localhost:8080/tienda1/publico/entrar.jsp?errorMsg=Credenciales+incorrectas HTTP/1.1",
        "GET",
        "close",
        "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
    ],
]


MALICIOUS_PAYLOAD_SAMPLES = []
