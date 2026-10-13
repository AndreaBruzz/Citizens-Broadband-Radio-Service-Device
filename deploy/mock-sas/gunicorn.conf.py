import os
import ssl

bind = "0.0.0.0:8443"
workers = 1
threads = 4
accesslog = "-"
errorlog = "-"
loglevel = "info"
capture_output = True
certfile = os.environ.get("SAS_TLS_CERT", "/credentials/server-cert.pem")
keyfile = os.environ.get("SAS_TLS_KEY", "/credentials/server-key.pem")

require_client = os.environ.get("SAS_REQUIRE_CLIENT_CERT", "true")
if require_client not in ("true", "false"):
    raise ValueError("SAS_REQUIRE_CLIENT_CERT must be true or false")
cert_reqs = ssl.CERT_REQUIRED if require_client == "true" else ssl.CERT_NONE
ca_certs = os.environ.get("SAS_CLIENT_CA", "/credentials/client-ca.pem") if cert_reqs else None
ciphers = (
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "AES128-GCM-SHA256:AES256-GCM-SHA384"
)


def ssl_context(conf, default_ssl_context_factory):
    context = default_ssl_context_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def post_worker_init(worker):
    control = worker.wsgi.extensions.get("lab_control")
    if control:
        control.start()


def worker_exit(server, worker):
    control = worker.wsgi.extensions.get("lab_control") if worker.wsgi else None
    if control:
        control.close()
