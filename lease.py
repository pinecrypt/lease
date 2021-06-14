#!/usr/bin/env python

import os
import socket
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient
from prometheus_client import Counter
from pymongo import ReturnDocument
from sanic import Sanic, response
from sanic.exceptions import InvalidUsage, NotFound
from sanic_prometheus import monitor
from sanic_wtf import SanicForm
from wtforms import IntegerField, StringField
from wtforms.validators import DataRequired, IPAddress, NumberRange

submit_count = Counter(
    "pinecrypt_gateway_lease_updates",
    "Client IP address updates.",
    ["service"])
flush_count = Counter(
    "pinecrypt_gateway_lease_flushes",
    "Client IP address flushes.",
    ["service"])
migration_count = Counter(
    "pinecrypt_gateway_lease_migrations",
    "Client migrations to this replica.",
    ["replica"])
not_found_count = Counter(
    "pinecrypt_gateway_lease_not_found",
    "Invalid connection attempts.",
    ["service"])

class LeaseUpdateForm(SanicForm):
    service = StringField("Service name")
    internal_addr = StringField("Internal IP address", validators=[DataRequired(), IPAddress(ipv4=True, ipv6=True)])
    remote_addr = StringField("Remote IP address", validators=[DataRequired(), IPAddress(ipv4=True, ipv6=True)])
    remote_port = IntegerField(validators=[NumberRange(min=0, max=65534)])

app = Sanic("lease")
app.config["WTF_CSRF_ENABLED"] = False

MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017/default")
FQDN = socket.getfqdn()


@app.listener('before_server_start')
async def setup_db(app, loop):
    app.ctx.db = AsyncIOMotorClient(MONGO_URI).get_default_database()


async def submit(request, q):
    q["status"] = "signed"
    # TODO: add expiration check

    form = LeaseUpdateForm(request)
    if not form.validate():
        raise InvalidUsage("Invalid form input")

    instance = "%s-%s" % (FQDN, form.service.data)
    doc = await app.ctx.db.certidude_certificates.find_one_and_update(q, {
        "$set": {
            "last_seen": datetime.utcnow(),
            "instance": instance,
            "remote.port": form.remote_port.data,
            "remote.addr": form.remote_addr.data,
        },
        "$addToSet": {
            "ip": form.internal_addr.data
        }
    }, return_document=ReturnDocument.BEFORE)
    if doc:
        submit_count.labels(form.service.data).inc()
        if doc.get("instance") != instance:
            migration_count.labels(FQDN).inc()
        return response.text('Client lease info updated')
    else:
        not_found_count.labels(form.service.data).inc()
        raise NotFound("Client not found")


@app.route("/api/by-serial/<serial_number:int>", methods=["GET"])
async def get_by_serial(request, serial_number):
    obj = await app.ctx.db.certidude_certificates.find_one({
        "serial_number": "%x" % serial_number,
        "status": "signed"})
        # TODO: Add expiration check
    if obj:
        return response.text("Certificate valid")
    else:
        raise NotFound("Certificate not found or not valid")


@app.route("/api/by-dn/<distinguished_name:string>", methods=["POST"])
async def submit_by_dn(request, distinguished_name):
    return await submit(request, {"distinguished_name": distinguished_name.replace("%20", " ")})


@app.route("/api/by-serial/<serial_number:int>", methods=["POST"])
async def submit_by_serial(request, serial_number):
    return await submit(request, {"serial_number": "%x" % serial_number})


@app.route("/api/by-service/<service:string>", methods=["DELETE"])
async def flush(request, service):
    """
    Flush IP addresses assigned by this instance as it was restarted
    """
    await app.ctx.db.certidude_certificates.update_many({
        "instance": "%s-%s" % (FQDN, service),
    }, {
        "$unset": {
            "ip": "",
            "instance": "",
        }
    })
    flush_count.labels(service).inc()
    return response.text('Leases flushed')


monitor(app).expose_endpoint()
app.run(port=2001)
