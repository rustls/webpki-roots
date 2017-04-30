# -*- coding: utf-8 -*-

# Agence Nationale de la Securite des Systemes d'Information (ANSSI)
ANSSI_SUBJECT_DN = (
    "\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02" "FR"
    "\x31\x0F\x30\x0D\x06\x03\x55\x04\x08\x13\x06" "France"
    "\x31\x0E\x30\x0C\x06\x03\x55\x04\x07\x13\x05" "Paris"
    "\x31\x10\x30\x0E\x06\x03\x55\x04\x0A\x13\x07" "PM/SGDN"
    "\x31\x0E\x30\x0C\x06\x03\x55\x04\x0B\x13\x05" "DCSSI"
    "\x31\x0E\x30\x0C\x06\x03\x55\x04\x03\x13\x05" "IGC/A"
    "\x31\x23\x30\x21\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01"
    "\x16\x14" "igca@sgdn.pm.gouv.fr"
    )

ANSSI_NAME_CONSTRAINTS = (
    "\x30\x5D\xA0\x5B"
    "\x30\x05\x82\x03" ".fr"
    "\x30\x05\x82\x03" ".gp"
    "\x30\x05\x82\x03" ".gf"
    "\x30\x05\x82\x03" ".mq"
    "\x30\x05\x82\x03" ".re"
    "\x30\x05\x82\x03" ".yt"
    "\x30\x05\x82\x03" ".pm"
    "\x30\x05\x82\x03" ".bl"
    "\x30\x05\x82\x03" ".mf"
    "\x30\x05\x82\x03" ".wf"
    "\x30\x05\x82\x03" ".pf"
    "\x30\x05\x82\x03" ".nc"
    "\x30\x05\x82\x03" ".tf"
    )

# TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1
TUBITAK1_SUBJECT_DN = (
    "\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02" "TR"
    "\x31\x18\x30\x16\x06\x03\x55\x04\x07\x13\x0f" "Gebze - Kocaeli"
    "\x31\x42\x30\x40\x06\x03\x55\x04\x0a\x13\x39" "Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK"
    "\x31\x2d\x30\x2b\x06\x03\x55\x04\x0b\x13\x24" "Kamu Sertifikasyon Merkezi - Kamu SM"
    "\x31\x36\x30\x34\x06\x03\x55\x04\x03\x13\x2d" "TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1"
    )

TUBITAK1_NAME_CONSTRAINTS = (
    "\x30\x65\xa0\x63"
    "\x30\x09\x82\x07" ".gov.tr"
    "\x30\x09\x82\x07" ".k12.tr"
    "\x30\x09\x82\x07" ".pol.tr"
    "\x30\x09\x82\x07" ".mil.tr"
    "\x30\x09\x82\x07" ".tsk.tr"
    "\x30\x09\x82\x07" ".kep.tr"
    "\x30\x09\x82\x07" ".bel.tr"
    "\x30\x09\x82\x07" ".edu.tr"
    "\x30\x09\x82\x07" ".org.tr"
    )

name_constraints = {
    TUBITAK1_SUBJECT_DN: TUBITAK1_NAME_CONSTRAINTS,
    ANSSI_SUBJECT_DN: ANSSI_NAME_CONSTRAINTS
}

def get_imposed_name_constraints(subject):
    """
    For the given certificate subject name, return a
    name constraints encoding which will be applied
    to that certificate.  Return None to apply
    no constraints.

    Data returned by this function is sourced from:

    https://hg.mozilla.org/projects/nss/file/tip/lib/certdb/genname.c

    Such that webpki-roots implements the same policy in this
    respect as the Mozilla root program.
    """

    return name_constraints.get(subject.decode('hex'), None)
