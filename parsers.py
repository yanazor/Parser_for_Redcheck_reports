# функция для перевода в csv

import xml.etree.ElementTree as ET
import csv
import re
import pandas as pd
from collections import defaultdict


def xml2csv(file, filename):
    trt = []
    address = []
    description = []
    cpe = []
    b_id = []
    start = []
    stop = []
    cred = []
    l_def = []
    inner_ids = {}
    items = {}
    prods = {}
    titles = {}
    tdesc = {}
    def_class = {}
    def_oval_id = {}
    def_version = {}
    def_deprecated = {}
    def_remediation = {}
    def_altx_id = {}
    def_severity = {}
    ref_source_1 = {}
    ref_source_2 = {}
    ref_source_3 = {}
    ref_source_4 = {}
    ref_id_1 = {}
    ref_id_2 = {}
    ref_id_3 = {}
    ref_id_4 = {}
    ref_url_1 = {}
    ref_url_2 = {}
    ref_url_3 = {}
    ref_url_4 = {}
    cvss_score_1 = {}
    cvss_score_2 = {}
    cvss_score_3 = {}
    cvss_score_4 = {}
    cvss_vector_1 = {}
    cvss_vector_2 = {}
    cvss_vector_3 = {}
    cvss_vector_4 = {}
    cvss_score3_1 = {}
    cvss_score3_2 = {}
    cvss_score3_3 = {}
    cvss_score3_4 = {}
    cvss_vector3_1 = {}
    cvss_vector3_2 = {}
    cvss_vector3_3 = {}
    cvss_vector3_4 = {}
    cvss_cwe_1 = {}
    cvss_cwe_2 = {}
    cvss_cwe_3 = {}
    cvss_cwe_4 = {}

    tree = ET.parse(file)
    root = tree.getroot()
    cat = root.find('catalogs')
    rep = cat.find('targets')
    body = root.find('body')

    for i in rep:
        trt.append(i.attrib['inner_id'])
        address.append(i.find('address').text)
        if len(i.findall('description')) > 0:
            description.append(i.find('description').text)
        else:
            description.append('-')
        cpe.append(i.find('cpe').text)
    for i in body.findall('.//result'):
        b_id.append(i.attrib['id'])
        start.append(i.attrib['start'])
        stop.append(i.attrib['stop'])
        cred.append(i.attrib['cred'])

    body = root.find('body')
    job_report = body.findall('job_report')
    for b in range(len(job_report)):
        # В tar_rep список из всех таргет_репортов
        tar_rep = job_report[b].findall('target_report')
        for i in range(len(tar_rep)):
            tar = tar_rep[i].find('target')
            result = tar_rep[i].find('result')
            ddef = []
            iitem = []
            pprod = []
            # в vulnerability список всех vulnerability
            vulnerability = result.findall('vulnerability')
            for a in range(len(vulnerability)):
                inner_id = vulnerability[a].attrib['inner_id']
                ddef.append(inner_id)
                inner_ids = {**inner_ids, **{tar.text: ddef}}
            l_def.append(ddef)
            for a in range(len(vulnerability)):
                item = vulnerability[a].find('detalization').find('item')
                try:
                    iitem.append(item.text)
                except AttributeError:
                    iitem.append('')
                items = {**items, **{tar.text: iitem}}
            for a in range(len(vulnerability)):
                prod = vulnerability[a].find('products').find('product')
                try:
                    pprod.append(prod.text)
                except AttributeError:
                    pprod.append('')
                prods = {**prods, **{tar.text: pprod}}
    definitions = cat.find('definitions')
    definition = definitions.findall('definition')
    for a in range(len(definition)):
        def_inner = definition[a].attrib['inner_id']
        dc = definition[a].attrib['class']
        dovid = definition[a].attrib['oval_id']
        dver = definition[a].attrib['version']
        ddep = definition[a].attrib['deprecated']
        drem = definition[a].attrib['remediation']
        daltx = definition[a].attrib['altx_id']
        dsevr = definition[a].attrib['severity']
        tt = definition[a].find('title')
        td = definition[a].find('description')
        def_class = {**def_class, **{def_inner: dc}}
        def_oval_id = {**def_oval_id, **{def_inner: dovid}}
        def_version = {**def_version, **{def_inner: dver}}
        def_deprecated = {**def_deprecated, **{def_inner: ddep}}
        def_remediation = {**def_remediation, **{def_inner: drem}}
        def_altx_id = {**def_altx_id, **{def_inner: daltx}}
        def_severity = {**def_severity, **{def_inner: dsevr}}
        titles = {**titles, **{def_inner: tt.text}}
        tdesc = {**tdesc, **{def_inner: td.text}}
        reference = definition[a].findall('reference')
        for b in range(len(reference)):
            if b < 4:
                rsource = ' '
                rsource_el = ' '
                rsource_els = ' '
                rsource_4 = ' '
                refid_1 = ' '
                refid_2 = ' '
                refid_3 = ' '
                refid_4 = ' '
                refurl_1 = ' '
                refurl_2 = ' '
                refurl_3 = ' '
                refurl_4 = ' '
                cvssscore_1 = ' '
                cvssscore_2 = ' '
                cvssscore_3 = ' '
                cvssscore_4 = ' '
                cvssvector_1 = ' '
                cvssvector_2 = ' '
                cvssvector_3 = ' '
                cvssvector_4 = ' '
                cvssscore3_1 = ' '
                cvssscore3_2 = ' '
                cvssscore3_3 = ' '
                cvssscore3_4 = ' '
                cvssvector3_1 = ' '
                cvssvector3_2 = ' '
                cvssvector3_3 = ' '
                cvssvector3_4 = ' '
                cvsscwe_1 = ' '
                cvsscwe_2 = ' '
                cvsscwe_3 = ' '
                cvsscwe_4 = ' '

                ref_source_1 = {**ref_source_1, **{def_inner: rsource}}
                ref_source_2 = {**ref_source_2, **{def_inner: rsource_el}}
                ref_source_3 = {**ref_source_3, **{def_inner: rsource_els}}
                ref_source_4 = {**ref_source_4, **{def_inner: rsource_4}}
                ref_id_1 = {**ref_id_1, **{def_inner: refid_1}}
                ref_id_2 = {**ref_id_2, **{def_inner: refid_2}}
                ref_id_3 = {**ref_id_3, **{def_inner: refid_3}}
                ref_id_4 = {**ref_id_4, **{def_inner: refid_4}}
                ref_url_1 = {**ref_url_1, **{def_inner: refurl_1}}
                ref_url_2 = {**ref_url_2, **{def_inner: refurl_2}}
                ref_url_3 = {**ref_url_3, **{def_inner: refurl_3}}
                ref_url_4 = {**ref_url_4, **{def_inner: refurl_4}}
                cvss_score_1 = {**cvss_score_1, **{def_inner: cvssscore_1}}
                cvss_score_2 = {**cvss_score_2, **{def_inner: cvssscore_2}}
                cvss_score_3 = {**cvss_score_3, **{def_inner: cvssscore_3}}
                cvss_score_4 = {**cvss_score_4, **{def_inner: cvssscore_4}}
                cvss_vector_1 = {**cvss_vector_1, **{def_inner: cvssvector_1}}
                cvss_vector_2 = {**cvss_vector_2, **{def_inner: cvssvector_2}}
                cvss_vector_3 = {**cvss_vector_3, **{def_inner: cvssvector_3}}
                cvss_vector_4 = {**cvss_vector_4, **{def_inner: cvssvector_4}}
                cvss_score3_1 = {**cvss_score3_1, **{def_inner: cvssscore3_1}}
                cvss_score3_2 = {**cvss_score3_2, **{def_inner: cvssscore3_2}}
                cvss_score3_3 = {**cvss_score3_3, **{def_inner: cvssscore3_3}}
                cvss_score3_4 = {**cvss_score3_4, **{def_inner: cvssscore3_4}}
                cvss_vector3_1 = {**cvss_vector3_1, **{def_inner: cvssvector3_1}}
                cvss_vector3_2 = {**cvss_vector3_2, **{def_inner: cvssvector3_2}}
                cvss_vector3_3 = {**cvss_vector3_3, **{def_inner: cvssvector3_3}}
                cvss_vector3_4 = {**cvss_vector3_4, **{def_inner: cvssvector3_4}}
                cvss_cwe_1 = {**cvss_cwe_1, **{def_inner: cvsscwe_1}}
                cvss_cwe_2 = {**cvss_cwe_2, **{def_inner: cvsscwe_2}}
                cvss_cwe_3 = {**cvss_cwe_3, **{def_inner: cvsscwe_3}}
                cvss_cwe_4 = {**cvss_cwe_4, **{def_inner: cvsscwe_4}}

        for b in range(len(reference)):
            if b == 0:
                rsource = reference[b].attrib['source']
                ref_source_1 = {**ref_source_1, **{def_inner: rsource}}
                refid_1 = reference[b].attrib['ref_id']
                ref_id_1 = {**ref_id_1, **{def_inner: refid_1}}
                try:
                    refurl_1 = reference[b].attrib['ref_url']
                except KeyError:
                    refurl_1 = ' '
                ref_url_1 = {**ref_url_1, **{def_inner: refurl_1}}
                cvssscore_1 = reference[b].find('cvss_score')
                if cvssscore_1 is None:
                    cvssscore_1 = ' '
                    cvss_score_1 = {**cvss_score_1, **{def_inner: cvssscore_1}}
                else:
                    cvss_score_1 = {**cvss_score_1, **{def_inner: 'score:' + cvssscore_1.text}}

                cvssvector_1 = reference[b].find('cvss_vector')
                if cvssvector_1 is None:
                    cvssvector_1 = ' '
                    cvss_vector_1 = {**cvss_vector_1, **{def_inner: cvssvector_1}}
                else:
                    cvss_vector_1 = {**cvss_vector_1, **{def_inner: cvssvector_1.text}}
                cvssscore3_1 = reference[b].find('cvss_score_3')
                if cvssscore3_1 is None:
                    cvssscore3_1 = ' '
                    cvss_score3_1 = {**cvss_score3_1, **{def_inner: cvssscore3_1}}
                else:
                    cvss_score3_1 = {**cvss_score3_1, **{def_inner: 'score:' + cvssscore3_1.text}}
                cvssvector3_1 = reference[b].find('cvss_vector_3')
                if cvssvector3_1 is None:
                    cvssvector3_1 = ' '
                    cvss_vector3_1 = {**cvss_vector3_1, **{def_inner: cvssvector3_1}}
                else:
                    cvss_vector3_1 = {**cvss_vector3_1, **{def_inner: cvssvector3_1.text}}
                cvsscwe_1 = reference[b].find('cwe')
                if cvsscwe_1 is None:
                    cvsscwe_1 = ' '
                    cvss_cwe_1 = {**cvss_cwe_1, **{def_inner: cvsscwe_1}}
                else:
                    cvss_cwe_1 = {**cvss_cwe_1, **{def_inner: cvsscwe_1.text}}
            elif b == 1:
                rsource_el = reference[b].attrib['source']
                ref_source_2 = {**ref_source_2, **{def_inner: rsource_el}}
                refid_2 = reference[b].attrib['ref_id']
                ref_id_2 = {**ref_id_2, **{def_inner: refid_2}}
                refurl_2 = reference[b].attrib['ref_url']
                ref_url_2 = {**ref_url_2, **{def_inner: refurl_2}}
                cvssscore_2 = reference[b].find('cvss_score')
                if cvssscore_2 is None:
                    cvssscore_2 = ' '
                    cvss_score_2 = {**cvss_score_2, **{def_inner: cvssscore_2}}
                else:
                    cvss_score_2 = {**cvss_score_2, **{def_inner: 'score:' + cvssscore_2.text}}
                cvssvector_2 = reference[b].find('cvss_vector')
                if cvssvector_2 is None:
                    cvssvector_2 = ' '
                    cvss_vector_2 = {**cvss_vector_2, **{def_inner: cvssvector_2}}
                else:
                    cvss_vector_2 = {**cvss_vector_2, **{def_inner: cvssvector_2.text}}

                cvssscore3_2 = reference[b].find('cvss_score_3')
                if cvssscore3_2 is None:
                    cvssscore3_2 = ' '
                    cvss_score3_2 = {**cvss_score3_2, **{def_inner: cvssscore3_2}}
                else:
                    cvss_score3_2 = {**cvss_score3_2, **{def_inner: 'score:' + cvssscore3_2.text}}
                cvssvector3_2 = reference[b].find('cvss_vector_3')
                if cvssvector3_2 is None:
                    cvssvector3_2 = ' '
                    cvss_vector3_2 = {**cvss_vector3_2, **{def_inner: cvssvector3_2}}
                else:
                    cvss_vector3_2 = {**cvss_vector3_2, **{def_inner: cvssvector3_2.text}}
                cvsscwe_2 = reference[b].find('cwe')
                if cvsscwe_2 is None:
                    cvsscwe_2 = ' '
                    cvss_cwe_2 = {**cvss_cwe_2, **{def_inner: cvsscwe_2}}
                else:
                    cvss_cwe_2 = {**cvss_cwe_2, **{def_inner: cvsscwe_2.text}}
            elif b == 2:
                rsource_els = reference[b].attrib['source']
                ref_source_3 = {**ref_source_3, **{def_inner: rsource_els}}
                refid_3 = reference[b].attrib['ref_id']
                ref_id_3 = {**ref_id_3, **{def_inner: refid_3}}
                refurl_3 = reference[b].attrib['ref_url']
                ref_url_3 = {**ref_url_3, **{def_inner: refurl_3}}
                cvssscore_3 = reference[b].find('cvss_score')
                if cvssscore_3 is None:
                    cvssscore_3 = ' '
                    cvss_score_3 = {**cvss_score_3, **{def_inner: cvssscore_3}}
                else:
                    cvss_score_3 = {**cvss_score_3, **{def_inner: 'score:' + cvssscore_3.text}}
                cvssvector_3 = reference[b].find('cvss_vector')
                if cvssvector_3 is None:
                    cvssvector_3 = ' '
                    cvss_vector_3 = {**cvss_vector_3, **{def_inner: cvssvector_3}}
                else:
                    cvss_vector_3 = {**cvss_vector_3, **{def_inner: cvssvector_3.text}}
                cvssscore3_3 = reference[b].find('cvss_score_3')
                if cvssscore3_3 is None:
                    cvssscore3_3 = ' '
                    cvss_score3_3 = {**cvss_score3_3, **{def_inner: cvssscore3_3}}
                else:
                    cvss_score3_3 = {**cvss_score3_3, **{def_inner: 'score:' + cvssscore3_3.text}}
                cvssvector3_3 = reference[b].find('cvss_vector_3')
                if cvssvector3_3 is None:
                    cvssvector3_3 = ' '
                    cvss_vector3_3 = {**cvss_vector3_3, **{def_inner: cvssvector3_3}}
                else:
                    cvss_vector3_3 = {**cvss_vector3_3, **{def_inner: cvssvector3_3.text}}
                cvsscwe_3 = reference[b].find('cwe')
                if cvsscwe_3 is None:
                    cvsscwe_3 = ' '
                    cvss_cwe_3 = {**cvss_cwe_3, **{def_inner: cvsscwe_3}}
                else:
                    cvss_cwe_3 = {**cvss_cwe_3, **{def_inner: cvsscwe_3.text}}
            elif b == 3:
                rsource_4 = reference[b].attrib['source']
                ref_source_4 = {**ref_source_4, **{def_inner: rsource_4}}
                refid_4 = reference[b].attrib['ref_id']
                ref_id_4 = {**ref_id_4, **{def_inner: refid_4}}
                refurl_4 = reference[b].attrib['ref_url']
                ref_url_4 = {**ref_url_4, **{def_inner: refurl_4}}
                cvssscore_4 = reference[b].find('cvss_score')
                if cvssscore_4 is None:
                    cvssscore_4 = ' '
                    cvss_score_4 = {**cvss_score_4, **{def_inner: cvssscore_4}}
                else:
                    cvss_score_4 = {**cvss_score_4, **{def_inner: 'score:' + cvssscore_4.text}}
                cvssvector_4 = reference[b].find('cvss_vector')
                if cvssvector_4 is None:
                    cvssvector_4 = ' '
                    cvss_vector_4 = {**cvss_vector_4, **{def_inner: cvssvector_4}}
                else:
                    cvss_vector_4 = {**cvss_vector_4, **{def_inner: cvssvector_4.text}}
                cvssscore3_4 = reference[b].find('cvss_score_3')
                if cvssscore3_4 is None:
                    cvssscore3_4 = ' '
                    cvss_score3_4 = {**cvss_score3_4, **{def_inner: cvssscore3_4}}
                else:
                    cvss_score3_4 = {**cvss_score3_4, **{def_inner: 'score:' + cvssscore3_4.text}}
                cvssvector3_4 = reference[b].find('cvss_vector_3')
                if cvssvector3_4 is None:
                    cvssvector3_4 = ' '
                    cvss_vector3_4 = {**cvss_vector3_4, **{def_inner: cvssvector3_4}}
                else:
                    cvss_vector3_4 = {**cvss_vector3_4, **{def_inner: cvssvector3_4.text}}
                cvsscwe_4 = reference[b].find('cwe')
                if cvsscwe_4 is None:
                    cvsscwe_4 = ' '
                    cvss_cwe_4 = {**cvss_cwe_4, **{def_inner: cvsscwe_4}}
                else:
                    cvss_cwe_4 = {**cvss_cwe_4, **{def_inner: cvsscwe_4.text}}

    with open(filename, mode="wt", encoding='utf-8') as w_file:
        cols = ["trt", "address", "trt_description", "cpe", "id", "start", "stop", "cred", "def", "item", "product",
                "title", "def_description",
                "def_class", "def_oval_id", "def_version", "def_deprecated", "def_altx_id", "def_severity",
                "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1", "cvss_score_1", "cvss_vector_1",
                "cvss_score3_1", "cvss_vector3_1", "cvss_cwe_1",
                "reference_source_2", "ref_id_2", "ref_url_2", "cvss_score_2", "cvss_vector_2", "cvss_score3_2",
                "cvss_vector3_2", "cvss_cwe_2",
                "reference_source_3", "ref_id_3", "ref_url_3", "cvss_score_3", "cvss_vector_3", "cvss_score3_3",
                "cvss_vector3_3", "cvss_cwe_3",
                "reference_source_4", "ref_id_4", "ref_url_4", "cvss_score_4", "cvss_vector_4", "cvss_score3_4",
                "cvss_vector3_4", "cvss_cwe_4"]
        file_writer = csv.DictWriter(w_file, delimiter=";",
                                     lineterminator='\r', fieldnames=cols)
        file_writer.writeheader()
        for i in range(len(trt)):
            first_line = {"trt": trt[i], "address": address[i], "trt_description": description[i], "cpe": cpe[i],
                          'id': b_id[i],
                          "start": start[i], "stop": stop[i], "cred": cred[i], "def": "", "item": "", "product": "",
                          "title": "", 'def_description': '', "def_class": "", "def_oval_id": "", "def_version": "",
                          "def_deprecated": "",
                          "def_altx_id": "", "def_remediation": "",
                          "def_severity": "", "reference_source_1": "", "ref_id_1": "",
                          "ref_url_1": "", "cvss_score_1": "", "cvss_vector_1": "",
                          "cvss_score3_1": "", "cvss_vector3_1": "", "cvss_cwe_1": "", "reference_source_2": "",
                          "ref_id_2": "", "ref_url_2": "", "cvss_score_2": "",
                          "cvss_vector_2": "", "cvss_score3_2": "", "cvss_vector3_2": "", "cvss_cwe_2": "",
                          "reference_source_3": "", "ref_id_3": "", "ref_url_3": "",
                          "cvss_score_3": "", "cvss_vector_3": "", "cvss_score3_3": "", "cvss_vector3_3": "",
                          "cvss_cwe_3": "", "reference_source_4": "", "ref_id_4": "",
                          "ref_url_4": "", "cvss_score_4": "", "cvss_vector_4": "", "cvss_score3_4": "",
                          "cvss_vector3_4": "", "cvss_cwe_4": ""}
            other_lines = []
            for a in range(len(inner_ids[trt[i]])):
                if a == 0:
                    first_line["def"] = inner_ids[trt[i]][a]
                    first_line["item"] = items[trt[i]][a]
                    first_line["product"] = prods[trt[i]][a]
                else:
                    other_lines.append(
                        {"trt": trt[i], "address": address[i], "trt_description": description[i], "cpe": cpe[i],
                         'id': b_id[i], "start": start[i],
                         "stop": stop[i], "cred": cred[i], "def": inner_ids[trt[i]][a], "item": items[trt[i]][a],
                         "product": prods[trt[i]][a], "title": "", 'def_description': '',
                         "def_class": "", "def_oval_id": "", "def_version": "",
                         "def_deprecated": "", "def_altx_id": "", "def_remediation": "",
                         "def_severity": "", "reference_source_1": "", "ref_id_1": "", "ref_url_1": "",
                         "cvss_score_1": "", "cvss_vector_1": "", "cvss_score3_1": "", "cvss_vector3_1": "",
                         "cvss_cwe_1": "", "reference_source_2": "", "ref_id_2": "", "ref_url_2": "",
                         "cvss_score_2": "", "cvss_vector_2": "", "cvss_score3_2": "", "cvss_vector3_2": "",
                         "cvss_cwe_2": "", "reference_source_3": "", "ref_id_3": "", "ref_url_3": "",
                         "cvss_score_3": "", "cvss_vector_3": "", "cvss_score3_3": "", "cvss_vector3_3": "",
                         "cvss_cwe_3": "", "reference_source_4": "", "ref_id_4": "", "ref_url_4": "",
                         "cvss_score_4": "", "cvss_vector_4": "", "cvss_score3_4": "", "cvss_vector3_4": "",
                         "cvss_cwe_4": ""})

            for c in range(len(l_def[i])):
                if c == 0:
                    first_line["title"] = titles[l_def[i][c]]
                    first_line["def_class"] = def_class[l_def[i][c]]
                    first_line["def_oval_id"] = def_oval_id[l_def[i][c]]
                    first_line["def_version"] = def_version[l_def[i][c]]
                    first_line["def_deprecated"] = def_deprecated[l_def[i][c]]
                    first_line["def_altx_id"] = def_altx_id[l_def[i][c]]
                    first_line["def_remediation"] = def_remediation[l_def[i][c]]
                    first_line["def_severity"] = def_severity[l_def[i][c]]
                    first_line["def_description"] = tdesc[l_def[i][c]]
                    first_line["reference_source_1"] = ref_source_1[l_def[i][c]]
                    first_line["ref_id_1"] = ref_id_1[l_def[i][c]]
                    first_line["ref_url_1"] = ref_url_1[l_def[i][c]]
                    first_line["cvss_score_1"] = cvss_score_1[l_def[i][c]]
                    first_line["cvss_vector_1"] = cvss_vector_1[l_def[i][c]]
                    first_line["cvss_score3_1"] = cvss_score3_1[l_def[i][c]]
                    first_line["cvss_vector3_1"] = cvss_vector3_1[l_def[i][c]]
                    first_line["cvss_cwe_1"] = cvss_cwe_1[l_def[i][c]]
                    first_line["reference_source_2"] = ref_source_2[l_def[i][c]]
                    first_line["ref_id_2"] = ref_id_2[l_def[i][c]]
                    first_line["ref_url_2"] = ref_url_2[l_def[i][c]]
                    first_line["cvss_score_2"] = cvss_score_2[l_def[i][c]]
                    first_line["cvss_vector_2"] = cvss_vector_2[l_def[i][c]]
                    first_line["cvss_score3_2"] = cvss_score3_2[l_def[i][c]]
                    first_line["cvss_vector3_2"] = cvss_vector3_2[l_def[i][c]]
                    first_line["cvss_cwe_2"] = cvss_cwe_2[l_def[i][c]]
                    first_line["reference_source_3"] = ref_source_3[l_def[i][c]]
                    first_line["ref_id_3"] = ref_id_3[l_def[i][c]]
                    first_line["ref_url_3"] = ref_url_3[l_def[i][c]]
                    first_line["cvss_score_3"] = cvss_score_3[l_def[i][c]]
                    first_line["cvss_vector_3"] = cvss_vector_3[l_def[i][c]]
                    first_line["cvss_score3_3"] = cvss_score3_3[l_def[i][c]]
                    first_line["cvss_vector3_3"] = cvss_vector3_3[l_def[i][c]]
                    first_line["cvss_cwe_3"] = cvss_cwe_3[l_def[i][c]]
                    first_line["reference_source_4"] = ref_source_4[l_def[i][c]]
                    first_line["ref_id_4"] = ref_id_4[l_def[i][c]]
                    first_line["ref_url_4"] = ref_url_4[l_def[i][c]]
                    first_line["cvss_score_4"] = cvss_score_4[l_def[i][c]]
                    first_line["cvss_vector_4"] = cvss_vector_4[l_def[i][c]]
                    first_line["cvss_score3_4"] = cvss_score3_4[l_def[i][c]]
                    first_line["cvss_vector3_4"] = cvss_vector3_4[l_def[i][c]]
                    first_line["cvss_cwe_4"] = cvss_cwe_4[l_def[i][c]]
                else:
                    other_lines[c - 1]["title"] = titles[l_def[i][c]]
                    other_lines[c - 1]["def_class"] = def_class[l_def[i][c]]
                    other_lines[c - 1]["def_oval_id"] = def_oval_id[l_def[i][c]]
                    other_lines[c - 1]["def_version"] = def_version[l_def[i][c]]
                    other_lines[c - 1]["def_deprecated"] = def_deprecated[l_def[i][c]]
                    other_lines[c - 1]["def_altx_id"] = def_altx_id[l_def[i][c]]
                    other_lines[c - 1]["def_remediation"] = def_remediation[l_def[i][c]]
                    other_lines[c - 1]["def_severity"] = def_severity[l_def[i][c]]
                    other_lines[c - 1]["def_description"] = tdesc[l_def[i][c]]
                    other_lines[c - 1]["reference_source_1"] = ref_source_1[l_def[i][c]]
                    other_lines[c - 1]["ref_id_1"] = ref_id_1[l_def[i][c]]
                    other_lines[c - 1]["ref_url_1"] = ref_url_1[l_def[i][c]]
                    other_lines[c - 1]["cvss_score_1"] = cvss_score_1[l_def[i][c]]
                    other_lines[c - 1]["cvss_vector_1"] = cvss_vector_1[l_def[i][c]]
                    other_lines[c - 1]["cvss_score3_1"] = cvss_score3_1[l_def[i][c]]
                    other_lines[c - 1]["cvss_vector3_1"] = cvss_vector3_1[l_def[i][c]]
                    other_lines[c - 1]["cvss_cwe_1"] = cvss_cwe_1[l_def[i][c]]
                    other_lines[c - 1]["reference_source_2"] = ref_source_2[l_def[i][c]]
                    other_lines[c - 1]["ref_id_2"] = ref_id_2[l_def[i][c]]
                    other_lines[c - 1]["ref_url_2"] = ref_url_2[l_def[i][c]]
                    other_lines[c - 1]["cvss_score_2"] = cvss_score_2[l_def[i][c]]
                    other_lines[c - 1]["cvss_vector_2"] = cvss_vector_2[l_def[i][c]]
                    other_lines[c - 1]["cvss_score3_2"] = cvss_score3_2[l_def[i][c]]
                    other_lines[c - 1]["cvss_vector3_2"] = cvss_vector3_2[l_def[i][c]]
                    other_lines[c - 1]["cvss_cwe_2"] = cvss_cwe_2[l_def[i][c]]
                    other_lines[c - 1]["reference_source_3"] = ref_source_3[l_def[i][c]]
                    other_lines[c - 1]["ref_id_3"] = ref_id_3[l_def[i][c]]
                    other_lines[c - 1]["ref_url_3"] = ref_url_3[l_def[i][c]]
                    other_lines[c - 1]["cvss_score_3"] = cvss_score_3[l_def[i][c]]
                    other_lines[c - 1]["cvss_vector_3"] = cvss_vector_3[l_def[i][c]]
                    other_lines[c - 1]["cvss_score3_3"] = cvss_score3_3[l_def[i][c]]
                    other_lines[c - 1]["cvss_vector3_3"] = cvss_vector3_3[l_def[i][c]]
                    other_lines[c - 1]["cvss_cwe_3"] = cvss_cwe_3[l_def[i][c]]
                    other_lines[c - 1]["reference_source_4"] = ref_source_4[l_def[i][c]]
                    other_lines[c - 1]["ref_id_4"] = ref_id_4[l_def[i][c]]
                    other_lines[c - 1]["ref_url_4"] = ref_url_4[l_def[i][c]]
                    other_lines[c - 1]["cvss_score_4"] = cvss_score_4[l_def[i][c]]
                    other_lines[c - 1]["cvss_vector_4"] = cvss_vector_4[l_def[i][c]]
                    other_lines[c - 1]["cvss_score3_4"] = cvss_score3_4[l_def[i][c]]
                    other_lines[c - 1]["cvss_vector3_4"] = cvss_vector3_4[l_def[i][c]]
                    other_lines[c - 1]["cvss_cwe_4"] = cvss_cwe_4[l_def[i][c]]
            file_writer.writerow(first_line)
            for line in other_lines:
                file_writer.writerow(line)


def modern(filename, file, file_soot=None):
    f = pd.read_csv(filename, sep=';', encoding='utf-8')  # открыаем файл

    # создаем список имен столбцов

    keep_col = ["address", "product", "title", "def_severity",
                "def_remediation", 'def_description', "reference_source_1", "ref_id_1", "ref_url_1",
                "reference_source_2", "ref_id_2", "ref_url_2", "reference_source_3", "ref_id_3", "ref_url_3",
                "reference_source_4", "ref_id_4", "ref_url_4"]
    # ">[A-Z]{2}[0-9]{7}"gm для отлова kb
    # создаем фрейм
    new_f = f[keep_col]

    # обновления
    for col, row in new_f.iterrows():
        upd = ''
        match = re.findall(r'>[A-Z]{2}[0-9]{3,9}', row['def_remediation'])
        if not match:
            continue
        for i in match:
            upd += i.lstrip('>') + ' '

        row['def_remediation'] = upd

    # проверяем все ref_id на наличие значений FSTEC по reference_source
    # и перезаписываем ref_id_1
    for col, row in new_f.iterrows():
        if row['reference_source_1'] == "FSTEC":
            continue
        elif row["reference_source_2"] == "FSTEC":
            row["reference_source_1"] = "FSTEC"
            row["ref_id_1"] = row["ref_id_2"]
            row["ref_url_1"] = row["ref_url_2"]
        elif row["reference_source_3"] == "FSTEC":
            row["reference_source_1"] = "FSTEC"
            row["ref_id_1"] = row["ref_id_3"]
            row["ref_url_1"] = row["ref_url_3"]
        elif row["reference_source_4"] == "FSTEC":
            row["reference_source_1"] = "FSTEC"
            row["ref_id_1"] = row["ref_id_4"]
            row["ref_url_1"] = row["ref_url_4"]

    # или CVE
    for col, row in new_f.iterrows():
        if row['reference_source_1'] != "FSTEC":
            if row['reference_source_1'] == "CVE":
                continue
            elif row["reference_source_2"] == "CVE":
                row["reference_source_1"] = "CVE"
                row["ref_id_1"] = row["ref_id_2"]
                row["ref_url_1"] = row["ref_url_2"]
            elif row["reference_source_3"] == "CVE":
                row["reference_source_1"] = "CVE"
                row["ref_id_1"] = row["ref_id_3"]
                row["ref_url_1"] = row["ref_url_3"]
            elif row["reference_source_4"] == "CVE":
                row["reference_source_1"] = "CVE"
                row["ref_id_1"] = row["ref_id_4"]
                row["ref_url_1"] = row["ref_url_4"]

    # замена ip-адресов на сетевые имена
    try:
        names = pd.read_csv(file_soot, sep=';', encoding='utf-8')  # открыаем файл
        new_f = new_f.merge(names, on='address', how='left')  # соединяем по 'address'
        for col, row in new_f.iterrows():
            if row['name'] == row['name']:
                continue
            else:
                row['name'] = row['address']
    except FileNotFoundError:
        new_f.columns = ["name", 'product', "title", "def_severity", "def_remediation", 'def_description',
                         "reference_source_1", "ref_id_1", "ref_url_1",
                         "reference_source_2", "ref_id_2", "ref_url_2", "reference_source_3", "ref_id_3", "ref_url_3",
                         "reference_source_4", "ref_id_4", "ref_url_4"]

    new_f = new_f[["name", 'product', "title", "def_severity",
                   "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1",
                   "reference_source_2", "ref_id_2", "ref_url_2", "reference_source_3", "ref_id_3", "ref_url_3",
                   "reference_source_4", "ref_id_4", "ref_url_4"]]

    # заменяем значения def_severity на русский
    for col, row in new_f.iterrows():
        if row["def_severity"] == 'Critical':
            row["def_severity"] = 'Критический'
        elif row["def_severity"] == 'High':
            row["def_severity"] = 'Высокий'
        elif row["def_severity"] == 'Medium':
            row["def_severity"] = 'Средний'
        elif row["def_severity"] == 'Low':
            row["def_severity"] = 'Низкий'

    # создаем новый фрейм без ненужных reference_source, ref_id, ref_url
    new_f = new_f[["name", "product", "title", "def_severity",
                   "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1"]]

    # переименовываем столбцы
    new_f.columns = ["name", "product", "title", "def_severity",
                     "def_remediation", "reference_source", "ref_id", "ref_url"]

    # создаем столбец  заполняем его в зависимости от значения в reference_source
    new_f['BDU FSTEC'] = 'BDU FSTEC'

    for col, row in new_f.iterrows():
        if row['reference_source'] == 'FSTEC':
            row['BDU FSTEC'] = '+'
        else:
            row['BDU FSTEC'] = '-'

    dfv2 = new_f  # делаем копию фрейма

    ref_id = []  # здесь лежат уязвимости
    for i in new_f['ref_id']:
        ref_id.append(i)

    ref_id = list(set(ref_id))  # делаем список с уникальными значениями

    adr = []  # здесь адреса
    for i in new_f['name']:
        adr.append(i)

    # создаем словарь

    d = defaultdict(list)

    # ищем перебором строки с address и ref_id
    for i in ref_id:
        param = new_f.loc[new_f['ref_id'] == i]
        for col, row in param.iterrows():
            j = row['name']
            d[i].append(j)

    nf = pd.DataFrame(
        {key: pd.Series(value) for key, value in d.items()})  # создаем новый фрейм на основе словаря с уязвимостями
    nf = nf.reset_index()  # сбрасываем индекс
    nf = nf.set_index('index').T  # транспонируем
    nf['name'] = [[i for i in row if i == i] for row in
                  nf.values]  # складываем значения из всех адресов в новый столбец
    nf = nf.reset_index()  # сбрасываем индекс
    nf = nf[['index', 'name']]  # оставляем нужные столбцы
    nf.columns = ['ref_id', 'name']  # переименовывываем столбцы

    # удаляем столбец address
    del dfv2['name']
    nf = nf.merge(dfv2, on='ref_id', how='left')  # соединяем по ref_id

    new = nf.drop_duplicates('ref_id')  # удаляем дубликаты

    try:
        vullist = pd.read_excel('vullist.xlsx', sheet_name=None)

        df = pd.DataFrame()
        xls = pd.ExcelFile("vullist.xlsx")
        for i in xls.sheet_names:
            df = pd.concat([df, vullist[i]], axis=0)

        df.columns = ["ref_id", "Возможные меры по устранению"]
        new = new.merge(df, on='ref_id', how='left')
    except FileNotFoundError:
        new.loc[:, "Возможные меры по устранению"] = ''

    new = new.sort_values(['product'])  # сортировка
    new = new[['name', 'product', 'title', 'ref_url', "def_severity", "BDU FSTEC", "Возможные меры по устранению",
               "def_remediation"]]
    # new.columns=['Место установки(ИМЯ)', 'Группа программного обеспечения(Тип ПО)','Тип уязвимости',
    # '№ в БД общеизвестных уязвимостей', 'Уровень риска', 'БДУ ФСТЭК(+/-)', 'Возможные меры по устранению уязвимости']
    # new.to_csv("result.csv", index=False, sep=';', encoding='utf-8') #сохраняем в csv
    new.columns = ['Место установки(ИМЯ)', 'Группа программного обеспечения(Тип ПО)', 'Тип уязвимости (описание)',
                   '№ в БД общеизвестных уязвимостей', 'Уровень риска', 'БДУ ФСТЭК(+/-)',
                   'Возможные меры по устранению уязвимости', 'Рекомендация по устранению уязвимости']

    filesavename = "{}.xlsx".format(file)
    new.to_excel(filesavename, index=False, encoding='utf-8')  # сохраняем в xlsx


def services(file_do, file_posle, file_soot=None):
    xml2csv(file_do, 'rep_do.csv')
    xml2csv(file_posle, 'rep_posle.csv')
    f_1 = pd.read_csv("rep_do.csv", sep=';', encoding='utf-8')
    f_2 = pd.read_csv("rep_posle.csv", sep=';', encoding='utf-8')
    keep_col = ["address", "product", "title", "def_severity",
                "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1",
                "reference_source_2", "ref_id_2", "ref_url_2", "reference_source_3", "ref_id_3", "ref_url_3",
                "reference_source_4", "ref_id_4", "ref_url_4"]

    b = f_1[keep_col]
    a = f_2[keep_col]

    # обновления
    for col, row in b.iterrows():
        upd = ''
        match = re.findall(r'>[A-Z]{2}[0-9]{3,9}', row['def_remediation'])
        if match:
            upd += 'Необходимо установить обновления '
            for i in match:
                upd += i.lstrip('>') + ' '
        if not match:
            match = re.findall(r'/.[a-z/.]*', row['def_remediation'])
            if not match:
                continue
            else:
                match1 = re.findall(r'[А-Яа-я, ]*', row['def_remediation'])
                match[0] = match[0].lstrip('/')
                upd += match1[0] + ' ' + match[0]
        row['def_remediation'] = upd

    # обновления
    for col, row in a.iterrows():
        upd = ''
        match = re.findall(r'>[A-Z]{2}[0-9]{3,9}', row['def_remediation'])
        if match:
            upd += 'Необходимо установить обновления '
            for i in match:
                upd += i.lstrip('>') + ' '
        if not match:
            match = re.findall(r'/.[a-z/.]*', row['def_remediation'])
            if not match:
                continue
            else:
                match1 = re.findall(r'[А-Яа-я, ]*', row['def_remediation'])
                match[0] = match[0].lstrip('/')
                upd += match1[0] + ' ' + match[0]
        row['def_remediation'] = upd

    for col, row in b.iterrows():
        if row['reference_source_1'] == "FSTEC":
            continue
        elif row["reference_source_2"] == "FSTEC":
            row["reference_source_1"] = "FSTEC"
            row["ref_id_1"] = row["ref_id_2"]
            row["ref_url_1"] = row["ref_url_2"]
        elif row["reference_source_3"] == "FSTEC":
            row["reference_source_1"] = "FSTEC"
            row["ref_id_1"] = row["ref_id_3"]
            row["ref_url_1"] = row["ref_url_3"]
        elif row["reference_source_4"] == "FSTEC":
            row["reference_source_1"] = "FSTEC"
            row["ref_id_1"] = row["ref_id_4"]
            row["ref_url_1"] = row["ref_url_4"]

    for col, row in b.iterrows():
        if row['reference_source_1'] != "FSTEC":
            if row['reference_source_1'] == "CVE":
                continue
            elif row["reference_source_2"] == "CVE":
                row["reference_source_1"] = "CVE"
                row["ref_id_1"] = row["ref_id_2"]
                row["ref_url_1"] = row["ref_url_2"]
            elif row["reference_source_3"] == "CVE":
                row["reference_source_1"] = "CVE"
                row["ref_id_1"] = row["ref_id_3"]
                row["ref_url_1"] = row["ref_url_3"]
            elif row["reference_source_4"] == "CVE":
                row["reference_source_1"] = "CVE"
                row["ref_id_1"] = row["ref_id_4"]
                row["ref_url_1"] = row["ref_url_4"]

    for col, row in a.iterrows():
        if row['reference_source_1'] == "FSTEC":
            continue
        elif row["reference_source_2"] == "FSTEC":
            row["reference_source_1"] = "FSTEC"
            row["ref_id_1"] = row["ref_id_2"]
            row["ref_url_1"] = row["ref_url_2"]
        elif row["reference_source_3"] == "FSTEC":
            row["reference_source_1"] = "FSTEC"
            row["ref_id_1"] = row["ref_id_3"]
            row["ref_url_1"] = row["ref_url_3"]
        elif row["reference_source_4"] == "FSTEC":
            row["reference_source_1"] = "FSTEC"
            row["ref_id_1"] = row["ref_id_4"]
            row["ref_url_1"] = row["ref_url_4"]

    # или CVE
    for col, row in a.iterrows():
        if row['reference_source_1'] != "FSTEC":
            if row['reference_source_1'] == "CVE":
                continue
            elif row["reference_source_2"] == "CVE":
                row["reference_source_1"] = "CVE"
                row["ref_id_1"] = row["ref_id_2"]
                row["ref_url_1"] = row["ref_url_2"]
            elif row["reference_source_3"] == "CVE":
                row["reference_source_1"] = "CVE"
                row["ref_id_1"] = row["ref_id_3"]
                row["ref_url_1"] = row["ref_url_3"]
            elif row["reference_source_4"] == "CVE":
                row["reference_source_1"] = "CVE"
                row["ref_id_1"] = row["ref_id_4"]
                row["ref_url_1"] = row["ref_url_4"]

    try:
        names = pd.read_csv(file_soot, sep=';', encoding='utf-8')  # открыаем файл
        b = b.merge(names, on='address', how='left')  # соединяем по 'address'
        for col, row in b.iterrows():
            if row['name'] == row['name']:
                continue
            else:
                row['name'] = row['address']
    except:
        b.columns = ["name", 'product', "title", "def_severity",
                     "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1",
                     "reference_source_2", "ref_id_2", "ref_url_2", "reference_source_3", "ref_id_3", "ref_url_3",
                     "reference_source_4", "ref_id_4", "ref_url_4"]

    try:
        names = pd.read_csv(file_soot, sep=';', encoding='utf-8')  # открыаем файл
        a = a.merge(names, on='address', how='left')  # соединяем по 'address'
        for col, row in a.iterrows():
            if row['name'] == row['name']:
                continue
            else:
                row['name'] = row['address']
    except FileNotFoundError:
        a.columns = ["name", 'product', "title", "def_severity",
                     "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1",
                     "reference_source_2", "ref_id_2", "ref_url_2", "reference_source_3", "ref_id_3", "ref_url_3",
                     "reference_source_4", "ref_id_4", "ref_url_4"]

    b = b[["name", 'product', "title", "def_severity",
           "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1",
           "reference_source_2", "ref_id_2", "ref_url_2", "reference_source_3", "ref_id_3", "ref_url_3",
           "reference_source_4", "ref_id_4", "ref_url_4"]]
    a = a[["name", 'product', "title", "def_severity",
           "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1",
           "reference_source_2", "ref_id_2", "ref_url_2", "reference_source_3", "ref_id_3", "ref_url_3",
           "reference_source_4", "ref_id_4", "ref_url_4"]]

    for col, row in a.iterrows():
        if row["def_severity"] == 'Critical':
            row["def_severity"] = 'Критический'
        elif row["def_severity"] == 'High':
            row["def_severity"] = 'Высокий'
        elif row["def_severity"] == 'Medium':
            row["def_severity"] = 'Средний'
        elif row["def_severity"] == 'Low':
            row["def_severity"] = 'Низкий'
    for col, row in b.iterrows():
        if row["def_severity"] == 'Critical':
            row["def_severity"] = 'Критический'
        elif row["def_severity"] == 'High':
            row["def_severity"] = 'Высокий'
        elif row["def_severity"] == 'Medium':
            row["def_severity"] = 'Средний'
        elif row["def_severity"] == 'Low':
            row["def_severity"] = 'Низкий'

    b = b[["name", "product", "title", "def_severity",
           "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1"]]

    # переименовываем столбцы
    b.columns = ["name", "product", "title", "def_severity",
                 "def_remediation", "reference_source", "ref_id", "ref_url"]

    a = a[["name", "product", "title", "def_severity",
           "def_remediation", "reference_source_1", "ref_id_1", "ref_url_1"]]

    # переименовываем столбцы
    a.columns = ["name", "product", "title", "def_severity",
                 "def_remediation", "reference_source", "ref_id", "ref_url"]

    b['BDU FSTEC'] = 'BDU FSTEC'

    for col, row in b.iterrows():
        if row['reference_source'] == 'FSTEC':
            row['BDU FSTEC'] = '+'
        else:
            row['BDU FSTEC'] = '-'

    a['BDU FSTEC'] = 'BDU FSTEC'

    for col, row in a.iterrows():
        if row['reference_source'] == 'FSTEC':
            row['BDU FSTEC'] = '+'
        else:
            row['BDU FSTEC'] = '-'

    from collections import defaultdict
    ref_id_b = []  # здесь лежат уязвимости
    for i in b['ref_id']:
        ref_id_b.append(i)

    ref_id_b = list(set(ref_id_b))  # делаем список с уникальными значениями

    adr = []  # здесь адреса
    for i in b['name']:
        adr.append(i)

    # создаем словарь

    d = defaultdict(list)

    for i in ref_id_b:
        param = b.loc[b['ref_id'] == i]
        for col, row in param.iterrows():
            j = row['name']
            d[i].append(j)

    nf = pd.DataFrame(
        {key: pd.Series(value) for key, value in d.items()})  # создаем новый фрейм на основе словаря с уязвимостями
    nf = nf.reset_index()  # сбрасываем индекс
    nf = nf.set_index('index').T  # транспонируем
    nf['name'] = [[i for i in row if i == i] for row in
                  nf.values]  # складываем значения из всех адресов в новый столбец
    nf = nf.reset_index()  # сбрасываем индекс
    nf = nf[['index', 'name']]  # оставляем нужные столбцы
    nf.columns = ['ref_id', 'name']  # переименовывываем столбцы

    # удаляем столбец address
    del b['name']
    nfb = nf.merge(b, on='ref_id', how='left')  # соединяем по ref_id

    nfb = nfb.drop_duplicates('ref_id')  # удаляем дубликаты
    nfb = nfb.sort_values(['product'])  # сортировка

    ref_id_a = []  # здесь лежат уязвимости
    for i in a['ref_id']:
        ref_id_a.append(i)

    ref_id_a = list(set(ref_id_a))  # делаем список с уникальными значениями

    adr = []  # здесь адреса
    for i in a['name']:
        adr.append(i)

    # создаем словарь

    d = defaultdict(list)

    for i in ref_id_a:
        param = a.loc[a['ref_id'] == i]
        for col, row in param.iterrows():
            j = row['name']
            d[i].append(j)

    nf = pd.DataFrame(
        {key: pd.Series(value) for key, value in d.items()})  # создаем новый фрейм на основе словаря с уязвимостями
    nf = nf.reset_index()  # сбрасываем индекс
    nf = nf.set_index('index').T  # транспонируем
    nf['name'] = [[i for i in row if i == i] for row in
                  nf.values]  # складываем значения из всех адресов в новый столбец
    nf = nf.reset_index()  # сбрасываем индекс
    nf = nf[['index', 'name']]  # оставляем нужные столбцы
    nf.columns = ['ref_id', 'name']  # переименовывываем столбцы

    # удаляем столбец address
    del a['name']
    nfa = nf.merge(a, on='ref_id', how='left')  # соединяем по ref_id

    nfa = nfa.drop_duplicates('ref_id')  # удаляем дубликаты
    nfa = nfa.sort_values(['product'])  # сортировка

    for col, row in nfb.iterrows():
        row['name'] = str(row['name'])
    for col, row in nfa.iterrows():
        row['name'] = str(row['name'])

    df_all = pd.concat([nfb, nfa], ignore_index=True)
    df_all = df_all.drop_duplicates()  # удаляем дубликаты

    df_all['eliminated'] = ''
    df_all['real_def'] = '-'
    for col, row in df_all.iterrows():
        if ((row['ref_id'] in ref_id_b) & (row['ref_id'] in ref_id_a)) | (
                (row['ref_id'] not in ref_id_b) & (row['ref_id'] in ref_id_a)):
            row['eliminated'] = 'Нет'
        else:
            row['eliminated'] = 'Да'
            row['def_remediation'] = 'Устранена во время проведения СО'
            row['real_def'] = 'Устранена во время проведения СО'
    try:
        vullist = pd.read_excel('vullist.xlsx', sheet_name=None)

        df = pd.DataFrame()
        xls = pd.ExcelFile("vullist.xlsx")
        for i in xls.sheet_names:
            df = pd.concat([df, vullist[i]], axis=0)

        df.columns = ["ref_id", "Возможные меры по устранению"]
        df_all = df_all.merge(df, on='ref_id', how='left')

        for col, row in df_all.iterrows():
            if row['BDU FSTEC'] == '-':
                row['Возможные меры по устранению'] = "-"
    except:
        df_all['Возможные меры по устранению'] = ''

    del df_all['ref_id']

    df_all = df_all[['name', 'product', 'title', 'ref_url', 'def_severity',
                     'BDU FSTEC', 'Возможные меры по устранению',
                     'real_def', 'eliminated', 'def_remediation']]
    df_all.columns = ['Место установки (ИМЯ)', 'Группа программного обеспечения (Тип ПО)',
                      'Тип уязвимости (описание)', '№ в БД общеизвестных уязвимостей', 'Уровень риска',
                      'БДУ ФСТЭК (+/-)', 'Возможные меры по устранению уязвимости', 'Реализованная мера защиты',
                      "Устранена Да/нет", 'Рекомендация по устранению']

    df_all = df_all.set_index(
        ['Место установки (ИМЯ)', 'Группа программного обеспечения (Тип ПО)', 'Тип уязвимости (описание)'])
    df_all.to_excel("./report.xlsx", encoding='utf-8')  # сохраняем в xlsx
