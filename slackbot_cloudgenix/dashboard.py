#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
from datetime import datetime, timedelta
import numpy as np
import requests
import json
from lxml import html

GOOD_RESPONSE = '✅'
BAD_RESPONSE = '❌'
POOR_RESPONSE = '🔴'
NO_RESPONSE = '⚪'
EXCEPTIONAL_RESPONSE = '🔵'
WARNING_RESPONSE = '⚠️'

passed_raw_api = {}

#!/usr/bin/env python
PROGRAM_NAME = "cg-site-health-check.py"
PROGRAM_DESCRIPTION = """
CloudGenix script
---------------------------------------

TODO: Jitter/Latency/Loss measurements per link
TODO: Determine endpoint for service links (which zscaler node/prisma cloud)
TODO: Only Major and Critical alarms/alerts

"""
from cloudgenix import API, jd
import os
import sys
import argparse
from fuzzywuzzy import fuzz
from datetime import datetime,timedelta   
import numpy as np
import requests 
import json
from lxml import html
import cloudgenix_idname

###SYSTEM DEFAULTS
global_vars = {}
global_vars['print_mode'] = "slack"
global_vars['print_borders'] = True
global_vars['print_colors'] = False

global_vars['last_style'] = ""
global_vars['html_buffer'] = '<!DOCTYPE html><html><meta charset="utf-8"><title>CloudGenix Site Health Check</title><br>'
global_vars['slack_buffer'] = '[ { "type": "section", "text": { "type": "mrkdwn", "text": "*CloudGenix Site Health Check*" }, "accessory": {"type": "image","image_url": "https://www.cloudgenix.com/wp-content/uploads/2017/12/CloudGenix_GRD_CLR_RGB-800.png","alt_text": "CloudGenix"}} ]'


T1 = "T1"
P1 = "P1"
H1 = "H1"
H2 = "H2"
B0 = "B0"
B1 = "B1"

class slack_formatter:
    P1_header = "P1"
    H1_header = "H1"
    H2_header = "H2"
    B0_header = "B0"
    B1_header = "B1"
    T1_header = "T1"
    P1_footer = "P1"
    H1_footer = "H1"
    H2_footer = "H2"
    B0_footer = "B0"
    B1_footer = "B1"
    T1_footer = "T1"

style = "style"
data = "data"
theader = "header"
boldfirst = "boldfirst"

dns_trt_thresholds = {
    'fail': 120,
    'warn': 50
}

CLIARGS = {}
sdk = API(update_check=False)              #Instantiate a new CG API Session for AUTH

pan_service_dict = {
                "Prisma Access": 'q8kbg3n63tmp',
                "Prisma Cloud Management": "61lhr4ly5h9b",
                "Prisma Cloud": '1nvndw0xz3nd',
                "Prisma SaaS": 'f0q7vkhppsgw',
}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def pBold(str_to_print):
    global global_vars
    print_mode = global_vars['print_mode']
    print_colors    = global_vars['print_colors']
    if(print_colors):
        if (print_mode == "slack"):
            return(str_to_print)
        if (print_mode == "html"):
            return(str_to_print)
        if (print_mode == "console"):    
            return(bcolors.BOLD + str_to_print + bcolors.ENDC)
    return(str_to_print) ###UKNOWN PRINT MODE

def pFail(str_to_print):
    print_mode      = global_vars['print_mode']
    print_colors    = global_vars['print_colors']
    if(print_colors):
        if (print_mode == "slack"):
            return(":x:" + str_to_print )
        if (print_mode == "html"):
            return(str_to_print)
        if (print_mode == "console"):    
            return(bcolors.FAIL + str_to_print + bcolors.ENDC)
    return(str_to_print) ###UKNOWN PRINT MODE

def pPass(str_to_print):
    global global_vars
    print_mode      = global_vars['print_mode']
    print_colors    = global_vars['print_colors']
    if(print_colors):
        if (print_mode == "slack"):
            return(":white_check_mark:" + str_to_print )
        if (print_mode == "html"):
            return(str_to_print)
        if (print_mode == "console"):    
            return(bcolors.OKGREEN + str_to_print + bcolors.ENDC)
    return(str_to_print) ###UKNOWN PRINT MODE

def pWarn(str_to_print):
    global global_vars
    print_mode      = global_vars['print_mode']
    print_colors    = global_vars['print_colors']
    if(print_colors):
        if (print_mode == "slack"):
            return(":warning:" + str_to_print )
        if (print_mode == "html"):
            return(str_to_print)
        if (print_mode == "console"):    
            return(bcolors.WARNING + str_to_print + bcolors.ENDC)
    return(str_to_print) ###UKNOWN PRINT MODE

def pExceptional(str_to_print):
    global global_vars
    print_mode      = global_vars['print_mode']
    print_colors    = global_vars['print_colors']
    if(print_colors):
        if (print_mode == "slack"):
            return(":small_blue_diamond:" + str_to_print )
        if (print_mode == "html"):
            return(str_to_print)
        if (print_mode == "console"):    
            return(bcolors.OKBLUE + str_to_print + bcolors.ENDC)
    return(str_to_print) ###UKNOWN PRINT MODE
    
def pUnderline(str_to_print):
    global global_vars
    print_mode      = global_vars['print_mode']
    print_colors    = global_vars['print_colors']
    if(print_colors):
        if (print_mode == "slack"):
            return(str_to_print)
        if (print_mode == "html"):
            return(str_to_print)
        if (print_mode == "console"):    
            return(bcolors.UNDERLINE + str_to_print + bcolors.ENDC)
    return(str_to_print) ###UKNOWN PRINT MODE

def dns_trt_classifier(dns_trt_time):
    if( dns_trt_time > dns_trt_thresholds['fail']):
        return pFail(str(dns_trt_time))
    elif (dns_trt_time > dns_trt_thresholds['warn']):
        return pWarn(str(dns_trt_time))
    else:
        return pPass(str(dns_trt_time))

def metric_classifier(value, expected, error_percentage_as_decimal, warn_percentage_as_decimal=0.05):
    if (value < (expected - ( expected * error_percentage_as_decimal ) )):
        return pFail(str(value))
    if (value >= expected + (expected * error_percentage_as_decimal * 2) ):
        return pExceptional(str(value))
    if (value >= expected - (expected * warn_percentage_as_decimal) ):
        return pPass(str(value))
    return pWarn(str(value))
    
class border_char_class:
    dl = u'\u255a'
    ul = u'\u2554'
    dc = u'\u2569'
    uc = u'\u2566'
    ur = u'\u2557'
    lc = u'\u2560'
    u = u'\u2550'
    c = u'\u256c'
    l = u'\u2551'
    rc = u'\u2563'
    dr = u'\u255d'

class low_res_border_char_class:
    dl = '*'
    ul = '+'
    dc = '+'
    uc = '+'
    ur = '+'
    lc = '+'
    u = '-'
    c = '+'
    l = '|'
    rc = '+'
    dr = '+'

class blank_border_char_class:
    dl = ' '
    ul = ' '
    dc = ' '
    uc = ' '
    ur = ' '
    lc = ' '
    u = ' '
    c = ' '
    l = ' '
    rc = ' '
    dr = ' '

def true_len(input_str):
    text = str(input_str)
    if (type(input_str) == str and global_vars['print_mode'] == "console"):
        text = text.replace(bcolors.HEADER, '')
        text = text.replace(bcolors.OKBLUE, '')
        text = text.replace(bcolors.OKGREEN, '')
        text = text.replace(bcolors.WARNING, '')
        text = text.replace(bcolors.FAIL, '')
        text = text.replace(bcolors.BOLD, '')
        text = text.replace(bcolors.UNDERLINE, '')
        text = text.replace(bcolors.ENDC, '')
        return len(text)
    elif (type(input_str) == str and global_vars['print_mode'] == "console"):
        text = text.replace(":white_check_mark:", '')
    return len(input_str)

def uprint(input_array):
    first_item = True
    last_item = False
    
    last_style      = global_vars['last_style']
    print_colors    = global_vars['print_colors']
    print_mode      = global_vars['print_mode']
    print_borders   = global_vars['print_borders']
    html_buffer     = global_vars['html_buffer']
    slack_buffer    = global_vars['slack_buffer']

    item_counter = 0
    if (print_mode == "console"):    
        if (print_borders):
            dbbox = border_char_class
        else:
            dbbox = low_res_border_char_class
        for item in input_array:
            item_counter += 1
            if (item_counter == len(input_array)):
                last_item = True
            if (item['style'] == "P1"):
                if (last_style != ""):
                    print(" ")
                text = item['data']
                item_len = true_len(text)
                print( dbbox.ul + (dbbox.u*item_len) + dbbox.ur)
                print( dbbox.l + pBold(text)+ dbbox.l)
                print( dbbox.lc + (dbbox.u*item_len)+ dbbox.dr)
            elif (item['style'] == "H1"):
                if (last_style != "P1"):
                    print(dbbox.l)
                text = item['data'] 
                item_len = true_len(text)
                print(dbbox.l + dbbox.ul + (dbbox.u*item_len) + dbbox.ur)
                print(dbbox.l + dbbox.l + pBold(text)+ dbbox.l)
                print(dbbox.l + dbbox.lc + (dbbox.u*item_len)+ dbbox.dr)
            elif (item['style'] == "H2"):
                text = item['data'] 
                item_len = true_len(text)
                print(dbbox.l + dbbox.ul + (dbbox.u*item_len) + dbbox.ur)
                print(dbbox.l + dbbox.l + pBold(text) + dbbox.l )
                print(dbbox.l + dbbox.lc + (dbbox.u*item_len)+ dbbox.dr)
            elif (item['style'] == "B1"):
                text = item['data'] 
                print(dbbox.l + dbbox.l + (text))
            elif (item['style'] == "B0"):
                text = item['data'] 
                print(dbbox.l + (text))
                
            elif (item['style'] == "T1"):
                if ("header" not in item.keys()):
                    item['header'] = " "
                if ("boldfirst" not in item.keys()):
                    item['boldfirst'] = True
                table_data = np.array(item['data'])
                if (true_len(table_data.shape) != 2):
                    print ("ERROR, non 2d square data passed to table print function")
                    return False
                table_column_lengths = []
                for iterate in range(table_data.shape[1]):
                    table_column_lengths.append(0)
                for row in table_data:
                    c_count = 0
                    for column in row:
                        mytype = type(column)
                        if ("str" in str(type(column)) ):
                            if (true_len(str(column)) > table_column_lengths[c_count]):
                                table_column_lengths[c_count] = true_len(str(column))
                        else:
                            if (true_len(str(column)) > table_column_lengths[c_count]):
                                table_column_lengths[c_count] = true_len(str(column))
                        c_count += 1
                if (sum(table_column_lengths) < true_len(item['header'])):
                    extra_column_divider_counts = (true_len(table_column_lengths) - 2)
                    len_sum_of_data = sum(table_column_lengths)
                    header_len = true_len(item['header'])
                    addition = (header_len - len_sum_of_data) - extra_column_divider_counts
                    table_column_lengths[0] += addition - 1
                    
                    header_len = true_len(item['header'])
                    table_width = header_len ##width without edge borders
                else:
                    extra_column_divider_counts = (true_len(table_column_lengths)) - 1
                    len_sum_of_data = sum(table_column_lengths)
                    header_len = len_sum_of_data + extra_column_divider_counts
                    table_width = header_len ##width without edge borders
                if ((item['header'] != " ")):
                    print(dbbox.l + dbbox.ul + (dbbox.u*table_width) + dbbox.ur )
                    added_padding = len(str(item['header'])) - true_len(str(item['header']))
                    justified_header = str(item['header']).ljust(table_width + added_padding)
                    print(dbbox.l + dbbox.l + pBold(justified_header)  + dbbox.l)
                    
                    ###print header trailer
                    print(dbbox.l + dbbox.lc, end = "")
                    for iterate in range(table_data.shape[1]):
                        print((dbbox.u * table_column_lengths[iterate]), end = '')
                        c_count += 1
                        if (iterate == table_data.shape[1] - 1):
                            print(dbbox.rc)
                        else:
                            print(dbbox.uc, end="")
                else:
                    print(dbbox.l + dbbox.ul + (dbbox.u*table_width) + dbbox.ur )
                #print data
                r_count = 0
                for row in table_data:
                    print(dbbox.l + dbbox.l, end = "")
                    c_count = 0
                    is_first = True
                    for column in row:
                        added_padding = len(str(column)) - true_len(str(column))
                        if is_first:
                            print( pBold(
                                str(column).ljust(table_column_lengths[c_count] + added_padding)), end = '')
                            
                            is_first = False
                        else:
                            print(  
                                str(column).rjust(table_column_lengths[c_count] + added_padding), end = '')
                        c_count += 1
                        if (true_len(row) == c_count): #is this last?
                            if (r_count == table_data.shape[1]):
                                print(dbbox.rc)
                            else:
                                print(dbbox.l)
                        else:
                            print(dbbox.l, end="")
                #print trailer
                print(dbbox.l + dbbox.dl, end = "")
                for iterate in range(table_data.shape[1]):
                    print((dbbox.u * table_column_lengths[iterate]),end = '')
                    if (iterate == table_data.shape[1] - 1):
                        print(dbbox.dr)
                    else:
                        print(dbbox.dc, end='')
                    c_count += 1
                    ###########END of TABLE PRINTER #######
            last_style = item['style']
            if (last_item):
                print(dbbox.dl + (dbbox.u*item_len))
    if (print_mode == "html"):
        for item in input_array:
            if (item['style'] == "P1"):
                text = item['data'] 
                html_buffer += '<br><h1>' + text + '</h1>'
            elif (item['style'] == "H1"):
                text = item['data'] 
                html_buffer += '<h1>' + text + '</h1>'
            elif (item['style'] == "H2"):
                text = item['data'] 
                html_buffer += '<h2>' + text + '</h2>'
            elif (item['style'] == "B1"):
                text = item['data'] 
                html_buffer += '<body>' + text + '</body>'
            elif (item['style'] == "B0"):
                text = item['data'] 
                html_buffer += '<h3>' + text + '</h3>'
            elif (item['style'] == "T1"):
                if(type(item['data']) == list): ###TBLEHEADER HERE
                    for rows in item[data]:
                        if(type(item['data']) == list):
                            for cell in rows:
                                text = cell
                                html_buffer += "asdad"
                else:
                    html_buffer += '<body>' + str(item['data']) + '</body>'
                print(text)
    if (print_mode == "slack"):
        slack_bullet = "• "
        slack_linebreak = "\\r\\n"
        dbbox = blank_border_char_class
        slack_buffer = '[ {"type": "divider"}'
        item_counter = 0 
        for item in input_array:
            item_counter += 1
            if (item['style'] == "P1"):
                text = item['data'] 
                slack_buffer += ',{	"type": "section","text": {"type": "mrkdwn","text": ":heavy_minus_sign:*' + text + '*:heavy_minus_sign:"}} \r\n'
            elif (item['style'] == "H1"):
                text = item['data'] 
                slack_buffer += ',{	"type": "section","text": {"type": "mrkdwn","text": "*' + text + '*"}} \r\n'
            elif (item['style'] == "H2"):
                text = item['data'] 
                slack_buffer += ',{	"type": "section","text": {"type": "mrkdwn","text": "' + text + '"}} \r\n'
            elif (item['style'] == "B1"):
                text = item['data'] 
                slack_buffer += ',{	"type": "section","text": {"type": "mrkdwn","text": "' + text + '"}} \r\n'
            elif (item['style'] == "B0"):
                text = item['data'] 
                slack_buffer += ',{	"type": "section","text": {"type": "mrkdwn","text": "_' + text + '_"}} \r\n'
            elif (item['style'] == "T1"): ###SLACK TABLE PRINTER
                if ("header" not in item.keys()):
                    item['header'] = " "
                if ("boldfirst" not in item.keys()):
                    item['boldfirst'] = True
                table_data = np.array(item['data'])
                if (true_len(table_data.shape) != 2):
                    print ("ERROR, non 2d square data passed to table print function")
                    return False
                table_column_lengths = []
                for iterate in range(table_data.shape[1]):
                    table_column_lengths.append(0)
                for row in table_data:
                    c_count = 0
                    for column in row:
                        mytype = type(column)
                        if ("str" in str(type(column)) ):
                            if (true_len(str(column)) > table_column_lengths[c_count]):
                                table_column_lengths[c_count] = true_len(str(column))
                        else:
                            if (true_len(str(column)) > table_column_lengths[c_count]):
                                table_column_lengths[c_count] = true_len(str(column))
                        c_count += 1
                #print("HEADER LEN:",true_len(item['header']))
                #print("COL1",table_column_lengths[0],"     COL2",table_column_lengths[1])

                if (sum(table_column_lengths) < true_len(item['header'])):
                    extra_column_divider_counts = 0
                    len_sum_of_data = sum(table_column_lengths)
                    header_len = true_len(item['header'])
                    addition = (header_len - len_sum_of_data) - extra_column_divider_counts
                    table_column_lengths[0] += addition - 12
                    
                    header_len = true_len(item['header'])
                    table_width = header_len ##width without edge borders
                else:
                    extra_column_divider_counts = 0
                    len_sum_of_data = sum(table_column_lengths)
                    header_len = len_sum_of_data + extra_column_divider_counts
                    table_width = header_len ##width without edge borders
                if ((item['header'] != " ")):
                    added_padding = 0
                    justified_header = str(item['header']).ljust(table_width + added_padding)
                    slack_buffer += ',{	"type": "section","text": {"type": "mrkdwn","text": "```'
                    
                    slack_buffer += justified_header + slack_linebreak
                else:
                    slack_buffer += ',{	"type": "section","text": {"type": "mrkdwn","text": "```'
                #print data
                r_count = 0
                for row in table_data:
                    c_count = 0
                    is_first = True
                    for column in row:
                        #added_padding = len(str(column)) + 2 - true_len(str(column))
                        added_padding = 0
                        #slack_buffer += "\\t" + ( str(column).ljust(table_column_lengths[c_count] + added_padding)) + "\\t"
                        slack_buffer += " " + ( str(column).ljust(table_column_lengths[c_count] + added_padding)) + " "
                        c_count += 1
                        if (true_len(row) == c_count): #is this last?
                            slack_buffer += slack_linebreak
                slack_buffer += '```"}} \r\n'
        slack_buffer += "]"            ##close slack block message      
        #print(slack_buffer)
        constructed_raw_message = {
                "channel": passed_raw_api.channel_id,
                "as_user": passed_raw_api.self_id,
                "blocks": slack_buffer
            }
        
        passed_raw_api.Slacker.chat.post('chat.postMessage', data=constructed_raw_message)
        

def getpanstatus(webcontent, str_service):
    services_list = webcontent.xpath('//*[@data-component-id="' + str_service + '"]/span')
    if (len(services_list) == 4):
        service_status = (services_list[2].text).lstrip().rstrip()
    else:
        service_status = (services_list[1].text).lstrip().rstrip()
    return service_status

 
 #### Print the tenant information from authentication


def tenant_information(sdk, idname, global_vars):
    print_array = []
    print_array.append({ style: P1, data: "TENANT Information"})
    resp = sdk.get.tenants()
    if resp.cgx_status:
        tenant_name = resp.cgx_content.get("name", None)
        print_array.append({ style: B0, data: pBold("Tenant Name") + ": " + pUnderline(tenant_name)  })
    else:
        logout()
        print_array.append({ style: B0, data: pFail("ERROR") + ": " + pUnderline("API Call failure when enumerating TENANT Name! Exiting!")  })
        print(resp.cgx_status)
        return(False)    
    uprint(print_array)

#### Get Element Information and Health
def health_tenant_disconnected_elements(sdk, idname, global_vars):
    print_array = []
    site_elements = []
    site_id_to_name = global_vars['site_id_to_name']
    show_success = global_vars['show_success']

    print_array.append({ style: P1, data: "ELEMENT Information"})
    resp = sdk.get.elements()
    if resp.cgx_status:
        print_array.append({ style: H1, data: "ION Status for site"})
        element_list = resp.cgx_content.get("items", None)    #EVENT_LIST contains an list of all returned events
        if (len(element_list) >= 0):
            for element in element_list:                            #Loop through each EVENT in the EVENT_LIST
                if (element['site_id'] == '1'):
                    site_id = "Unassigned"
                else:
                    site_id = str(site_id_to_name[element['site_id']])
                if (element['connected'] == True):
                    ion_status = pPass("CONNECTED")
                    if show_success:
                        site_elements.append([ pUnderline(str(element['name'])),  ion_status, element['id'], site_id ])
                else:
                    ion_status = pFail("OFFLINE")
                    site_elements.append([ pUnderline(str(element['name'])),  ion_status, element['id'], site_id ])
        if (len(site_elements) == 0):
            print_array.append({ style: B1, data: "No DOWNED IONS for site found"})
        else:
            site_elements.insert(0,['Name', 'Status', "ID", "Site"])
            print_array.append({ style: T1, theader: "Tenant IONS" , data:  site_elements  })
        uprint(print_array)


#### Get SITE Information and Health
def health_tenant_disconnected_sites(sdk, idname, global_vars):
    print_array = []
    site_table_array = []
    site_id_to_name = global_vars['site_id_to_name']
    show_success = global_vars['show_success']

    print_array.append({ style: P1, data: "ELEMENT Information"})
    resp = sdk.get.sites()
    if resp.cgx_status:
        print_array.append({ style: H1, data: "Sites Status"})
        site_list = resp.cgx_content.get("items", None)    #EVENT_LIST contains an list of all returned events
        if (len(site_list) >= 0):
            for site in site_list:                            #Loop through each EVENT in the EVENT_LIST
                if (site['admin_state'] == 'active'):
                    site_status = pPass("ONLINE")
                    if show_success:
                        site_table_array.append([ pUnderline(site['name']),  site_status, site['id'] ])
                else:
                    site_status = pFail("OFFLINE")
                    site_table_array.append([ pUnderline(site['name']),  site_status, site['id'] ])
        if (len(site_table_array) == 0):
            print_array.append({ style: B1, data: "No DOWNED Sites Found"})
        else:
            site_table_array.insert(0,['Name', 'Status', "ID"])
            print_array.append({ style: T1, theader: "Tenant IONS" , data:  site_table_array  })
        uprint(print_array)


def health_tenant_alarm_information(sdk, idname, global_vars):
    print_array = []

    print_array.append({ style: P1, data: "ALARMS Information"})
    diff_hours = global_vars['diff_hours']
    show_success = global_vars['show_success']

    dt_now       = str(datetime.now().isoformat())
    dt_start     = str((datetime.today() - timedelta(hours=diff_hours)).isoformat())
    dt_yesterday = str((datetime.today() - timedelta(hours=48)).isoformat())

    global_vars['dt_now']       = dt_now
    global_vars['dt_start']     = dt_start
    global_vars['dt_yesterday'] = dt_yesterday
    site_id_to_name = global_vars['site_id_to_name']

    #### Now print alarm summaries
    alarm_summary_dict = {}
    event_filter = '{"limit":{"count":1000,"sort_on":"time","sort_order":"descending"},"view":{"summary":false},"severity":[],"query":{"site":[],"category":[],"code":[],"correlation_id":[],"type":["alarm"]}, "start_time": "' + dt_start + '", "end_time": "'+ dt_now + '"}'
    resp = sdk.post.events_query(event_filter)
    if resp.cgx_status:
        print_array.append({ style: H1, data: "ALARM Summaries for the past "+ str(diff_hours) + " hours"})
        alarms_list = resp.cgx_content.get("items", None)
        if(len(alarms_list) > 0 ):
            for alarm in alarms_list:
               if(alarm['code'] in alarm_summary_dict.keys() ):
                    alarm_summary_dict[alarm['code']]['count'] += 1
                    if (site_id_to_name[alarm['site_id']] in alarm_summary_dict[alarm['code']].keys()):
                        alarm_summary_dict[alarm['code']][site_id_to_name[alarm['site_id']]] += 1
                    else:
                        alarm_summary_dict[alarm['code']][site_id_to_name[alarm['site_id']]] = 1
               else:
                   alarm_summary_dict[alarm['code']] = {}
                   alarm_summary_dict[alarm['code']]['count'] = 1
                   alarm_summary_dict[alarm['code']][site_id_to_name[alarm['site_id']]] = 1
            alarm_site_list = []
            for alarm_code in alarm_summary_dict.keys():
                alarm_site_list.clear()
                alarm_site_list.append([ "Total Count For All Sites", alarm_summary_dict[alarm_code]['count'] ])
                for alarm_sites in alarm_summary_dict[alarm_code].keys():
                    if alarm_sites != "count":
                        alarm_site_list.append([" " + str(alarm_sites), str(alarm_summary_dict[alarm_code][alarm_sites]) ])
                print_array.append({ style: T1, theader: "Global alarms summaries for ALARM: " + str(alarm_code) + " ", data: alarm_site_list })
        else:
            print_array.append({ style: B1, data: "No ALARM summaries found" })
    else:
        print_array.append({ style: B1, data: pFail("ERROR in SCRIPT. Could not get ALARM SUMMARIES") })
    uprint(print_array)

def health_tenant_alert_information(sdk, idname, global_vars):
    print_array = []

    print_array.append({ style: P1, data: "ALERTS Information"})
    diff_hours = global_vars['diff_hours']

    dt_now       = str(datetime.now().isoformat())
    dt_start     = str((datetime.today() - timedelta(hours=diff_hours)).isoformat())
    dt_yesterday = str((datetime.today() - timedelta(hours=48)).isoformat())

    dt_start     = str((datetime.today() - timedelta(hours=72)).isoformat())

    global_vars['dt_now']       = dt_now
    global_vars['dt_start']     = dt_start
    global_vars['dt_yesterday'] = dt_yesterday
    site_id_to_name = global_vars['site_id_to_name']

    #### Now print alert summaries
    alert_summary_dict = {}
    event_filter = '{"limit":{"count":1000,"sort_on":"time","sort_order":"descending"},"view":{"summary":false},"severity":[],"query":{"site":[],"category":[],"code":[],"correlation_id":[],"type":["alert"]}, "start_time": "' + dt_start + '", "end_time": "'+ dt_now + '"}'
    resp = sdk.post.events_query(event_filter)
    if resp.cgx_status:
        print_array.append({ style: H1, data: "ALERT Summaries for the past "+ str(diff_hours) + " hours"})
        alert_list = resp.cgx_content.get("items", None)
        if(len(alert_list) > 0 ):
            for alert in alert_list:
               if(alert['code'] in alert_summary_dict.keys() ):
                    alert_summary_dict[alert['code']]['count'] += 1
                    if (site_id_to_name[alert['site_id']] in alert_summary_dict[alert['code']].keys()):
                        alert_summary_dict[alert['code']][site_id_to_name[alert['site_id']]] += 1
                    else:
                        alert_summary_dict[alert['code']][site_id_to_name[alert['site_id']]] = 1
               else:
                   alert_summary_dict[alert['code']] = {}
                   alert_summary_dict[alert['code']]['count'] = 1
                   alert_summary_dict[alert['code']][site_id_to_name[alert['site_id']]] = 1
            alert_site_list = []
            for alert_code in alert_summary_dict.keys():
                alert_site_list.clear()
                alert_site_list.append([ "Total Count For All Sites", alert_summary_dict[alert_code]['count'] ])
                for alert_sites in alert_summary_dict[alert_code].keys():
                    if alert_sites != "count":
                        alert_site_list.append([" " + str(alert_sites), str(alert_summary_dict[alert_code][alert_sites]) ])
                print_array.append({ style: T1, theader: "Global alert summaries for ALERT: " + str(alert_code) + " ", data: alert_site_list })
        else:
            print_array.append({ style: B1, data: "No ALERT summaries found" })
    else:
        print_array.append({ style: B1, data: pFail("ERROR in SCRIPT. Could not get ALERT SUMMARIES") })
    uprint(print_array)


#### Get VPN Link Health Information
def health_downed_VPN_information(sdk, idname, global_vars):
    
    #### Create ID to NAME maps efficiently
    elements_id_to_name = idname.generate_elements_map()
    site_id_to_name = idname.generate_sites_map()
    wan_label_id_to_name = idname.generate_waninterfacelabels_map()
    wan_if_id_to_name = idname.generate_waninterfaces_map()
    
    #### Store these ID MAPS for later use in other functions
    global_vars['elements_id_to_name'] = elements_id_to_name
    global_vars['site_id_to_name'] = site_id_to_name
    global_vars['wan_label_id_to_name'] = wan_label_id_to_name
    global_vars['wan_if_id_to_name'] = wan_if_id_to_name
    
    show_success = global_vars['show_success']
    
    #########   VPN LINK INFORMATION  #########
    print_array = []
    
    ####topology_filter = '{"type":"basenet","nodes":["' +  site_id + '"]}'
    topology_filter = '{"type":"anynet","links_only": "False"}'
    ###topology_filter = '{"stub_links": "True", "type": "anynet", "links_only": False}'
    resp = sdk.post.topology(topology_filter)
    if resp.cgx_status:
        unsorted_topology_list = resp.cgx_content.get("links", None)
        vpn_count = 0 
        vpn_state_array = []
        
        
        ### Minimize the amount of sites as the primary key using the ryder-reduce algorithm
        priority_dict = {}
        for links in unsorted_topology_list:
            if links['target_site_name'] in priority_dict.keys():
                priority_dict[links['target_site_name']] += 1
            else:
                priority_dict[links['target_site_name']] = 1 
            if links['source_site_name'] in priority_dict.keys():
                priority_dict[links['source_site_name']] += 1
            else:
                priority_dict[links['source_site_name']] = 1              
        for index,links in enumerate(unsorted_topology_list):   
            if priority_dict[links['source_site_name']] < priority_dict[links['target_site_name']]:
                unsorted_topology_list[index]['target_site_name'], unsorted_topology_list[index]['source_site_name'] = unsorted_topology_list[index]['source_site_name'], unsorted_topology_list[index]['target_site_name']
                unsorted_topology_list[index]['target_wan_if_id'], unsorted_topology_list[index]['source_wan_if_id'] = unsorted_topology_list[index]['source_wan_if_id'], unsorted_topology_list[index]['target_wan_if_id']
                unsorted_topology_list[index]['target_wan_network'], unsorted_topology_list[index]['source_wan_network'] = unsorted_topology_list[index]['source_wan_network'], unsorted_topology_list[index]['target_wan_network']
                unsorted_topology_list[index]['target_node_id'], unsorted_topology_list[index]['source_node_id'] = unsorted_topology_list[index]['source_node_id'], unsorted_topology_list[index]['target_node_id']
                unsorted_topology_list[index]['target_wan_nw_id'], unsorted_topology_list[index]['source_wan_nw_id'] = unsorted_topology_list[index]['source_wan_nw_id'], unsorted_topology_list[index]['target_wan_nw_id']
        topology_list = sorted(unsorted_topology_list, key = lambda i: i['source_site_name']) 
        
        problem_list = {}

        for links in topology_list:
            if (links['status'] != "up"):
                vpn_count += 1
                if(('admin_up' in links.keys()) and (links['admin_up'])):
                    vpn_admin_state = pWarn("ACTIVE")
                else:
                    vpn_admin_state = pFail("ADMIN DOWN") 
                if ( links['source_site_name'] not in problem_list.keys() ):
                    problem_list[links['source_site_name']] = []
                problem_list[links['source_site_name']].append( [         str(links['source_wan_network']),
                                               str(links['target_site_name']), str(links['target_wan_network']),  
                                            str(pFail("DOWN")),  str(vpn_admin_state) ])
            elif show_success:
                vpn_count += 1
                if(('admin_up' in links.keys()) and (links['admin_up'])):
                    vpn_admin_state = pPass("ACTIVE")
                else:
                    vpn_admin_state = pWarn("ADMIN DOWN")
                if (links['source_site_name'] not in problem_list.keys()):
                    problem_list[links['source_site_name']] = []
                problem_list[links['source_site_name']].append( [         str(links['source_wan_network']),
                                               str(links['target_site_name']), str(links['target_wan_network']),  
                                            str(pPass("UP")),  str(vpn_admin_state) ])
        if (vpn_count == 0):
            print_array.append({ style: P1, data: "ANYNET TUNNEL Status for sites"})
            print_array.append({ style: B1, data: "No DOWN VPN links detected" })
            uprint(print_array)
        else:
            for tables in problem_list:
                print_array.clear()
                vpn_state_array.clear()
                print_array.append({ style: P1, data: "ANYNET TUNNEL Status for site " + tables })
                vpn_state_array.insert(0,[pUnderline("Source WAN"), 
                                 pUnderline("Target SITE"), pUnderline("Target WAN"), pUnderline("Status"), pUnderline("Admin State") ] )
                for row in problem_list[tables]:
                    vpn_state_array.append(row)
                print_array.append({ style: T1, data: vpn_state_array })
                uprint(print_array)



def health_VPN_l3_metrics(sdk, idname, global_vars):    
    #### Get ID MAPS for use in this function
    elements_id_to_name     = global_vars['elements_id_to_name']
    site_id_to_name         = global_vars['site_id_to_name']
    wan_label_id_to_name    = global_vars['wan_label_id_to_name']
    wan_if_id_to_name       = global_vars['wan_if_id_to_name']
    
    threshold_jitter    = global_vars['threshold_jitter']
    threshold_loss      = global_vars['threshold_loss']
    threshold_latency   = global_vars['threshold_latency']

    show_success = global_vars['show_success']
    
    diff_hours = 24 
    dt_now       = str(datetime.now().isoformat())
    dt_start     = str((datetime.today() - timedelta(hours=diff_hours)).isoformat())

    site_name_to_id         = dict([[v,k] for k,v in site_id_to_name.items()])
    global_vars['site_name_to_id'] = site_name_to_id

    #########   VPN LINK INFORMATION  #########
    print_array = []
    
    topology_filter = '{"type":"anynet","links_only": "False"}'

    resp = sdk.post.topology(topology_filter)
    if resp.cgx_status:
        unsorted_topology_list = resp.cgx_content.get("links", None)
        vpn_count = 0 

        ### Minimize the amount of sites as the primary key using the ryder-reduce algorithm
        priority_dict = {}
        for links in unsorted_topology_list:
            if links['target_site_name'] in priority_dict.keys():
                priority_dict[links['target_site_name']] += 1
            else:
                priority_dict[links['target_site_name']] = 1 
            if links['source_site_name'] in priority_dict.keys():
                priority_dict[links['source_site_name']] += 1
            else:
                priority_dict[links['source_site_name']] = 1              
        for index,links in enumerate(unsorted_topology_list):   
            if priority_dict[links['source_site_name']] < priority_dict[links['target_site_name']]:
                unsorted_topology_list[index]['target_site_name'], unsorted_topology_list[index]['source_site_name'] = unsorted_topology_list[index]['source_site_name'], unsorted_topology_list[index]['target_site_name']
                unsorted_topology_list[index]['target_wan_if_id'], unsorted_topology_list[index]['source_wan_if_id'] = unsorted_topology_list[index]['source_wan_if_id'], unsorted_topology_list[index]['target_wan_if_id']
                unsorted_topology_list[index]['target_wan_network'], unsorted_topology_list[index]['source_wan_network'] = unsorted_topology_list[index]['source_wan_network'], unsorted_topology_list[index]['target_wan_network']
                unsorted_topology_list[index]['target_node_id'], unsorted_topology_list[index]['source_node_id'] = unsorted_topology_list[index]['source_node_id'], unsorted_topology_list[index]['target_node_id']
                unsorted_topology_list[index]['target_wan_nw_id'], unsorted_topology_list[index]['source_wan_nw_id'] = unsorted_topology_list[index]['source_wan_nw_id'], unsorted_topology_list[index]['target_wan_nw_id']
        topology_list = sorted(unsorted_topology_list, key = lambda i: i['source_site_name']) 

        ###Build VPN Dict for ease of access for overlay tunnels
        vpn_dict = {}
        metrics_array = []

        last_site = " "
        for links in topology_list:
            if ("vpnlinks" in links.keys() ):
                if (last_site != links['source_site_name']):
                    site_id  = site_name_to_id[links['source_site_name']]
                    topology_filter = '{"type":"basenet","nodes":["' +  site_id + '"]}'
                    site_vpn_response = sdk.post.topology(topology_filter)
                    site_vpn_topology = site_vpn_response.cgx_content.get("links", None)
                    for site_links in site_vpn_topology:
                        if ("type" in site_links.keys() and site_links['type'] == "vpn"):
                            vpn_dict[site_links["path_id"]] = site_links



                for vpn in links['vpnlinks']:
                    in_use = vpn_dict[vpn].get('in_use', False) 
                    if (in_use):
                        isbad = False
                        site_id  = site_name_to_id[links['source_site_name']]

                        metrics_array.clear()
                        ####get jitter
                        try:
                           #lqm_request = '{"start_time":"' + dt_start + 'Z","end_time":"' + dt_now + 'Z","interval":"5min","metrics":[{"name":"LqmJitter","statistics":["average"],"unit":"milliseconds"}],"view":{},"filter":{"site":["' + site_id + '"],"path":["' + vpn + '"],"direction":"Ingress"}}'
                            lqm_request = '{"start_time":"' + dt_start + 'Z","end_time":"' + dt_now + 'Z","interval":"5min","metrics":[{"name":"LqmJitter","statistics":["average"],"unit":"milliseconds"}],"view":{"individual":"site"},"filter":{"site":["' + site_id + '"],"element":[],"path":["' + vpn + '"],"direction":"Ingress"}}'
                            lqm_resp = sdk.post.metrics_monitor(lqm_request)
                            series = lqm_resp.cgx_content.get("metrics")
                            for datapoint in series[0]['series'][0]['data'][0]['datapoints']:
                                if (datapoint['value'] != None):
                                    metrics_array.append(datapoint['value'])
                            
                            jitter_samples = (len(metrics_array))
                            #metrics_resp = sdk.get.metrics(vpn_jitter)
                            #nparray = metrics_resp.cgx_content.get("items")
                            if (jitter_samples > 0):
                                jitter_result_min = round( np.amin(metrics_array)            ,3)
                                jitter_result_avg = round( np.average(metrics_array)         ,3)
                                jitter_result_prc = round( np.percentile(metrics_array,90)   ,3)
                                jitter_result_max = round( np.amax(metrics_array)            ,3)
                                if ((jitter_result_avg > threshold_jitter) or (jitter_result_prc > threshold_jitter) or (jitter_result_min > threshold_jitter) ):
                                    isbad = True
                            else:
                                jitter_result_min = "N/A"
                                jitter_result_avg = "N/A"
                                jitter_result_prc = "N/A"
                                jitter_result_max = "N/A"
                                isbad = True
                        except:
                            jitter_result_min = "N/A"
                            jitter_result_avg = "N/A"
                            jitter_result_prc = "N/A"
                            jitter_result_max = "N/A"
                            isbad = True                 

                        metrics_array.clear()
                        ###get loss
                        try:
                            lqm_request = '{"start_time":"' + dt_start + 'Z","end_time":"' + dt_now + 'Z","interval":"5min","metrics":[{"name":"LqmPacketLoss","statistics":["average"],"unit":"Percentage"}],"view":{},"filter":{"site":["' + site_id + '"],"path":["' + vpn + '"],"direction":"Ingress"}}'
                            lqm_resp = sdk.post.metrics_monitor(lqm_request)
                            series = lqm_resp.cgx_content.get("metrics")
                            for datapoint in series[0]['series'][0]['data'][0]['datapoints']:
                                if (datapoint['value'] != None):
                                    metrics_array.append(datapoint['value'])
                            
                            loss_samples = (len(metrics_array))
                            if (loss_samples > 0):
                                loss_result_min = round( np.amin(metrics_array)            ,3)
                                loss_result_avg = round( np.average(metrics_array)         ,3)
                                loss_result_prc = round( np.percentile(metrics_array,90)   ,3)
                                loss_result_max = round( np.amax(metrics_array)            ,3)
                                if ((loss_result_avg > threshold_jitter) or (loss_result_prc > threshold_jitter) or (loss_result_min > threshold_jitter) ):
                                    isbad = True    
                            else:
                                loss_result_min = "N/A"
                                loss_result_avg = "N/A"
                                loss_result_prc = "N/A"
                                loss_result_max = "N/A"
                        except:
                            loss_result_min = "N/A"
                            loss_result_avg = "N/A"
                            loss_result_prc = "N/A"
                            loss_result_max = "N/A"
                            isbad = True

                        metrics_array.clear()
                        ###get latency
                        try:
                            lqm_request = '{"start_time":"' + dt_start + 'Z","end_time":"' + dt_now + 'Z","interval":"5min","metrics":[{"name":"LqmLatency","statistics":["average"],"unit":"milliseconds"}],"view":{},"filter":{"site":["' + site_id + '"],"path":["' + vpn + '"]}}'
                            lqm_resp = sdk.post.metrics_monitor(lqm_request)
                            series = lqm_resp.cgx_content.get("metrics")
                            for datapoint in series[0]['series'][0]['data'][0]['datapoints']:
                                if (datapoint['value'] != None):
                                    metrics_array.append(datapoint['value'])
                            latency_samples = len(metrics_array)

                            if (latency_samples > 0):
                                latency_result_min = round( np.amin(metrics_array)            ,3)
                                latency_result_avg = round( np.average(metrics_array)         ,3)
                                latency_result_prc = round( np.percentile(metrics_array,90)   ,3)
                                latency_result_max = round( np.amax(metrics_array)            ,3)
                                if ((latency_result_avg > threshold_jitter) or (latency_result_prc > threshold_jitter) or (latency_result_min > threshold_jitter) ):
                                    isbad = True    
                            else:
                                latency_result_min = "N/A"
                                latency_result_avg = "N/A"
                                latency_result_prc = "N/A"
                                latency_result_max = "N/A"
                        except:
                            latency_result_min = "N/A"
                            latency_result_avg = "N/A"
                            latency_result_prc = "N/A"
                            latency_result_max = "N/A"
                            isbad = True
                        
                        have_data = True
                        if (jitter_result_min == "N/A" and latency_result_min == "N/A" and loss_result_min == "N/A"):
                            have_data = False
                        
                        ###Print out result
                        if (isbad or show_success) and (have_data):
                            print_array.clear()
                            print_array.append({ style: P1, data: "Layer-3 Metrics Stats for site " + str(links['source_site_name']) + " (" + vpn + ")" })
                            table_header = "LINK: via "  + str(links['source_wan_network']) + " -> " + str(links['target_site_name']) + " VIA " + str(links['target_wan_network'])

                            print_array.append({ style: T1, theader: table_header, data: [
                                [ "______", "MIN", "AVG", "90th", "MAX" ],
                                [ " JITTER",     jitter_result_min,  jitter_result_avg,  jitter_result_prc,  jitter_result_max   ],
                                [ "LATENCY",    latency_result_min, latency_result_avg, latency_result_prc, latency_result_max  ],
                                [ "   LOSS",       loss_result_min,    loss_result_avg,    loss_result_prc,    loss_result_max     ],
                            ] })
                            uprint(print_array)
                            vpn_count += 1
        if (vpn_count == 0):
            print_array.append({ style: P1, data: "Layer-3 Metrics Stats for site "})
            print_array.append({ style: B1, data: "No Problem Link Stats found" })
            uprint(print_array)
         
    


def dashboard_health_check(raw_api, sdk, idname):

    global global_vars
    global passed_raw_api
    passed_raw_api = raw_api
    print_array = []
    
    constructed_raw_message = {
                "channel": passed_raw_api.channel_id,
                "as_user": passed_raw_api.self_id,
                "blocks": global_vars['slack_buffer']
            }
    passed_raw_api.Slacker.chat.post('chat.postMessage', data=constructed_raw_message)

    idname =  cloudgenix_idname.CloudGenixIDName(sdk)
    site_id_to_name = idname.generate_sites_map()
    global_vars['site_id_to_name'] = site_id_to_name
    global_vars['show_success'] = True

    ##GlobalVars is a DICT used to pass information back and forth between functions
    global_vars['diff_hours']   = 24          #Hours to look back at
    print_mode                  = global_vars['print_mode']
    slack_buffer                = global_vars['slack_buffer']
    

    global_vars['threshold_jitter'] = 5     #As an int in Milliseconds
    global_vars['threshold_loss'] = .10     #As a decimal percent
    global_vars['threshold_latency'] = 150  #As an int in Milliseconds

    ##Health Check Functions
    tenant_information(sdk, idname, global_vars)
    health_tenant_disconnected_elements(sdk, idname, global_vars)
    health_tenant_disconnected_sites(sdk, idname, global_vars)
    health_tenant_alarm_information(sdk, idname, global_vars)
    health_tenant_alert_information(sdk, idname, global_vars)
    health_downed_VPN_information(sdk, idname, global_vars)
    health_VPN_l3_metrics(sdk, idname, global_vars)
    #health_cb_prisma_information(sdk, idname, global_vars)
    #health_cb_zscaler_information(sdk, idname, global_vars)
    #health_mscloud_information(sdk, idname, global_vars)
    #health_gcloud_information(sdk, idname, global_vars)
    return("DONE")

def logout():
    print("Logging out")
    sdk.get.logout()


