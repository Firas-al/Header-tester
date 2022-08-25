import datetime
import socket
import ssl
import urllib.request
import dns
import requests
import xlsxwriter
from ocspchecker import ocspchecker


"""
https://stackoverflow.com/questions/24533018/get-a-header-with-python-and-convert-in-json-requests-urllib2-json
https://stackoverflow.com/questions/55588079/csp-self-is-failing-in-various-directives
ocspchecker
"""


# Open and create a new Execl file to write the results
workbook = xlsxwriter.Workbook("results.xlsx") # name of file
worksheet = workbook.add_worksheet("Banks") # name of worksheet
# name of  fields
worksheet.write('A1', "Website")
worksheet.write('B1', "X-Frame-Options")
worksheet.write('C1', "X-Content-Type-Options")
worksheet.write('D1', "HSTS")
worksheet.write('E1', "CSP")
worksheet.write('F1', "HTTPS")
worksheet.write('G1', "DNSsec")
worksheet.write('H1', "Referrer-Policy Headers")
worksheet.write('I1', "Revoked")
worksheet.write('J1', "X.509")

# the field that will use to write in
rowIndex = 2

"""
Empty strings use to save the value then write to Execl 
"""
WebsiteTowrite = ""
X_Frame_OptionsTowrite = ""
X_Content_Type_OptionsTowrite = ""
HSTSTowrite = ""
CSPTowrite = ""
HTTPSTowrite = ""
DNSsecTowrite = ""

Referrer_Policy_HeadersTowrite = ""
RevokedTowrite = ""
X508Towrite = ""


"""
Empty int counters
"""

X_Frame_Options_OK = 0
X_Content_Type_Options_OK = 0
HSTS_OK = 0
CSP_OK = 0
HTTPS_OK = 0
DNSsec_OK = 0

Referrer_Policy_Headers_OK = 0
Revoked_OK = 0
X508_OK = 0

X_Frame_Options_NOT_OK = 0
X_Content_Type_Options_NOT_OK = 0
HSTS_NOT_OK = 0
CSP_NOT_OK = 0
DNSsec_NOT_OK = 0

Referrer_Policy_Headers_NOT_OK = 0
Revoked_NOT_Revoked = 0
X508_NOT_OK = 0

X_Frame_Options_ERORR = 0
X_Content_Type_Options_ERORR = 0
HSTS_ERORR = 0
CSP_ERORR = 0
HTTPS_ERORR = 0
Referrer_Policy_Headers_ERORR = 0
Revoked_ERORR = 0
X508_ERORR = 0



# open file
with open('test.txt', 'r', encoding="utf-8") as apple:
    # read line by line.
    for apps in apple.readlines():
        website = apps.strip()
        http = "http://" + website # add http://
        https = "https://" + website# add https://
        print(website) #print the website
        WebsiteTowrite = website # write to the Execl file
        try:
            # get the header for the website
            r = requests.get(http)
            print(dict(r.headers))
        except:
            # print error if you did not get the header
            print("error")

        print()

        """
         X-frame-options test
        """
        #https://www.geeksforgeeks.org/http-headers-x-frame-options/
        #https://stackoverflow.com/questions/28397945/header-data-render-to-response-to-include-x-frame-options-allowall
        print("=============================")
        print("x-frame-options")
        try:
            # Get from header the field with x-frame-options
            x_frame_options = dict(r.headers).get("x-frame-options")
            if (x_frame_options == None):
                x_frame_options = dict(r.headers).get("X-Frame-Options")
            else:
                x_frame_options = dict(r.headers).get("x-frame-options")
            if ( #check the value
                    x_frame_options == "deny" or x_frame_options == "SAMEORIGIN" or x_frame_options == "sameorigin" or x_frame_options == "SameOrigin"):
                print("x-frame-options Okay")
                X_Frame_OptionsTowrite = "Okay"
                X_Frame_Options_OK += 1
            else:
                print("x-frame-options NOT Okay")
                X_Frame_OptionsTowrite = "Not Okay"
                X_Frame_Options_NOT_OK += 1
        except:
            print("x-frame-options NOT Okay")
            X_Frame_OptionsTowrite = "Untestable - error"
            X_Frame_Options_ERORR = +1

        print()
        print("=============================")
        print("X-Content-Type-Options")
        try:
            X_Content_Type_Options = dict(r.headers).get("X-Content-Type-Options")

            if (X_Content_Type_Options == None):
                X_Content_Type_Options = dict(r.headers).get("x-content-type-options")
            else:
                X_Content_Type_Options = dict(r.headers).get("X-Content-Type-Options")
                # check the value
            if ("nosniff" in X_Content_Type_Options):
                print("X_Content_Type_Options is Okay <<nosniff>>")
                X_Content_Type_OptionsTowrite = "Okay"
                X_Content_Type_Options_OK += 1

            else:
                print("X_Content_Type_Options NOT Okay")
                X_Content_Type_OptionsTowrite = "Not Okay"
                X_Content_Type_Options_NOT_OK += 1
        except:
            print("X_Content_Type_Options NOT Okay")
            X_Content_Type_OptionsTowrite = "Untestable - error"
            X_Content_Type_Options_ERORR += 1

        # nosniff is okay
        print()
        print("=============================")
        print("HSTS")

        value = ""
        try:
            theV = str(dict(r.headers))
            print(theV)
            # check the value
            value = dict(r.headers).get("strict-transport-security")
            if value is None:
                value = dict(r.headers).get("Strict-Transport-Security")
            if value is None:
                value = dict(r.headers).get("strict-transport-security")
            if value is None:
                if "31536000" in theV:
                    value = "31536000"
            print(value)
            if (value != None):
                theAge = ""
                ageToInt = 0
                for x in value:
                    if x.isdigit():
                        theAge = theAge + x
                ageToInt = int(theAge)

                if (ageToInt < 31536000):
                    print("NO HSTS")
                    HSTSTowrite = "No HSTS"
                    HSTS_NOT_OK += 1
                else:
                    print("HSTS Okay")
                    HSTSTowrite = "HSTS Okay"
                    HSTS_OK += 1
            else:
                print("NO HSTS")
                HSTSTowrite = "Untestable - error"
                HSTS_ERORR += 1
        except:
            HSTSTowrite = "Untestable - error"
            HSTS_ERORR += 1
        print()
        print("=============================")
        print("Content-Security-Policy")
        try:
            CSP = dict(r.headers).get("content-security-policy")
            doNothaveCSP = "content-security-policy"
            if (CSP != None): # check the value
                if (
                        doNothaveCSP in CSP or "unsafe-inline" in CSP or "data:" in CSP or "default-src" in CSP or "script-src" in CSP or "object-src" in CSP or "HTTP:" in CSP or "*" in CSP or "127.0.0.1" in CSP):
                    print("upgrade-insecure-requests")
                    CSPTowrite = "CSP Not okay"
                    CSP_NOT_OK += 1
                else:
                    print("CSP OK")
                    CSPTowrite = "Ok"
                    CSP_OK += 1
            else:
                print("CSP Not okay")
                CSPTowrite = "Untestable - error"
                CSP_ERORR += 1
        except:
            CSPTowrite = "Untestable - error"
            CSP_ERORR += 1
        print()
        print("=============================")
        try:
            print("HTTPS")
            print(urllib.request.urlopen(https).getcode())# print the header
            HTTPSTowrite = "Ok"
            HTTPS_OK += 1
        except:
            print("NO HTTPS")
            HTTPSTowrite = "Untestable - error"
            HTTPS_ERORR += 1
        print()
        #https://stackoverflow.com/questions/26137036/programmatically-check-if-domains-are-dnssec-protected
        print("=============================")
        print("DNSsec")
        try:

            x = website
            # get nameservers for target domain
            response = dns.resolver.resolve(x, dns.rdatatype.NS)

            # we'll use the first nameserver in this example
            nsname = response.rrset[0].to_text()  # name
            response = dns.resolver.resolve(nsname, dns.rdatatype.A)
            nsaddr = response.rrset[0].to_text()  # IPv4

            # get DNSKEY for zone

            request = dns.message.make_query(x, dns.rdatatype.DNSKEY, want_dnssec=True)

            # send the query
            response = dns.query.udp(request, nsaddr)
            if response.rcode() != 0:
                print("HANDLE QUERY FAILED SERVER ERROR OR NO DNSKEY RECORD)")
                # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)

            # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
            answer = response.answer
            if len(answer) != 2:
                print("SOMETHING WENT WRONG")
                # SOMETHING WENT WRONG

            # the DNSKEY should be self signed, validate it
            name = dns.name.from_text(x)
        except:
            print("DNSsec NOT okay")
            DNSsecTowrite = "Not Ok"
            DNSsec_NOT_OK += 1
            # BE SUSPICIOUS
        try:
            print((answer[0], answer[1], {name: answer[0]}))
        except:
            print("DNSsec NOT okay")
            DNSsecTowrite = "Not Ok"
            DNSsec_NOT_OK += 1
            # BE SUSPICIOUS
        else:
            print("DNSsec Okay")
            DNSsecTowrite = "Ok"
            DNSsec_OK += 1
            # WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR example.com

        # Referrer-Policy Headers
        print()
        print("=============================")
        print("Referrer-Policy Headers")
        try:
            referrer_policy_headers_To_lower = ""
            Recommended_policy_values = ["no-referrer", "same-origin", "strict-origin",
                                         "strict-origin-when-cross-origin"]
            referrer_policy_headers = dict(r.headers).get("Referrer-Policy")
        except:
            print("error")

        Referrer_Policy_HeadersTowrite = ""
        Referrer_Policy_Headers_OK = 0
        Referrer_Policy_Headers_NOT_OK = 0

        try:
            if referrer_policy_headers == None:
                print("None")
                Referrer_Policy_HeadersTowrite = "None"
                Referrer_Policy_Headers_ERORR += 1
            else:
                referrer_policy_headers_To_lower = referrer_policy_headers.lower()
                result = all(elem in referrer_policy_headers for elem in Recommended_policy_values)
                if result:
                    Referrer_Policy_HeadersTowrite = "Not Okay"
                    Referrer_Policy_Headers_NOT_OK += 1
                    print("Not Okay")
                else:
                    Referrer_Policy_HeadersTowrite = "OK "
                    Referrer_Policy_Headers_OK += 1
                    print("OK")
        except:
            print("None")
            Referrer_Policy_HeadersTowrite = "None"
            Referrer_Policy_Headers_ERORR += 1

        # Check if the certificate is Revoked
        print()
        print("=============================")
        #https://stackoverflow.com/questions/64436317/how-to-check-ocsp-client-certificate-revocation-using-python-requests-library
        print("certificate is Revoked")
        ocsp_request = ocspchecker.get_ocsp_status(website)
        size_OF = len(ocsp_request)
        if "Error" in ocsp_request or "error" in ocsp_request and size_OF == 2:
            RevokedTowrite = "error"
            Revoked_ERORR += 1
            print(ocsp_request[1])
        elif len(ocsp_request) != 2:
            changeType = str((ocsp_request[2]))
            RevokedTowrite = changeType.replace('OCSP Status:', '')
            if "GOOD" in RevokedTowrite:
                Revoked_NOT_Revoked += 1
                print(RevokedTowrite)
            else:
                Revoked_OK += 1
        print("")

        # check the certifcate
        #https://stackoverflow.com/questions/45810069/how-to-fetch-the-ssl-certificate-value-whether-its-expired-or-not
        try:
            ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=website,
            )
            # 3 second timeout because Lambda has runtime limitations
            conn.settimeout(3.0)
            conn.connect((website, 443))
            ssl_info = conn.getpeercert()
            print(ssl_info)
            # parse the string from the certificate into a Python datetime object
            res = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
            X508Towrite = "OK"
            X508_OK += 1
        except ssl.SSLError as error_msg:
            print("error", error_msg)
            X508Towrite = str(error_msg)
            X508_ERORR += 1
        except Exception as error_msg:
            print("error", error_msg)
            X508Towrite = str(error_msg)
            X508_ERORR += 1

        website = ""
        http = ""
        https = ""
        worksheet.write('A' + str(rowIndex), WebsiteTowrite)
        worksheet.write('B' + str(rowIndex), X_Frame_OptionsTowrite)
        worksheet.write('C' + str(rowIndex), X_Content_Type_OptionsTowrite)
        worksheet.write('D' + str(rowIndex), HSTSTowrite)
        worksheet.write('E' + str(rowIndex), CSPTowrite)
        worksheet.write('F' + str(rowIndex), HTTPSTowrite)
        worksheet.write('G' + str(rowIndex), DNSsecTowrite)
        worksheet.write('H' + str(rowIndex), Referrer_Policy_HeadersTowrite)
        worksheet.write('I' + str(rowIndex), RevokedTowrite)
        worksheet.write('J' + str(rowIndex), X508Towrite)

        rowIndex += 1

        WebsiteTowrite = ""
        X_Frame_OptionsTowrite = ""
        X_Content_Type_OptionsTowrite = ""
        HSTSTowrite = ""
        HSTSTowrite = ""
        CSPTowrite = ""
        HTTPSTowrite = ""
        DNSsecTowrite = ""
        value = ""
        Referrer_Policy_HeadersTowrite = ""
        RevokedTowrite = ""
        X508Towrite = ""

    workbook.close()

# print the results in the console
print()
print("X_Frame_Options_OK")
print(X_Frame_Options_OK)
print(X_Frame_Options_NOT_OK)
print(X_Frame_Options_ERORR)
print()

print("===============")
print("X_Content_Type_Options_OK")
print(X_Content_Type_Options_OK)
print(X_Content_Type_Options_NOT_OK)
print(X_Content_Type_Options_ERORR)

print()
print("===============")
print("HSTS")

print(HSTS_OK)
print(HSTS_NOT_OK)
print(HSTS_ERORR)

print()
print("===============")
print("CSP_OK")

print(CSP_OK)
print(CSP_NOT_OK)
print(CSP_ERORR)
print()
print("===============")
print("HTTPS_OK")

print(HTTPS_OK)
print(HTTPS_ERORR)

print()
print("===============")
print("DNSsec_OK")

print(DNSsec_OK)
print(DNSsec_NOT_OK)

print()
print("===============")
print("Referrer_Policy_Headers")

print(Referrer_Policy_Headers_OK)
print(Referrer_Policy_Headers_NOT_OK)
print(Referrer_Policy_Headers_ERORR)

print()
print("===============")
print("certificate is Revoked")

print(Revoked_OK)
print(Revoked_NOT_Revoked)
print(Revoked_ERORR)

print()
print("===============")
print("X.508")

print(X508_OK)
print(X508_ERORR)
