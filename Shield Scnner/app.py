from flask import Flask, render_template, url_for, request
import requests
import socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

app = Flask(__name__)

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings()

# Initialize requests session
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"


def get_forms(url):
    """Extract forms from HTML content."""
    try:
        response = s.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        return []


def form_details(form):
    """Extract details of forms."""
    details_of_form = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })

    details_of_form['action'] = action
    details_of_form['method'] = method
    details_of_form['inputs'] = inputs
    return details_of_form


def vulnerable(response):
    """Check for SQL injection vulnerability."""
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax"
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False


def sql_injection_scan(url):
    """Scan for SQL injection vulnerabilities in forms."""
    forms = get_forms(url)
    results = []

    for form in forms:
        details = form_details(form)

        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            if details["method"] == "post":
                res = s.post(urljoin(url, details["action"]), data=data)
            elif details["method"] == "get":
                res = s.get(urljoin(url, details["action"]), params=data)

            if res.status_code == 200:
                if vulnerable(res):
                    results.append(f"SQL injection attack vulnerability in link: {urljoin(url, details['action'])}")
                else:
                    results.append("No SQL injection attack vulnerability detected")
                    break
            else:
                results.append(f"Failed to fetch: {urljoin(url, details['action'])}")
                break

    return results


def open_port_scan(target):
    """Perform open port scan on target."""
    results = []

    try:
        results.append(f"Scanning open ports on {target}...")
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                results.append(f"Port {port}: Open")
            sock.close()
    except Exception as e:
        results.append(f"Error during port scan: {str(e)}")

    return results


def get_host_details(target):
    """Get host details."""
    results = []

    try:
        results.append(f"Getting host details for {target}...")
        host_ip = socket.gethostbyname(target)
        results.append(f"Host IP: {host_ip}")
        host_name, _, _ = socket.gethostbyaddr(host_ip)
        results.append(f"Host Name: {host_name}")
    except Exception as e:
        results.append(f"Error getting host details: {str(e)}")

    return results


def check_robots_txt(url):
    """Check robots.txt for disallowed paths."""
    results = []

    try:
        response = s.get(urljoin(url, "/robots.txt"))
        if response.status_code == 200:
            results.append("robots.txt exists. Checking for disallowed paths...")
            disallowed_paths = re.findall(r"Disallow: (.*)", response.text)
            if disallowed_paths:
                results.append("Disallowed paths:")
                for path in disallowed_paths:
                    results.append(path)
            else:
                results.append("No disallowed paths found in robots.txt")
        else:
            results.append("robots.txt does not exist.")
    except Exception as e:
        results.append(f"Error checking robots.txt: {str(e)}")

    return results


def get_technology_details(url):
    """Get technology details."""
    results = []

    try:
        response = s.get(url)
        if response.status_code == 200:
            server_header = response.headers.get('Server')
            if server_header:
                results.append(f"Server: {server_header}")
            else:
                results.append("Server header not found.")
            # Add more technology detection methods here
        else:
            results.append("Failed to fetch technology details.")
    except Exception as e:
        results.append(f"Error getting technology details: {str(e)}")

    return results


def check_security_headers(url):
    """Check for missing security headers."""
    results = []

    try:
        response = s.get(url)
        if response.status_code == 200:
            headers = response.headers
            if 'X-Frame-Options' not in headers:
                results.append("Missing X-Frame-Options header.")
            if 'X-XSS-Protection' not in headers:
                results.append("Missing X-XSS-Protection header.")
            if 'X-Content-Type-Options' not in headers:
                results.append("Missing X-Content-Type-Options header.")
            # Add more security headers to check here
            else:
                results.append("All required security headers present.")
        else:
            results.append("Failed to fetch security headers.")
    except Exception as e:
        results.append(f"Error checking security headers: {str(e)}")

    return results


def check_cookies(url):
    """Check for cookies."""
    results = []

    try:
        response = s.get(url)
        if response.status_code == 200:
            cookies = response.cookies
            if cookies:
                results.append("Cookies found:")
                for cookie in cookies:
                    results.append(f"{cookie.name}: {cookie.value}")
            else:
                results.append("No cookies found.")
        else:
            results.append("Failed to fetch cookies.")
    except Exception as e:
        results.append(f"Error checking cookies: {str(e)}")

    return results

#------------------------------

@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html")


#----------------------------------

@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        url_to_be_checked = request.form.get("url")
        if not url_to_be_checked:
            return render_template("scan.html", error="Please enter a URL.")

        results = {
            "sql injection scan": sql_injection_scan(url_to_be_checked),
            "open port scan": open_port_scan(url_to_be_checked.split("//")[1].split("/")[0]),
            "host details": get_host_details(url_to_be_checked.split("//")[1].split("/")[0]),
            "robots txt": check_robots_txt(url_to_be_checked),
            "technology details": get_technology_details(url_to_be_checked),
            "security headers": check_security_headers(url_to_be_checked),
            "cookies": check_cookies(url_to_be_checked)
        }

        return render_template("results.html", results=results, url=url_to_be_checked)

    return render_template("scan.html")


if __name__ == "__main__":
    app.run(debug=True)







#--------------------------------------------------------


# from flask import Flask, render_template, request
# from your_script_file_name import *

# app = Flask(__name__)

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/scan', methods=['POST'])
# def scan():
#     url = request.form['url']
#     # Call your functions from the script
#     # Example:
#     sql_scan_result = sql_injection_scan(url)
#     open_port_scan_result = open_port_scan(url)
#     host_details_result = get_host_details(url)
#     # Pass these results to the template
#     return render_template('result.html', url=url, sql_scan_result=sql_scan_result, open_port_scan_result=open_port_scan_result, host_details_result=host_details_result)

# if __name__ == '__main__':
#     app.run(debug=True)







# from flask import Flask, render_template, request
# from script import sql_injection_scan, open_port_scan, get_host_details, check_robots_txt, get_technology_details, check_security_headers, check_cookies

# app = Flask(__name__)

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/scan', methods=['post','get'])
# def scan():
#     url = request.form['result.html']
#     sql_vulnerabilities = sql_injection_scan(url)
#     target_host = url.split("//")[1].split("/")[0]
#     open_ports = open_port_scan(target_host)
#     host_details = get_host_details(target_host)
#     disallowed_paths = check_robots_txt(url)
#     technology_details = get_technology_details(url)
#     missing_security_headers = check_security_headers(url)
#     cookies = check_cookies(url)
#     return render_template('result.html', sql_vulnerabilities=sql_vulnerabilities, open_ports=open_ports,
#                            host_details=host_details, disallowed_paths=disallowed_paths,
#                            technology_details=technology_details, missing_security_headers=missing_security_headers,
#                            cookies=cookies)

# if __name__ == '__main__':
#     app.run(debug=True)



# #file : app.py
# from flask import Flask
# import requests
# import socket
# from bs4 import BeautifulSoup
# from urllib.parse import urljoin
# import re

# # Suppress SSL warnings
# requests.packages.urllib3.disable_warnings()

# # Initialize requests session
# s = requests.Session()
# s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"


# def get_forms(url):
#     """Extract forms from HTML content."""
#     try:
#         response = s.get(url)
#         soup = BeautifulSoup(response.content, "html.parser")
#         return soup.find_all("form")
#     except Exception as e:
#         return []


# def form_details(form):
#     """Extract details of forms."""
#     details_of_form = {}
#     action = form.attrs.get("action")
#     method = form.attrs.get("method", "get")
#     inputs = []

#     for input_tag in form.find_all("input"):
#         input_type = input_tag.attrs.get("type", "text")
#         input_name = input_tag.attrs.get("name")
#         input_value = input_tag.attrs.get("value", "")
#         inputs.append({
#             "type": input_type,
#             "name": input_name,
#             "value": input_value,
#         })

#     details_of_form['action'] = action
#     details_of_form['method'] = method
#     details_of_form['inputs'] = inputs
#     return details_of_form


# def vulnerable(response):
#     """Check for SQL injection vulnerability."""
#     errors = {
#         "quoted string not properly terminated",
#         "unclosed quotation mark after the character string",
#         "you have an error in your SQL syntax"
#     }
#     for error in errors:
#         if error in response.content.decode().lower():
#             return True
#     return False


# def sql_injection_scan(url):
#     """Scan for SQL injection vulnerabilities in forms."""
#     forms = get_forms(url)
#     vulnerabilities = []

#     for form in forms:
#         details = form_details(form)

#         for i in "\"'":
#             data = {}
#             for input_tag in details["inputs"]:
#                 if input_tag["type"] == "hidden" or input_tag["value"]:
#                     data[input_tag['name']] = input_tag["value"] + i
#                 elif input_tag["type"] != "submit":
#                     data[input_tag['name']] = f"test{i}"

#             if details["method"] == "post":
#                 res = s.post(urljoin(url, details["action"]), data=data)
#             elif details["method"] == "get":
#                 res = s.get(urljoin(url, details["action"]), params=data)

#             if res.status_code == 200:
#                 if vulnerable(res):
#                     vulnerabilities.append(urljoin(url, details["action"]))
#     return vulnerabilities


# def open_port_scan(target):
#     """Perform open port scan on target."""
#     open_ports = []
#     try:
#         for port in range(1, 1025):
#             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             sock.settimeout(1)
#             result = sock.connect_ex((target, port))
#             if result == 0:
#                 open_ports.append(port)
#             sock.close()
#     except Exception as e:
#         pass
#     return open_ports


# def get_host_details(target):
#     """Get host details."""
#     try:
#         host_ip = socket.gethostbyname(target)
#         host_name, _, _ = socket.gethostbyaddr(host_ip)
#         return {"host_ip": host_ip, "host_name": host_name}
#     except Exception as e:
#         return {"error": str(e)}


# def check_robots_txt(url):
#     """Check robots.txt for disallowed paths."""
#     try:
#         response = s.get(urljoin(url, "/robots.txt"))
#         if response.status_code == 200:
#             disallowed_paths = re.findall(r"Disallow: (.*)", response.text)
#             return disallowed_paths
#         else:
#             return []
#     except Exception as e:
#         return []


# def get_technology_details(url):
#     """Get technology details."""
#     try:
#         response = s.get(url)
#         if response.status_code == 200:
#             server_header = response.headers.get('Server')
#             return server_header
#         else:
#             return None
#     except Exception as e:
#         return None


# def check_security_headers(url):
#     """Check for missing security headers."""
#     try:
#         response = s.get(url)
#         if response.status_code == 200:
#             headers = response.headers
#             missing_headers = []
#             if 'X-Frame-Options' not in headers:
#                 missing_headers.append("X-Frame-Options")
#             if 'X-XSS-Protection' not in headers:
#                 missing_headers.append("X-XSS-Protection")
#             if 'X-Content-Type-Options' not in headers:
#                 missing_headers.append("X-Content-Type-Options")
#             return missing_headers
#         else:
#             return []
#     except Exception as e:
#         return []


# def check_cookies(url):
#     """Check for cookies."""
#     try:
#         response = s.get(url)
#         if response.status_code == 200:
#             cookies = response.cookies
#             return [{"name": cookie.name, "value": cookie.value} for cookie in cookies]
#         else:
#             return []
#     except Exception as e:
#         return []


# if __name__ == "__main__":
#     url_to_be_checked = input("Enter URL to be checked: ")

#     # SQL injection scan
#     sql_vulnerabilities = sql_injection_scan(url_to_be_checked)

#     # Open port scan
#     try:
#         target_host = url_to_be_checked.split("//")[1].split("/")[0]
#         open_ports = open_port_scan(target_host)
#     except Exception as e:
#         open_ports = []

#     # Get host details
#     host_details = get_host_details(target_host)

#     # Check robots.txt
#     disallowed_paths = check_robots_txt(url_to_be_checked)

#     # Get technology details
#     technology_details = get_technology_details(url_to_be_checked)

#     # Check security headers
#     missing_security_headers = check_security_headers(url_to_be_checked)

#     # Check cookies
#     cookies = check_cookies(url_to_be_checked)

#     # Output results
#     print("SQL Injection Vulnerabilities:", sql_vulnerabilities)
#     print("Open Ports:", open_ports)
#     print("Host Details:", host_details)
#     print("Disallowed Paths in robots.txt:", disallowed_paths)
#     print("Technology Details:", technology_details)
#     print("Missing Security Headers:", missing_security_headers)
#     print("Cookies:", cookies)

# if __name__ == '__main__':
#     app.run(debug=True)

# # you can create on html code where i can add my url and it shows result in blow and make sure you can use this given python code for run using flask.

# #Output:
# # Enter URL to be checked: https://programmator-java.blogspot.com/
# # SQL Injection Vulnerabilities: []
# # Open Ports: [80, 443]
# # Host Details: {'host_ip': '142.250.70.97', 'host_name': 'pnbomb-ac-in-f1.1e100.net'}
# # Disallowed Paths in robots.txt: ['/nogooglebot/', '/wp-admin/', '/search', '/tag/', '/cgi-bin/', '/scripts/', '/tmp/']
# # Technology Details: GSE
# # Missing Security Headers: ['X-Frame-Options']
# # Cookies: []

# #file : scan.html

# #     <style>
# #   .cid-u7EkX2fdqC {
# #     padding-top: 6rem;
# #     padding-bottom: 6rem;
# #     background-image: url("assets/images/photo-1563920443079-783e5c786b83.jpeg");
# #   }
# #   .cid-u7EkX2fdqC .mbr-fallback-image.disabled {
# #     display: none;
# #   }
# #   .cid-u7EkX2fdqC .mbr-fallback-image {
# #     display: block;
# #     background-size: cover;
# #     background-position: center center;
# #     width: 100%;
# #     height: 100%;
# #     position: absolute;
# #     top: 0;
# #   }
# #   .cid-u7EkX2fdqC .card-wrapper {
# #     background: var(--dominant-color, #333333);
# #     border-radius: 4px;
# #   }
# #   @media (max-width: 767px) {
# #     .cid-u7EkX2fdqC .card-wrapper {
# #       padding: 2rem 1.5rem;
# #       margin-bottom: 1rem;
# #     }
# #   }
# #   @media (min-width: 768px) and (max-width: 991px) {
# #     .cid-u7EkX2fdqC .card-wrapper {
# #       padding: 2.25rem;
# #     }
# #   }
# #   @media (min-width: 992px) {
# #     .cid-u7EkX2fdqC .card-wrapper {
# #       padding: 4rem;
# #     }
# #   }
# #   .cid-u7EkX2fdqC .mbr-text,
# #   .cid-u7EkX2fdqC .mbr-section-btn {
# #     text-align: center;
# #   }
# #   .cid-u7EkX2fdqC .card-title {
# #     text-align: center;
# #     color: var(--dominant-text, #ffd7ef);
# #   }
# # </style>
# # <section class="header14 cid-u7EkX2fdqC mbr-parallax-background" id="call-to-action-1-u7EkX2fdqC">
# # 	<div class="container">
# # 		<div class="row justify-content-center">
# # 			<div class="card col-12 col-md-12 col-lg-8">
# # 				<div class="card-wrapper">
# # 					<div class="card-box align-center">
# #             <div class="col-md col-sm-12 form-group mb-3" data-for="URL">
# #               <input type="url" name="URL" placeholder="Enter Your URL Here" data-form-field="URL" class="form-control" value="" id="name-form02-0">
# # 						<div class="mbr-section-btn mt-4">
# # 							<a class="btn btn-primary display-7" href="#">Get Protected</a>
# # 						</div>
# # 					</div>
# # 				</div>
# # 			</div>
# # 		</div>
# # 	</div>
# # </section>



# #   </style>
# #   <section class="people05 cid-u7EmNlWWT2" id="testimonials-5-u7EmNlWWT2">
# #     <div class="container">
# # 		  <div class="row mb-5 justify-content-center">
# # 			  <div class="col-12 mb-0 content-head">
# # 				  <h3 class="mbr-section-title mbr-fonts-style align-center mb-0 display-2">
# # 					  <strong>Results</strong>
# # 				  </h3>
# # 			  </div>
# # 		  </div>

# #       <div class="container">
# #         <div class="row">
# #           <div class="col-12 col-md-12 col-lg-8">
# #             <div class="card-wrapper">
# #               <div class="card-box align-center">
# #                 <div id="scan-results">
# #                   <!-- Scan results will be displayed here -->
# #                 </div>
# #               </div>
# #             </div>
# #           </div>
# #         </div>
# #       </div>
# #     </div>

# # 	</div>
# # </section>

