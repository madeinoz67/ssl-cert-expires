local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local datetime = require "datetime"
local tls = require "tls"

description = [[
Retrieves a server's SSL certificate and from that, calculates the number of days until the SSL certificate expires.
]]

---
-- @output
-- 443/tcp open  https
-- |_ssl-cert-expires: SSL certificate for 'CN=www.paypal.com' expires in 39 days.
--

author = "Lars von Zipper"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

-- port rule
portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-- function to create a timestamp (in seconds) from the expiry date of the SSL certificate
function get_cert_exp_timestamp(cert)
  certexpdate = {year=cert.validity.notAfter.year , month=cert.validity.notAfter.month, day=cert.validity.notAfter.day}
  certexpdatetimestamp = datetime.date_to_timestamp(certexpdate)
  return certexpdatetimestamp
end

-- function to round number down 
function round_down(num)
  return math.floor(num)
end

-- action
action = function(host, port)
  host.targetname = tls.servername(host)
  secsinday = 86400
  today = os.time()
  status, cert = sslcert.getCertificate(host, port)
  if (not(status)) then
    stdnse.debug1("getCertificate ERROR!: %s", cert or "UNKNOWN")
    return
  else      
    certdaysleft = (os.difftime(get_cert_exp_timestamp(cert), today) / secsinday)
    return string.format("SSL certificate for 'commonName=%s' expires in %s days.",cert.subject.commonName, round_down(certdaysleft))
  end
end

